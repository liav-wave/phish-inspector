"""Tests for lightweight redirect follower tool."""

from unittest.mock import patch, AsyncMock, MagicMock

import pytest
import httpx

from phish_triage.tools.redirect_follower import follow_redirects


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch):
    """Stub DNS resolution so tests don't hit the network.

    Default: every name resolves to a single benign public IP. Tests that
    care about a specific resolution can override `phish_triage.utils.validators._resolve_hostname`.

    Note: must be a real public IP (`ipaddress.is_private=False`). RFC 5737
    TEST-NET ranges are flagged private by Python's `ipaddress` module.
    """
    monkeypatch.setattr(
        "phish_triage.utils.validators._resolve_hostname",
        lambda hostname: ["8.8.8.8"],
    )


async def test_invalid_url_no_scheme():
    result = await follow_redirects("not-a-url")
    assert result["error"] == "invalid_input"


async def test_private_ip_rejected():
    result = await follow_redirects("http://192.168.1.1/admin")
    assert result["error"] == "invalid_input"
    assert "private" in result["detail"].lower()


async def test_localhost_rejected():
    result = await follow_redirects("http://localhost:8080")
    assert result["error"] == "invalid_input"


async def test_dns_resolves_to_private_ip_rejected(monkeypatch):
    """Hostname that resolves to a private/internal IP must be rejected
    even if the URL doesn't contain a literal private IP. This is the
    GCE-metadata / LAN-pivot SSRF vector.
    """
    monkeypatch.setattr(
        "phish_triage.utils.validators._resolve_hostname",
        lambda hostname: ["169.254.169.254"],
    )
    result = await follow_redirects("https://metadata-attack.example/")
    assert result["error"] == "invalid_input"
    assert "169.254.169.254" in result["detail"]


async def test_dns_unresolvable_rejected(monkeypatch):
    monkeypatch.setattr(
        "phish_triage.utils.validators._resolve_hostname",
        lambda hostname: [],
    )
    result = await follow_redirects("https://does-not-resolve.example/")
    assert result["error"] == "invalid_input"
    assert "resolve" in result["detail"].lower()


async def test_redirect_to_dns_private_blocked(monkeypatch):
    """Initial URL resolves OK, but the redirect target resolves to a
    private IP. Must be caught at next-hop validation.
    """
    resolutions = {
        "start.example.com": ["8.8.8.8"],
        "evil.example": ["169.254.169.254"],
    }
    monkeypatch.setattr(
        "phish_triage.utils.validators._resolve_hostname",
        lambda hostname: resolutions.get(hostname, ["8.8.8.8"]),
    )

    resp_redirect = MagicMock()
    resp_redirect.status_code = 302
    resp_redirect.headers = {"location": "http://evil.example/admin", "server": "nginx"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.return_value = resp_redirect
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects("https://start.example.com/")

    assert result["reached_final"] is False
    assert result["error"] == "ssrf_blocked"
    assert "169.254.169.254" in result["detail"]


async def test_no_redirect():
    """URL that returns 200 immediately — no redirect chain."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"server": "nginx"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects("https://example.com")

    assert result["reached_final"] is True
    assert result["final_url"] == "https://example.com"
    assert result["total_redirects"] == 0
    assert len(result["redirect_chain"]) == 1
    assert result["redirect_chain"][0]["status_code"] == 200


async def test_simple_redirect_chain():
    """301 → 302 → 200 chain."""
    resp_301 = MagicMock()
    resp_301.status_code = 301
    resp_301.headers = {"location": "https://step2.example.com/", "server": "apache"}

    resp_302 = MagicMock()
    resp_302.status_code = 302
    resp_302.headers = {"location": "https://final.example.com/page", "server": "nginx"}

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.headers = {"server": "nginx"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.side_effect = [resp_301, resp_302, resp_200]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects("https://start.example.com/link")

    assert result["reached_final"] is True
    assert result["url"] == "https://start.example.com/link"
    assert result["final_url"] == "https://final.example.com/page"
    assert result["total_redirects"] == 2
    assert len(result["redirect_chain"]) == 3
    assert result["redirect_chain"][0]["status_code"] == 301
    assert result["redirect_chain"][1]["status_code"] == 302
    assert result["redirect_chain"][2]["status_code"] == 200


async def test_max_redirects_exceeded():
    """Redirect loop that exceeds the max_redirects cap."""
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"server": "apache"}

    # Each redirect goes to a unique URL to avoid loop detection.
    urls = [f"https://example.com/hop{i}" for i in range(15)]
    responses = []
    for i in range(14):
        r = MagicMock()
        r.status_code = 302
        r.headers = {"location": urls[i + 1], "server": "apache"}
        responses.append(r)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.side_effect = responses
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects(urls[0], max_redirects=3)

    assert result["reached_final"] is False
    assert result["error"] == "max_redirects"


async def test_redirect_loop_detected():
    """Redirect that loops back to a previously seen URL."""
    resp_to_b = MagicMock()
    resp_to_b.status_code = 302
    resp_to_b.headers = {"location": "https://b.example.com/", "server": "nginx"}

    resp_to_a = MagicMock()
    resp_to_a.status_code = 302
    resp_to_a.headers = {"location": "https://a.example.com/", "server": "nginx"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.side_effect = [resp_to_b, resp_to_a]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects("https://a.example.com/")

    assert result["reached_final"] is False
    assert result["error"] == "redirect_loop"


async def test_ssrf_blocked_mid_chain():
    """Redirect to a private IP is blocked at the validation step."""
    resp_redirect = MagicMock()
    resp_redirect.status_code = 302
    resp_redirect.headers = {"location": "http://192.168.1.1/admin", "server": "nginx"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.return_value = resp_redirect
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects("https://evil.example.com/redir")

    assert result["reached_final"] is False
    assert result["error"] == "ssrf_blocked"
    assert "private" in result["detail"].lower()


async def test_head_fallback_to_get():
    """When HEAD returns 405, fall back to GET."""
    resp_head_405 = MagicMock()
    resp_head_405.status_code = 405

    resp_get_200 = MagicMock()
    resp_get_200.status_code = 200
    resp_get_200.headers = {"server": "IIS"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.return_value = resp_head_405
        mock_client.get.return_value = resp_get_200
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects("https://example.com/page")

    assert result["reached_final"] is True
    assert result["final_url"] == "https://example.com/page"
    mock_client.head.assert_called_once()
    mock_client.get.assert_called_once()


async def test_timeout_handling():
    """Request that times out mid-chain."""
    resp_redirect = MagicMock()
    resp_redirect.status_code = 302
    resp_redirect.headers = {"location": "https://slow.example.com/", "server": "nginx"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.side_effect = [resp_redirect, httpx.TimeoutException("timed out")]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects("https://start.example.com/")

    assert result["reached_final"] is False
    assert result["error"] == "timeout"
    assert len(result["redirect_chain"]) == 1  # first hop recorded before timeout


async def test_relative_redirect():
    """Server returns a relative Location header."""
    resp_relative = MagicMock()
    resp_relative.status_code = 301
    resp_relative.headers = {"location": "/new-path", "server": "nginx"}

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.headers = {"server": "nginx"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.side_effect = [resp_relative, resp_200]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects("https://example.com/old-path")

    assert result["reached_final"] is True
    assert result["final_url"] == "https://example.com/new-path"
    assert result["total_redirects"] == 1
