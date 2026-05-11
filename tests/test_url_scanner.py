"""Tests for URL scanner tool (URLScan.io integration)."""

from unittest.mock import patch, AsyncMock, MagicMock

import pytest
import httpx

from phish_triage.tools.url_scanner import scan_url


async def test_missing_api_key():
    with patch.dict("os.environ", {}, clear=True):
        result = await scan_url("https://example.com")
    assert result["error"] == "not_configured"
    assert "URLSCAN_API_KEY" in result["detail"]


async def test_private_ip_rejected():
    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        result = await scan_url("http://192.168.1.1/admin")
    assert result["error"] == "invalid_input"
    assert "private" in result["detail"].lower()


async def test_localhost_rejected():
    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        result = await scan_url("http://localhost:8080")
    assert result["error"] == "invalid_input"


async def test_loopback_rejected():
    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        result = await scan_url("http://127.0.0.1/test")
    assert result["error"] == "invalid_input"


async def test_invalid_url_no_scheme():
    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        result = await scan_url("not-a-url")
    assert result["error"] == "invalid_input"


async def test_rate_limit_handling():
    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        with patch("phish_triage.tools.url_scanner.urlscan_limiter") as mock_limiter:
            mock_limiter.acquire = AsyncMock(return_value=False)
            mock_limiter.wait_time.return_value = 30.0
            result = await scan_url("https://example.com")
    assert result["error"] == "rate_limit"


async def test_successful_scan():
    mock_submit_resp = MagicMock()
    mock_submit_resp.status_code = 200
    mock_submit_resp.json.return_value = {"uuid": "test-uuid-123"}

    mock_result_resp = MagicMock()
    mock_result_resp.status_code = 200
    mock_result_resp.json.return_value = {
        "page": {
            "url": "https://example.com/final",
            "domain": "example.com",
            "title": "Example Page",
            "server": "nginx",
        },
        "lists": {"domains": ["example.com", "cdn.example.com"], "categories": []},
        "verdicts": {"overall": {"malicious": False}},
        "data": {"requests": [{"url": "https://example.com"}]},
    }

    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        with patch("phish_triage.tools.url_scanner.urlscan_limiter") as mock_limiter:
            mock_limiter.acquire = AsyncMock(return_value=True)
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post.return_value = mock_submit_resp
                mock_client.get.return_value = mock_result_resp
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await scan_url("https://example.com")

    assert result["scan_id"] == "test-uuid-123"
    assert result["is_malicious"] is False
    assert result["untrusted_api_response"]["page_domain"] == "example.com"
    assert result["untrusted_input"]["url"] == "https://example.com"


async def test_api_429_handling():
    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        with patch("phish_triage.tools.url_scanner.urlscan_limiter") as mock_limiter:
            mock_limiter.acquire = AsyncMock(return_value=True)
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post.return_value = mock_resp
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                result = await scan_url("https://example.com")

    assert result["error"] == "rate_limit"
