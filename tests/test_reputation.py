"""Tests for reputation checking (VirusTotal + Google Safe Browsing)."""

from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from phish_triage.tools.reputation import check_reputation


async def test_missing_all_api_keys():
    with patch.dict("os.environ", {}, clear=True):
        result = await check_reputation("https://example.com", "url")
    assert result["virustotal"]["error"] == "not_configured"
    assert result["safe_browsing"]["error"] == "not_configured"


async def test_invalid_indicator_type():
    result = await check_reputation("example.com", "invalid_type")
    assert result["error"] == "invalid_input"


async def test_invalid_ip_format():
    result = await check_reputation("not-an-ip", "ip")
    assert result["error"] == "invalid_input"


async def test_private_ip_rejected():
    result = await check_reputation("192.168.1.1", "ip")
    assert result["error"] == "invalid_input"
    assert "private" in result["detail"].lower()


async def test_invalid_domain_format():
    result = await check_reputation("not a domain", "domain")
    assert result["error"] == "invalid_input"


async def test_url_without_scheme():
    result = await check_reputation("example.com", "url")
    assert result["error"] == "invalid_input"


async def test_virustotal_rate_limit():
    with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}, clear=True):
        with patch("phish_triage.tools.reputation.virustotal_limiter") as mock_limiter:
            mock_limiter.acquire = AsyncMock(return_value=False)
            mock_limiter.wait_time.return_value = 15.0
            result = await check_reputation("https://example.com", "url")
    assert result["virustotal"]["error"] == "rate_limit"
