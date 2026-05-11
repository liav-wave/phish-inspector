"""Integration tests: spearphish fixtures → indicator extraction → enrichment tool dispatch.

These tests verify that indicators extracted from realistic spearphish emails
are valid inputs for the enrichment tools (DNS, WHOIS, URLScan, reputation,
AbuseIPDB). The enrichment tools themselves are mocked — the point is to
confirm the full pipeline connects correctly.
"""

from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from phish_triage.tools.header_parser import parse_email_headers
from phish_triage.tools.dns_lookup import dns_lookup
from phish_triage.tools.whois_lookup import whois_lookup
from phish_triage.tools.url_scanner import scan_url
from phish_triage.tools.reputation import check_reputation
from phish_triage.tools.abuse_ip import check_abuse_ip
from phish_triage.utils.email_parser import parse_email_structure


# ── BEC Wire Transfer ────────────────────────────────────────────────────


async def test_bec_header_signals(spearphish_bec):
    headers = await parse_email_headers(spearphish_bec)
    ui = headers["untrusted_input"]
    assert ui["from_address"] == "m.hutchins@bandersnatch.llc"
    assert "bandersnatch-invoicing.com" in ui["return_path"]
    assert ui["authentication_results"]["dmarc"] == "fail"
    assert ui["authentication_results"]["dkim"] == "none"
    assert ui["reply_to"] == "m.hutchins.cfo@proton.me"


async def test_bec_indicators(spearphish_bec):
    indicators = parse_email_structure(spearphish_bec)["untrusted_input"]
    assert indicators["sender_domain"] == "bandersnatch.llc"
    assert len(indicators["attachments"]) == 1
    assert indicators["attachments"][0]["filename"] == "Cheshire_Research_Wire_Instructions_Updated.pdf"
    # BEC: no phishing URLs, attack is social engineering + attachment
    assert len(indicators["urls"]) == 0


async def test_bec_originating_ip_feeds_abuseipdb(spearphish_bec):
    headers = await parse_email_headers(spearphish_bec)
    ip = headers["untrusted_input"]["originating_ip"]
    assert ip is not None
    # Verify the IP is a valid input for AbuseIPDB
    with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-key"}):
        with patch("phish_triage.tools.abuse_ip.abuseipdb_limiter") as lim:
            lim.acquire = AsyncMock(return_value=True)
            with patch("httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"data": {"abuseConfidenceScore": 85, "totalReports": 12, "isp": "Test"}}
                mock_client.get.return_value = mock_resp
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_cls.return_value = mock_client

                result = await check_abuse_ip(ip)

    assert result["untrusted_input"]["ip_address"] == ip
    assert result["abuse_confidence_score"] == 85


async def test_bec_sender_domain_feeds_dns(spearphish_bec):
    indicators = parse_email_structure(spearphish_bec)["untrusted_input"]
    domain = indicators["sender_domain"]
    assert domain == "bandersnatch.llc"
    # DNS lookup is synchronous under the hood, no mock needed for the call shape
    result = await dns_lookup(domain)
    assert result["untrusted_input"]["domain"] == domain
    assert "has_mail_config" in result


# ── OAuth Credential Harvest ─────────────────────────────────────────────


async def test_oauth_header_signals(spearphish_oauth):
    headers = await parse_email_headers(spearphish_oauth)
    ui = headers["untrusted_input"]
    assert ui["from_address"] == "it-admin@cheshire-research.org"
    assert "cheshire-research-portal.com" in ui["return_path"]
    assert ui["authentication_results"]["dmarc"] == "fail"
    assert ui["authentication_results"]["dkim"] == "pass"
    assert ui["reply_to"] == "it-helpdesk@cheshire-research-portal.com"


async def test_oauth_urls_feed_urlscan(spearphish_oauth):
    indicators = parse_email_structure(spearphish_oauth)["untrusted_input"]
    phishing_urls = [u for u in indicators["urls"] if "sso/verify" in u]
    assert len(phishing_urls) >= 1
    url = phishing_urls[0]
    # Verify URL is accepted by scan_url (not rejected as invalid)
    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        with patch("phish_triage.tools.url_scanner.urlscan_limiter") as lim:
            lim.acquire = AsyncMock(return_value=True)
            with patch("httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_submit = MagicMock(status_code=200)
                mock_submit.json.return_value = {"uuid": "test-uuid"}
                mock_result = MagicMock(status_code=200)
                mock_result.json.return_value = {
                    "page": {"url": url, "domain": "cheshire-research-portal.com", "title": "SSO", "server": "nginx"},
                    "lists": {"domains": ["cheshire-research-portal.com"], "categories": []},
                    "verdicts": {"overall": {"malicious": True}},
                    "data": {"requests": []},
                }
                mock_client.post.return_value = mock_submit
                mock_client.get.return_value = mock_result
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_cls.return_value = mock_client

                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await scan_url(url)

    assert "error" not in result
    assert result["is_malicious"] is True


async def test_oauth_domains_feed_reputation(spearphish_oauth):
    indicators = parse_email_structure(spearphish_oauth)["untrusted_input"]
    assert "cheshire-research-portal.com" in indicators["domains"]
    with patch.dict("os.environ", {}, clear=True):
        result = await check_reputation("cheshire-research-portal.com", "domain")
    assert result["untrusted_input"]["indicator"] == "cheshire-research-portal.com"
    assert result["untrusted_input"]["indicator_type"] == "domain"


# ── IT Helpdesk Password Reset ──────────────────────────────────────────


async def test_helpdesk_header_signals(spearphish_helpdesk):
    headers = await parse_email_headers(spearphish_helpdesk)
    ui = headers["untrusted_input"]
    assert ui["from_address"] == "noreply@jabberwocky-corp.com"
    assert ui["authentication_results"]["spf"] == "softfail"
    assert ui["authentication_results"]["dkim"] == "none"
    assert ui["authentication_results"]["dmarc"] == "fail"


async def test_helpdesk_urls_all_point_to_lookalike(spearphish_helpdesk):
    indicators = parse_email_structure(spearphish_helpdesk)["untrusted_input"]
    non_empty_urls = [u for u in indicators["urls"] if u.startswith("https://")]
    assert len(non_empty_urls) >= 1
    for url in non_empty_urls:
        assert "jabberwocky-corp-sso.com" in url
    # Sender domain differs from URL domain
    assert indicators["sender_domain"] == "jabberwocky-corp.com"
    assert "jabberwocky-corp-sso.com" in indicators["domains"]
    assert indicators["sender_domain"] not in indicators["domains"]


async def test_helpdesk_ips_feed_abuseipdb(spearphish_helpdesk):
    headers = await parse_email_headers(spearphish_helpdesk)
    indicators = parse_email_structure(spearphish_helpdesk)["untrusted_input"]
    all_ips = indicators["ip_addresses"]
    # Should have public IPs suitable for AbuseIPDB
    public_ips = [ip for ip in all_ips if not ip.startswith(("10.", "172.", "192.168."))]
    assert len(public_ips) >= 1


# ── Vendor Impersonation ────────────────────────────────────────────────


async def test_vendor_url_mismatch_detected(spearphish_vendor):
    indicators = parse_email_structure(spearphish_vendor)["untrusted_input"]
    assert len(indicators["url_mismatches"]) >= 1
    mismatch = indicators["url_mismatches"][0]
    assert "billing-redqueenracing.com" in mismatch["href"]
    assert "payments.redqueenracing.com" in mismatch["display_text"]


async def test_vendor_header_signals(spearphish_vendor):
    headers = await parse_email_headers(spearphish_vendor)
    ui = headers["untrusted_input"]
    assert ui["from_address"] == "ap-invoices@redqueenracing.com"
    assert "redqueenracing-billing.com" in ui["return_path"]
    assert ui["authentication_results"]["dmarc"] == "fail"
    assert ui["authentication_results"]["dkim"] == "pass"


async def test_vendor_attachment_present(spearphish_vendor):
    indicators = parse_email_structure(spearphish_vendor)["untrusted_input"]
    assert len(indicators["attachments"]) == 1
    assert "Invoice" in indicators["attachments"][0]["filename"]
    assert indicators["attachments"][0]["content_type"] == "application/pdf"


async def test_vendor_domains_feed_whois(spearphish_vendor):
    indicators = parse_email_structure(spearphish_vendor)["untrusted_input"]
    # The phishing domain should be extracted
    assert "billing-redqueenracing.com" in indicators["domains"]
    # Verify it's a valid input for whois
    result = await whois_lookup("billing-redqueenracing.com")
    assert result["untrusted_input"]["domain"] == "billing-redqueenracing.com"


async def test_vendor_phishing_url_feeds_urlscan(spearphish_vendor):
    indicators = parse_email_structure(spearphish_vendor)["untrusted_input"]
    billing_urls = [u for u in indicators["urls"] if "billing-redqueenracing.com" in u]
    assert len(billing_urls) >= 1
    url = billing_urls[0]
    # Confirm it passes URL validation (not rejected as private/invalid)
    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        with patch("phish_triage.tools.url_scanner.urlscan_limiter") as lim:
            lim.acquire = AsyncMock(return_value=False)
            lim.wait_time.return_value = 10.0
            result = await scan_url(url)
    # Rate limited is fine — the point is it wasn't rejected as invalid input
    assert result["error"] == "rate_limit"
    assert result["untrusted_input"]["url"] == url
