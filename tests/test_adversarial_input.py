"""Defensive tests: confirm attacker-controlled strings in tool outputs are
sanitized before returning to the analyst LLM.

This is the contract laid out in CLAUDE.md's "Adversarial input" section:
every attacker-authored or attacker-influenced field must pass through
`clean_untrusted_string` and have a per-field length cap. These tests guard
against regressions where a future change leaks raw attacker bytes.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from phish_triage.tools.abuse_ip import check_abuse_ip
from phish_triage.tools.dns_lookup import dns_lookup
from phish_triage.tools.header_parser import parse_email_headers
from phish_triage.tools.redirect_follower import follow_redirects
from phish_triage.tools.reputation import check_reputation
from phish_triage.tools.url_scanner import scan_url
from phish_triage.tools.whois_lookup import whois_lookup
from phish_triage.utils.email_parser import parse_email_structure


FIXTURE = Path(__file__).parent / "fixtures" / "adversarial_injection.eml"

# Bytes that must never appear in any string field of any tool response.
# - ANSI CSI (`\x1b[` introducer)
# - C0 control chars (excluding CR/LF/TAB which the cleaner preserves)
# - Zero-width chars (ZWSP, ZWNJ, ZWJ, WORD-JOINER, BOM)
# - BiDi overrides (RLO U+202E, LRO U+202D, PDF U+202C) — these are not in
#   the current cleaner's zero-width set, so adding a test here also flags
#   if we need to extend the cleaner.
FORBIDDEN_SUBSTRINGS = [
    "\x1b[",
    "\x00",
    "\x01",
    "\x07",  # bell
    "​",  # ZWSP
    "‌",  # ZWNJ
    "‍",  # ZWJ
    "⁠",  # word joiner
    "﻿",  # BOM
    "‮",  # RTLO
    "‭",  # LRO
]


# Single payload reused across all upstream mocks. Contains one of each
# forbidden byte category, so if any cleaner regresses, at least one assert
# will catch it.
POISON = (
    "evil"
    "\x1b[31m"   # ANSI CSI
    "\x00"       # NUL
    "​"     # ZWSP
    "‮"     # RTLO
    "payload"
)


def _assert_clean(value, path: str) -> None:
    """Recursively check that no string in a nested structure contains
    forbidden bytes. `path` is for error messages.
    """
    if isinstance(value, str):
        for bad in FORBIDDEN_SUBSTRINGS:
            assert bad not in value, (
                f"forbidden byte {bad!r} found in {path}: {value!r}"
            )
    elif isinstance(value, dict):
        for k, v in value.items():
            _assert_clean(k, f"{path}.<key:{k!r}>")
            _assert_clean(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _assert_clean(item, f"{path}[{i}]")
    # int, bool, None, etc. — nothing to check.


# ───────────────────────────────────────────────────────────────────────────
# Fixture-driven tests for the local parsers (no network mocking needed).
# ───────────────────────────────────────────────────────────────────────────


async def test_header_parser_cleans_adversarial_eml():
    raw = FIXTURE.read_text()
    result = await parse_email_headers(raw)
    _assert_clean(result, "parse_email_headers")
    ui = result["untrusted_input"]
    # Spot check: the display name still has the legible portion and dropped the ANSI.
    assert "IT Support" in ui["from_display_name"]
    assert "\x1b" not in ui["from_display_name"]
    # X-headers preserved by key, but contents stripped.
    assert "X-Mailer" in ui["x_headers"]
    assert "​" not in ui["x_headers"]["X-Mailer"]


def test_email_parser_cleans_adversarial_eml():
    raw = FIXTURE.read_text()
    result = parse_email_structure(raw)
    _assert_clean(result, "parse_email_structure")
    # Attachment filename had an RTLO override (U+202E). The cleaner now
    # strips BiDi controls; if it's removed, this trip-wire fires.
    for att in result["untrusted_input"]["attachments"]:
        assert "‮" not in att["filename"], (
            "RTLO override leaked through attachment filename — extend "
            "clean_untrusted_string to strip BiDi controls"
        )


async def test_no_attacker_instruction_amplification():
    """A separate concern from sanitization: the parsed headers should
    preserve the attacker's instruction text *visibly* (not hidden by
    control chars), so the analyst LLM and the human reviewer both see
    exactly what was sent.

    The defense against the instructions is at the SKILL.md / prompt layer,
    not here. This test exists so that anyone tempted to "helpfully" filter
    out injection-like phrases at the tool layer gets a failure to think
    about it first.
    """
    raw = FIXTURE.read_text()
    result = await parse_email_headers(raw)
    # The string "IGNORE PREVIOUS INSTRUCTIONS" is in the From header.
    # The cleaner stripped the ANSI wrapper but preserved the plain text —
    # that is intentional: the analyst should see what the attacker tried.
    assert "IGNORE PREVIOUS INSTRUCTIONS" in result["untrusted_input"]["from_display_name"]


# ───────────────────────────────────────────────────────────────────────────
# Mocked-upstream tests for the network-facing tools. The point of each test
# is: stuff `POISON` into every attacker-influenced field of a realistic API
# response, run the tool, and assert the tool's output is forbidden-byte-free.
# These are regression tripwires for the trust-tier contract.
# ───────────────────────────────────────────────────────────────────────────


async def test_whois_response_is_sanitized():
    """python-whois returns a dict-like object built from raw WHOIS server
    text. A phisher who owns a domain controls every string field. The tool
    must scrub them before wrapping.
    """
    poisoned_whois = MagicMock()
    poisoned_whois.creation_date = None
    poisoned_whois.expiration_date = None
    poisoned_whois.updated_date = None
    poisoned_whois.registrar = f"Registrar{POISON}"
    poisoned_whois.name_servers = [f"ns1.{POISON}.com", f"ns2.{POISON}.com"]
    poisoned_whois.get = MagicMock(
        side_effect=lambda k, default="": {
            "org": f"Org{POISON}",
            "name": "",
            "country": f"Country{POISON}",
        }.get(k, default)
    )

    with patch("phish_triage.tools.whois_lookup.whois", return_value=poisoned_whois):
        result = await whois_lookup("example.com")

    _assert_clean(result, "whois_lookup")
    api = result["untrusted_api_response"]
    # Legible substring survives so the analyst can still see what was claimed.
    assert "Registrar" in api["registrar"]


async def test_dns_response_is_sanitized():
    """TXT records on an attacker-owned domain can hold arbitrary bytes. The
    tool must scrub each record before returning it.
    """
    poisoned_spf = f'"v=spf1 include:_spf.{POISON}.example -all"'
    poisoned_dmarc = f'"v=DMARC1; p=reject; rua=mailto:reports@{POISON}.example"'
    poisoned_mx_host = f"mail.{POISON}.example"

    async def fake_aquery(domain, rdtype):
        if rdtype == "MX":
            return [f"10 {poisoned_mx_host}"]
        if rdtype == "TXT":
            if domain.startswith("_dmarc."):
                return [poisoned_dmarc]
            return [poisoned_spf]
        if rdtype == "A":
            return ["203.0.113.42"]
        if rdtype == "NS":
            return [f"ns1.{POISON}.example."]
        return []

    with patch("phish_triage.tools.dns_lookup._aquery", side_effect=fake_aquery):
        result = await dns_lookup("example.com")

    _assert_clean(result, "dns_lookup")
    api = result["untrusted_api_response"]
    assert api["mx_records"][0]["priority"] == 10
    assert "mail" in api["mx_records"][0]["host"]
    assert api["spf_record"].startswith("v=spf1")
    assert api["dmarc_record"].startswith("v=DMARC1")


async def test_url_scanner_response_is_sanitized():
    """URLScan returns provider-shaped JSON whose page_title, page_domain,
    redirect chain, contacted domains, and categories are all written by
    code running on the attacker's page. Every string must be cleaned.
    """
    submit_resp = MagicMock()
    submit_resp.status_code = 200
    submit_resp.json.return_value = {"uuid": "uuid-1234"}

    result_resp = MagicMock()
    result_resp.status_code = 200
    result_resp.json.return_value = {
        "page": {
            "url": f"https://final.{POISON}.example/",
            "domain": f"final.{POISON}.example",
            "title": f"Login{POISON}",
            "server": f"server{POISON}",
        },
        "lists": {
            "domains": [f"a.{POISON}.example", f"b.{POISON}.example"],
            "categories": [f"phishing{POISON}"],
        },
        "verdicts": {"overall": {"malicious": True}},
        "data": {"requests": [{"url": f"https://hop1.{POISON}.example"}]},
    }

    with patch.dict("os.environ", {"URLSCAN_API_KEY": "test-key"}):
        with patch("phish_triage.tools.url_scanner.urlscan_limiter") as mock_limiter:
            mock_limiter.acquire = AsyncMock(return_value=True)
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post.return_value = submit_resp
                mock_client.get.return_value = result_resp
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await scan_url("https://attacker.example/landing")

    _assert_clean(result, "scan_url")
    api = result["untrusted_api_response"]
    assert "Login" in api["page_title"]
    assert "final" in api["page_domain"]
    assert "phishing" in api["categories"][0]


async def test_virustotal_response_is_sanitized():
    """VT engine names and result strings are partially attacker-influenced —
    engines often echo content from the URL/page back in the result field.
    """
    vt_resp = MagicMock()
    vt_resp.status_code = 200
    vt_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 2, "harmless": 80},
                "last_analysis_results": {
                    f"Engine{POISON}": {
                        "category": "malicious",
                        "result": f"phishing-kit{POISON}",
                    },
                    "Kaspersky": {"category": "malicious", "result": "malware"},
                },
                "categories": {f"engineA{POISON}": f"phishing{POISON}"},
                "reputation": -10,
                "last_analysis_date": 1700000000,
            }
        }
    }

    with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}, clear=True):
        with patch("phish_triage.tools.reputation.virustotal_limiter") as mock_limiter:
            mock_limiter.acquire = AsyncMock(return_value=True)
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get.return_value = vt_resp
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client
                result = await check_reputation("example.com", "domain")

    _assert_clean(result, "check_reputation/virustotal")
    vt = result["virustotal"]
    assert vt["detection_ratio"] == "2/82"


async def test_safe_browsing_response_is_sanitized():
    """Threat type strings from Google Safe Browsing are constrained, but the
    tool must still strip control bytes if Google ever returns them.
    """
    gsb_resp = MagicMock()
    gsb_resp.status_code = 200
    gsb_resp.json.return_value = {
        "matches": [
            {"threatType": f"SOCIAL_ENGINEERING{POISON}"},
            {"threatType": "MALWARE"},
        ]
    }

    with patch.dict(
        "os.environ", {"GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}, clear=True
    ):
        with patch("phish_triage.tools.reputation.safe_browsing_limiter") as mock_limiter:
            mock_limiter.acquire = AsyncMock(return_value=True)
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post.return_value = gsb_resp
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client
                result = await check_reputation("https://example.com/path", "url")

    _assert_clean(result, "check_reputation/safe_browsing")
    sb = result["safe_browsing"]
    assert sb["is_unsafe"] is True


async def test_abuse_ip_response_is_sanitized():
    """AbuseIPDB returns ISP, country, usage type, and domain strings about
    an attacker-controlled IP. All are attacker-influenced.
    """
    abuse_resp = MagicMock()
    abuse_resp.status_code = 200
    abuse_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 87,
            "totalReports": 42,
            "lastReportedAt": "2026-05-01T00:00:00Z",
            "isTor": False,
            "isWhitelisted": False,
            "isp": f"ISP{POISON}",
            "countryCode": "US",
            "usageType": f"Hosting{POISON}",
            "domain": f"evil.{POISON}.example",
        }
    }

    with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-key"}, clear=True):
        with patch("phish_triage.tools.abuse_ip.abuseipdb_limiter") as mock_limiter:
            mock_limiter.acquire = AsyncMock(return_value=True)
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get.return_value = abuse_resp
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client
                # Use a routable public IP — `validate_ip` rejects
                # RFC 5737 TEST-NET ranges as reserved before the mocked
                # HTTP path is reached.
                result = await check_abuse_ip("8.8.8.8")

    _assert_clean(result, "check_abuse_ip")
    api = result["untrusted_api_response"]
    assert "ISP" in api["isp"]
    assert "Hosting" in api["usage_type"]


async def test_redirect_follower_response_is_sanitized(monkeypatch):
    """The Location and Server response headers come from attacker-controlled
    servers. Both must be cleaned before they're returned in the hop record.
    """
    # Stub DNS so the SSRF validator doesn't reach the network.
    monkeypatch.setattr(
        "phish_triage.utils.validators._resolve_hostname",
        lambda hostname: ["8.8.8.8"],
    )

    resp_redirect = MagicMock()
    resp_redirect.status_code = 302
    resp_redirect.headers = {
        "location": f"https://next.example/{POISON}",
        "server": f"nginx{POISON}",
    }
    resp_final = MagicMock()
    resp_final.status_code = 200
    resp_final.headers = {"server": f"apache{POISON}"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.head.side_effect = [resp_redirect, resp_final]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await follow_redirects("https://start.example/")

    _assert_clean(result, "follow_redirects")
    assert result["reached_final"] is True
    chain = result["untrusted_api_response"]["redirect_chain"]
    # Each hop's location and server must be present (legible) but clean.
    assert any("next.example" in (hop.get("location") or "") for hop in chain)
    assert all("​" not in (hop.get("server") or "") for hop in chain)
