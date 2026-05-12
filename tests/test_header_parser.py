"""Tests for email header parsing."""

import pytest

from phish_triage.tools.header_parser import parse_email_headers
from phish_triage.utils.email_parser import MAX_EMAIL_CHARS


async def test_parse_phishing_headers(phishing_email_1):
    result = await parse_email_headers(phishing_email_1)
    assert "error" not in result
    ui = result["untrusted_input"]
    assert ui["from_address"] == "noreply@paypa1-security.com"
    assert ui["from_display_name"] == "PayPal Security Team"
    assert ui["reply_to"] == "paypal-verify@gmail.com"
    assert ui["return_path"] == "<bounce@paypa1-security.com>"
    assert ui["message_id"] == "<abc123@paypa1-security.com>"


async def test_authentication_results_parsing(phishing_email_1):
    result = await parse_email_headers(phishing_email_1)
    auth = result["untrusted_input"]["authentication_results"]
    assert auth["spf"] == "fail"
    assert auth["dkim"] == "none"
    assert auth["dmarc"] == "fail"


async def test_authentication_results_pass(legitimate_email):
    result = await parse_email_headers(legitimate_email)
    auth = result["untrusted_input"]["authentication_results"]
    assert auth["spf"] == "pass"
    assert auth["dkim"] == "pass"
    assert auth["dmarc"] == "pass"


async def test_received_hops(phishing_email_1):
    result = await parse_email_headers(phishing_email_1)
    hops = result["untrusted_input"]["received_hops"]
    assert len(hops) >= 2
    # Oldest hop should be first (reversed)
    assert "198.51.100.77" in str(hops[0])


async def test_originating_ip(phishing_email_1):
    result = await parse_email_headers(phishing_email_1)
    assert result["untrusted_input"]["originating_ip"] == "198.51.100.77"


async def test_dkim_selector_extraction(phishing_email_1):
    result = await parse_email_headers(phishing_email_1)
    assert result["untrusted_input"]["dkim_selector"] == "default"


async def test_dkim_selector_spearphish(phishing_email_2):
    result = await parse_email_headers(phishing_email_2)
    assert result["untrusted_input"]["dkim_selector"] == "selector1"


async def test_x_headers(phishing_email_1):
    result = await parse_email_headers(phishing_email_1)
    xh = result["untrusted_input"]["x_headers"]
    assert "X-Spam-Score" in xh
    assert "X-Mailer" in xh


async def test_spearphish_reply_to_mismatch(phishing_email_2):
    result = await parse_email_headers(phishing_email_2)
    ui = result["untrusted_input"]
    assert ui["from_address"] == "sarah.chen@targetcorp.com"
    assert ui["reply_to"] == "sarah.chen.ceo@protonmail.com"
    # Reply-to differs from From — suspicious


async def test_arc_authentication_results(phishing_email_2):
    """Spearphish email has ARC-Authentication-Results."""
    result = await parse_email_headers(phishing_email_2)
    auth = result["untrusted_input"]["authentication_results"]
    # This email has both standard and ARC auth results
    assert auth["spf"] == "pass"
    assert auth["dkim"] == "pass"


async def test_empty_headers():
    result = await parse_email_headers("")
    assert "error" not in result


async def test_malformed_headers():
    result = await parse_email_headers("This is not a valid email header")
    assert "error" not in result


async def test_oversize_input_rejected():
    """Same DoS-bound contract as parse_email_structure: inputs over
    MAX_EMAIL_CHARS must fail closed before parsing starts.
    """
    oversize = "a" * (MAX_EMAIL_CHARS + 1)
    result = await parse_email_headers(oversize)
    assert result["error"] == "input_too_large"
    assert result["untrusted_input"]["size_chars"] == MAX_EMAIL_CHARS + 1
    assert oversize not in str(result)


async def test_non_string_input_rejected():
    result = await parse_email_headers(b"bytes not a string")  # type: ignore[arg-type]
    assert result["error"] == "invalid_input"
