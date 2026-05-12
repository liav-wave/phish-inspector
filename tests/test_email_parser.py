"""Tests for email indicator extraction."""

import pytest

from phish_triage.utils.email_parser import (
    MAX_EMAIL_CHARS,
    extract_urls_from_text,
    extract_links_from_html,
    find_url_mismatches,
    detect_tracking_pixels,
    parse_email_structure,
)


def test_extract_urls_from_text():
    text = "Visit https://example.com/page and http://test.org/path?q=1"
    urls = extract_urls_from_text(text)
    assert len(urls) == 2
    assert "https://example.com/page" in urls
    assert "http://test.org/path?q=1" in urls


def test_extract_urls_ignores_non_urls():
    text = "No URLs here, just regular text with dots like v2.0"
    urls = extract_urls_from_text(text)
    assert len(urls) == 0


def test_extract_links_from_html():
    html = '<a href="https://evil.com/phish">Click here</a>'
    links = extract_links_from_html(html)
    assert len(links) == 1
    assert links[0]["href"] == "https://evil.com/phish"
    assert links[0]["display_text"] == "Click here"


def test_url_mismatch_detection():
    links = [
        {"href": "https://evil.com/phish", "display_text": "https://paypal.com/account"},
        {"href": "https://example.com/page", "display_text": "Click here"},
        {"href": "https://example.com/page", "display_text": "https://example.com/page"},
    ]
    mismatches = find_url_mismatches(links)
    assert len(mismatches) == 1
    assert mismatches[0]["href"] == "https://evil.com/phish"
    assert mismatches[0]["display_text"] == "https://paypal.com/account"


def test_no_mismatch_for_non_url_display_text():
    links = [{"href": "https://example.com/page", "display_text": "Click here"}]
    mismatches = find_url_mismatches(links)
    assert len(mismatches) == 0


def test_tracking_pixel_detection():
    html_with_pixel = '<img src="https://track.example.com/pixel.gif" width="1" height="1" />'
    assert detect_tracking_pixels(html_with_pixel) is True


def test_no_tracking_pixel():
    html_normal = '<img src="https://example.com/logo.png" width="200" height="100" />'
    assert detect_tracking_pixels(html_normal) is False


def test_hidden_image_tracking():
    html = '<img src="https://track.example.com/t.gif" style="display:none" />'
    assert detect_tracking_pixels(html) is True


async def test_parse_phishing_email_1(phishing_email_1):
    result = parse_email_structure(phishing_email_1)
    ui = result["untrusted_input"]
    assert len(ui["urls"]) > 0
    assert "paypa1-security.com" in ui["domains"]
    assert ui["sender_domain"] == "paypa1-security.com"
    assert result["has_html"] is True
    assert result["has_tracking_pixels"] is True
    assert len(ui["url_mismatches"]) > 0


async def test_parse_phishing_email_2(phishing_email_2):
    result = parse_email_structure(phishing_email_2)
    ui = result["untrusted_input"]
    assert "targetcorp-docs.com" in ui["domains"]
    assert ui["sender_domain"] == "targetcorp.com"
    assert result["has_html"] is True
    # URL mismatch: display shows docs.targetcorp.com but href is targetcorp-docs.com
    assert len(ui["url_mismatches"]) > 0


async def test_parse_legitimate_email(legitimate_email):
    result = parse_email_structure(legitimate_email)
    ui = result["untrusted_input"]
    assert ui["sender_domain"] == "github.com"
    assert "github.com" in ui["domains"]
    assert result["has_html"] is False
    assert result["has_tracking_pixels"] is False
    assert len(ui["url_mismatches"]) == 0


async def test_parse_email_extracts_ips(phishing_email_1):
    result = parse_email_structure(phishing_email_1)
    # Should find IPs from headers
    assert len(result["untrusted_input"]["ip_addresses"]) > 0


async def test_parse_plain_text_body():
    body = "Check out https://example.com and visit https://test.org"
    result = parse_email_structure(body)
    assert len(result["untrusted_input"]["urls"]) == 2


def test_oversize_input_rejected():
    """An email larger than MAX_EMAIL_CHARS must fail closed before parsing
    starts — caps the work the parser, the MCP transport, and the analyst
    LLM will do on a single tool call.
    """
    oversize = "a" * (MAX_EMAIL_CHARS + 1)
    result = parse_email_structure(oversize)
    assert result["error"] == "input_too_large"
    assert "untrusted_input" in result
    assert result["untrusted_input"]["size_chars"] == MAX_EMAIL_CHARS + 1
    # Make sure the oversize string itself is not echoed back.
    assert oversize not in str(result)


def test_at_limit_input_accepted():
    """An input exactly at the limit must still be parsed (off-by-one guard)."""
    body = "Subject: test\n\n" + "x" * (MAX_EMAIL_CHARS - len("Subject: test\n\n"))
    assert len(body) == MAX_EMAIL_CHARS
    result = parse_email_structure(body)
    assert "error" not in result
    assert "untrusted_input" in result


def test_non_string_input_rejected():
    result = parse_email_structure(b"not a string")  # type: ignore[arg-type]
    assert result["error"] == "invalid_input"
