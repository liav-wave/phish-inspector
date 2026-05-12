"""Parse raw email headers into structured data for phishing analysis."""

import email
import email.policy
import re
from datetime import datetime

from phish_triage.utils.email_parser import MAX_EMAIL_CHARS
from phish_triage.utils.errors import sanitize_error
from phish_triage.utils.sanitize import clean_untrusted_string


def _parse_authentication_results(header_value: str) -> dict:
    """Parse Authentication-Results header into structured SPF/DKIM/DMARC verdicts.

    Returned dict lives inside `untrusted_input` in the tool response. The
    extracted verdict tokens (spf/dkim/dmarc) come from a constrained alphabet
    (`\\w+` post-regex) so they need no further cleaning; the `raw` field is
    sanitized to remove control/zero-width/BiDi bytes.
    """
    results = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "raw": clean_untrusted_string(header_value, max_len=1000),
    }

    if not header_value:
        return results

    # SPF
    spf_match = re.search(r'spf=(\w+)', header_value, re.IGNORECASE)
    if spf_match:
        results["spf"] = spf_match.group(1).lower()

    # DKIM
    dkim_match = re.search(r'dkim=(\w+)', header_value, re.IGNORECASE)
    if dkim_match:
        results["dkim"] = dkim_match.group(1).lower()

    # DMARC
    dmarc_match = re.search(r'dmarc=(\w+)', header_value, re.IGNORECASE)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1).lower()

    return results


def _parse_received_hops(msg: email.message.Message) -> list[dict]:
    """Extract relay hops from Received headers (newest first in email, we reverse).

    All string fields are attacker-influenced (the sender's MTA can put nearly
    arbitrary bytes in a Received header until it reaches a relay we trust).
    Clean every string returned to the model.
    """
    hops = []
    received_headers = msg.get_all("Received", [])

    for header in received_headers:
        hop = {"raw": clean_untrusted_string(str(header).strip(), max_len=1000)}

        # Extract "from" server
        from_match = re.search(r'from\s+([\w.-]+)', str(header), re.IGNORECASE)
        if from_match:
            hop["from"] = clean_untrusted_string(from_match.group(1), max_len=255)

        # Extract "by" server — handle IPv6 (2002:a05:...) and FQDNs
        by_match = re.search(r'by\s+([\w.:%-]+)', str(header), re.IGNORECASE)
        if by_match:
            hop["by"] = clean_untrusted_string(by_match.group(1), max_len=255)

        # Extract IP — check bracketed [ip] first, then parenthesized (ip) or bare ip
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(header))
        if not ip_match:
            # Match IP in parentheses like (efianalytics.com. 216.244.76.116)
            ip_match = re.search(r'[(\s](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[)\s]', str(header))
        if ip_match:
            # IP literal; only need length safety, not control-char stripping.
            hop["ip"] = ip_match.group(1)

        # Extract timestamp
        date_match = re.search(r';\s*(.+)$', str(header))
        if date_match:
            date_str = date_match.group(1).strip()
            hop["timestamp_raw"] = clean_untrusted_string(date_str, max_len=100)
            try:
                parsed = email.utils.parsedate_to_datetime(date_str)
                hop["timestamp"] = parsed.isoformat()
            except (ValueError, TypeError):
                pass

        hops.append(hop)

    # Reverse so oldest (originating) hop is first
    hops.reverse()
    return hops


def _extract_dkim_selector(msg: email.message.Message) -> str | None:
    """Extract DKIM selector from DKIM-Signature header."""
    dkim_sig = msg.get("DKIM-Signature", "")
    if not dkim_sig:
        return None
    match = re.search(r's=([^;\s]+)', str(dkim_sig))
    return match.group(1) if match else None


async def parse_email_headers(raw_headers: str) -> dict:
    """Parse raw email headers into structured phishing analysis data.

    Args:
        raw_headers: Raw email headers (from Gmail's "Show original" or similar).

    Returns:
        Structured header data including authentication results, relay hops,
        and sender information.
    """
    if not isinstance(raw_headers, str):
        return {
            "error": "invalid_input",
            "detail": "raw_headers must be a string",
            "untrusted_input": {"size_chars": 0},
        }
    if len(raw_headers) > MAX_EMAIL_CHARS:
        return {
            "error": "input_too_large",
            "detail": (
                f"Input exceeds {MAX_EMAIL_CHARS} character limit "
                f"(received {len(raw_headers)} chars). Trim the message and retry."
            ),
            "untrusted_input": {"size_chars": len(raw_headers)},
        }

    try:
        msg = email.message_from_string(raw_headers, policy=email.policy.default)

        from_header = msg.get("From", "")
        # Parse display name and email
        display_name = ""
        from_address = from_header
        match = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>', from_header)
        if match:
            display_name = match.group(1).strip()
            from_address = match.group(2).strip()
        elif re.match(r'^[\w.+-]+@[\w.-]+$', from_header.strip()):
            from_address = from_header.strip()

        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        message_id = msg.get("Message-ID", "")

        # Authentication results — check both standard and ARC headers
        auth_results_raw = msg.get("Authentication-Results", "")
        arc_auth_raw = msg.get("ARC-Authentication-Results", "")
        auth_header = auth_results_raw or arc_auth_raw
        authentication_results = _parse_authentication_results(auth_header)

        # DKIM selector — clean once at the extraction site so both copies
        # of this string (the top-level field and the nested one inside
        # authentication_results) come from the sanitized value.
        dkim_selector_raw = _extract_dkim_selector(msg)
        dkim_selector = (
            clean_untrusted_string(dkim_selector_raw, max_len=100)
            if dkim_selector_raw else None
        )
        if dkim_selector:
            authentication_results["dkim_selector"] = dkim_selector

        # Received hops
        received_hops = _parse_received_hops(msg)

        # Originating IP (from earliest Received header)
        originating_ip = None
        if received_hops:
            originating_ip = received_hops[0].get("ip")

        # X-headers — both keys and values are attacker-influenced.
        x_headers = {}
        for key in msg.keys():
            if key.lower().startswith("x-"):
                x_headers[clean_untrusted_string(key, max_len=100)] = clean_untrusted_string(
                    str(msg[key]), max_len=500
                )

        # Header content is entirely attacker-authored: every field below
        # was written by the sender's MTA chain. authentication_results is
        # set by the receiving MTA — partial trust, but we keep it inside
        # the untrusted container because we cannot verify which hop wrote
        # it. originating_ip is an IP literal so no string-injection surface,
        # but it's still attacker-influenced data.
        return {
            "untrusted_input": {
                "from_address": clean_untrusted_string(from_address, max_len=320),
                "from_display_name": clean_untrusted_string(display_name, max_len=200),
                "reply_to": clean_untrusted_string(reply_to, max_len=320),
                "return_path": clean_untrusted_string(return_path, max_len=320),
                "received_hops": received_hops,
                "authentication_results": authentication_results,
                "originating_ip": originating_ip,
                "message_id": clean_untrusted_string(message_id, max_len=255),
                "dkim_selector": dkim_selector,
                "x_headers": x_headers,
            },
        }
    except Exception as e:
        return {"error": "Header parsing failed", "detail": sanitize_error(e)}
