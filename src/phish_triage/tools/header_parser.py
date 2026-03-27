"""Parse raw email headers into structured data for phishing analysis."""

import email
import email.policy
import re
from datetime import datetime


def _parse_authentication_results(header_value: str) -> dict:
    """Parse Authentication-Results header into structured SPF/DKIM/DMARC verdicts."""
    results = {"spf": None, "dkim": None, "dmarc": None, "raw": header_value}

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
    """Extract relay hops from Received headers (newest first in email, we reverse)."""
    hops = []
    received_headers = msg.get_all("Received", [])

    for header in received_headers:
        hop = {"raw": str(header).strip()}

        # Extract "from" server
        from_match = re.search(r'from\s+([\w.-]+)', str(header), re.IGNORECASE)
        if from_match:
            hop["from"] = from_match.group(1)

        # Extract "by" server — handle IPv6 (2002:a05:...) and FQDNs
        by_match = re.search(r'by\s+([\w.:%-]+)', str(header), re.IGNORECASE)
        if by_match:
            hop["by"] = by_match.group(1)

        # Extract IP — check bracketed [ip] first, then parenthesized (ip) or bare ip
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(header))
        if not ip_match:
            # Match IP in parentheses like (efianalytics.com. 216.244.76.116)
            ip_match = re.search(r'[(\s](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[)\s]', str(header))
        if ip_match:
            hop["ip"] = ip_match.group(1)

        # Extract timestamp
        date_match = re.search(r';\s*(.+)$', str(header))
        if date_match:
            date_str = date_match.group(1).strip()
            hop["timestamp_raw"] = date_str
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

        # DKIM selector
        dkim_selector = _extract_dkim_selector(msg)
        if dkim_selector:
            authentication_results["dkim_selector"] = dkim_selector

        # Received hops
        received_hops = _parse_received_hops(msg)

        # Originating IP (from earliest Received header)
        originating_ip = None
        if received_hops:
            originating_ip = received_hops[0].get("ip")

        # X-headers
        x_headers = {}
        for key in msg.keys():
            if key.lower().startswith("x-"):
                x_headers[key] = str(msg[key])

        return {
            "from_address": from_address,
            "from_display_name": display_name,
            "reply_to": reply_to,
            "return_path": return_path,
            "received_hops": received_hops,
            "authentication_results": authentication_results,
            "originating_ip": originating_ip,
            "message_id": message_id,
            "dkim_selector": dkim_selector,
            "x_headers": x_headers,
        }
    except Exception as e:
        return {"error": "Header parsing failed", "detail": str(e)}
