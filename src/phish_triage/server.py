"""Phishing Triage MCP Server — FastMCP tool registrations."""

import os
import sys

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from phish_triage.tools.header_parser import parse_email_headers
from phish_triage.tools.dns_lookup import dns_lookup
from phish_triage.tools.whois_lookup import whois_lookup
from phish_triage.tools.url_scanner import scan_url
from phish_triage.tools.reputation import check_reputation
from phish_triage.tools.abuse_ip import check_abuse_ip
from phish_triage.tools.redirect_follower import follow_redirects
from phish_triage.utils.email_parser import parse_email_structure
from phish_triage.utils.errors import sanitize_tool

load_dotenv()

# Bind to loopback by default. The active client deployment uses stdio
# transport (no socket is opened regardless of this value). Wider binds are
# only meaningful for the legacy Cloud Run path in `wip/cloud-run/`, and that
# path must opt in explicitly via `PHISH_TRIAGE_BIND_HOST=0.0.0.0`. This
# prevents an accidental `python -m phish_triage http` on a laptop from
# exposing an unauthenticated MCP server to the LAN.
_BIND_HOST = os.environ.get("PHISH_TRIAGE_BIND_HOST", "127.0.0.1")

mcp = FastMCP(
    "Phishing Triage",
    instructions="Email phishing analysis and enrichment tools. Call these tools to gather technical intelligence about suspicious emails.",
    host=_BIND_HOST,
    port=int(os.environ.get("PORT", 8080)),
)


@mcp.tool()
@sanitize_tool
async def tool_parse_email_headers(raw_headers: str) -> dict:
    """Parse raw email headers into structured data for phishing analysis.

    Extracts sender info, authentication results (SPF/DKIM/DMARC), relay hops,
    originating IP, and X-headers. This is typically the first tool to call
    when analyzing a suspicious email. Input: raw headers from Gmail's
    "Show original" or similar.
    """
    return await parse_email_headers(raw_headers)


@mcp.tool()
@sanitize_tool
async def tool_dns_lookup(domain: str, record_types: list[str] | None = None, dkim_selector: str | None = None) -> dict:
    """Query DNS records to check a domain's mail authentication and legitimacy.

    Returns MX, SPF, DMARC, DKIM (if selector provided), A, and NS records.
    Use this after parsing headers to verify the sender domain has proper
    mail configuration. Domains with no MX/SPF/DMARC are suspicious.
    """
    return await dns_lookup(domain, record_types, dkim_selector)


@mcp.tool()
@sanitize_tool
async def tool_whois_lookup(domain: str) -> dict:
    """Get WHOIS registration data for a domain to assess age and legitimacy.

    Returns registrar, creation/expiration dates, domain age, and privacy status.
    Domains less than 30 days old used in email are very suspicious. WHOIS
    privacy alone is not suspicious, but combined with a new domain it is.
    """
    return await whois_lookup(domain)


@mcp.tool()
@sanitize_tool
async def tool_scan_url(url: str) -> dict:
    """Submit a URL to URLScan.io for full page analysis.

    Returns the final destination after redirects, page title, contacted domains,
    and maliciousness verdict. URLScan visibility is fixed to "unlisted" for
    client privacy — the submission is not publicly searchable.
    Scanning takes 10-20 seconds. Requires URLSCAN_API_KEY.
    """
    return await scan_url(url)


@mcp.tool()
@sanitize_tool
async def tool_check_reputation(indicator: str, indicator_type: str) -> dict:
    """Check URL/domain/IP reputation via VirusTotal and Google Safe Browsing.

    indicator_type must be one of: "url", "domain", "ip".
    Returns detection ratios, community scores, and threat classifications.
    Requires VIRUSTOTAL_API_KEY and/or GOOGLE_SAFE_BROWSING_API_KEY.
    """
    return await check_reputation(indicator, indicator_type)


@mcp.tool()
@sanitize_tool
async def tool_check_abuse_ip(ip_address: str, max_age_in_days: int = 90) -> dict:
    """Check IP address reputation via AbuseIPDB.

    Returns abuse confidence score (0-100), report count, ISP, usage type,
    and whether the IP is a known Tor exit node. "Data Center/Web Hosting"
    usage type for a mail sender is mildly suspicious. Requires ABUSEIPDB_API_KEY.
    """
    return await check_abuse_ip(ip_address, max_age_in_days)


@mcp.tool()
@sanitize_tool
async def tool_follow_redirects(url: str, max_redirects: int = 10) -> dict:
    """Follow HTTP redirect chains locally without submitting to any third-party service.

    Issues HEAD requests (falling back to GET when servers reject HEAD) and
    records each hop. Use this for quick triage of where a link leads.
    Does NOT render JavaScript, so JS-based redirects (meta refresh,
    window.location) will not be followed. For full page rendering, use
    scan_url (URLScan.io) instead — but note the third-party disclosure.
    No API key required.
    """
    return await follow_redirects(url, max_redirects)


@mcp.tool()
@sanitize_tool
async def tool_extract_email_indicators(raw_email: str) -> dict:
    """Extract all actionable indicators from a raw email for further analysis.

    Finds all URLs, domains, IP addresses, and attachments. Detects URL
    mismatches (where display text shows a different URL than the href) and
    tracking pixels. Input: full raw email (headers + body) or just the body.
    """
    return parse_email_structure(raw_email)


# Startup: warn about missing API keys
def _check_api_keys():
    keys = {
        "URLSCAN_API_KEY": "scan_url",
        "VIRUSTOTAL_API_KEY": "check_reputation (VirusTotal)",
        "GOOGLE_SAFE_BROWSING_API_KEY": "check_reputation (Safe Browsing)",
        "ABUSEIPDB_API_KEY": "check_abuse_ip",
    }
    missing = [f"  {k} — needed for {v}" for k, v in keys.items() if not os.environ.get(k)]
    if missing:
        import logging
        logger = logging.getLogger("phish_triage")
        logger.warning("Missing API keys (tools will return helpful errors when called):\n%s", "\n".join(missing))


_check_api_keys()


if __name__ == "__main__":
    # The active per-client deployment is stdio, launched by Claude Desktop
    # via scripts/launch-mcp{,-env}.sh. HTTP/streamable-http transport is only
    # used by the legacy Cloud Run path (`wip/cloud-run/`); to keep that path
    # off by default on client laptops, this entry point is stdio-only. The
    # Cloud Run container uses `__main__.py http`, which gates HTTP behind a
    # warning and the `PHISH_TRIAGE_BIND_HOST` env var.
    mcp.run()
