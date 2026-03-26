"""AbuseIPDB IP reputation checking."""

import os
import re

import httpx

from phish_triage.utils.rate_limiter import abuseipdb_limiter


TIMEOUT = 15.0


async def check_abuse_ip(ip_address: str, max_age_in_days: int = 90) -> dict:
    """Check IP address reputation via AbuseIPDB.

    Args:
        ip_address: IP to check.
        max_age_in_days: How far back to check reports (default: 90).

    Returns:
        Abuse confidence score, report count, ISP, and usage information.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return {
            "error": "not_configured",
            "detail": "ABUSEIPDB_API_KEY environment variable is not set. Get a free API key from abuseipdb.com.",
        }

    # Validate IP
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address):
        return {"error": "invalid_input", "detail": "Invalid IP address format", "ip_address": ip_address}

    # Reject private IPs
    if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)', ip_address):
        return {"error": "invalid_input", "detail": "Refusing to check private/loopback IP", "ip_address": ip_address}

    if not await abuseipdb_limiter.acquire():
        wait = abuseipdb_limiter.wait_time()
        return {
            "error": "rate_limit",
            "detail": f"AbuseIPDB rate limit reached. Try again in ~{int(wait)}s.",
            "ip_address": ip_address,
        }

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip_address, "maxAgeInDays": max_age_in_days, "verbose": ""},
                headers={"Key": api_key, "Accept": "application/json"},
            )

            if resp.status_code == 429:
                return {"error": "rate_limit", "detail": "AbuseIPDB API rate limit hit.", "ip_address": ip_address}
            if resp.status_code != 200:
                return {"error": "api_error", "detail": f"HTTP {resp.status_code}: {resp.text[:200]}", "ip_address": ip_address}

            data = resp.json().get("data", {})

            return {
                "ip_address": ip_address,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "isp": data.get("isp", ""),
                "country_code": data.get("countryCode", ""),
                "usage_type": data.get("usageType", ""),
                "domain": data.get("domain", ""),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
            }
    except httpx.TimeoutException:
        return {"error": "timeout", "detail": "AbuseIPDB request timed out.", "ip_address": ip_address}
    except Exception as e:
        return {"error": "abuseipdb_error", "detail": str(e), "ip_address": ip_address}
