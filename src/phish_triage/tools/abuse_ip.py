"""AbuseIPDB IP reputation checking."""

import os

import httpx

from phish_triage.utils.errors import sanitize_error
from phish_triage.utils.rate_limiter import abuseipdb_limiter
from phish_triage.utils.sanitize import clean_untrusted_string
from phish_triage.utils.validators import validate_ip


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

    # Validate IP (handles hex, decimal, IPv4-mapped IPv6, shorthand notation)
    ip_error = validate_ip(ip_address)
    if ip_error:
        return {"error": "invalid_input", "detail": ip_error, "ip_address": ip_address}

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

            # See CLAUDE.md "Adversarial input" for the trust-tier wrapping
            # contract. Numeric scores and booleans are trusted (provider
            # cannot smuggle prompt text through an integer). The string
            # fields are attacker-influenced and live in untrusted_api_response.
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "untrusted_input": {
                    "ip_address": ip_address,
                },
                "untrusted_api_response": {
                    "isp": clean_untrusted_string(data.get("isp", ""), max_len=200),
                    "country_code": clean_untrusted_string(data.get("countryCode", ""), max_len=10),
                    "usage_type": clean_untrusted_string(data.get("usageType", ""), max_len=100),
                    "domain": clean_untrusted_string(data.get("domain", ""), max_len=255),
                },
            }
    except httpx.TimeoutException:
        return {"error": "timeout", "detail": "AbuseIPDB request timed out.", "ip_address": ip_address}
    except Exception as e:
        return {"error": "abuseipdb_error", "detail": sanitize_error(e), "ip_address": ip_address}
