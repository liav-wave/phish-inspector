"""URL/domain/IP reputation checks via VirusTotal and Google Safe Browsing."""

import base64
import os

import httpx

from phish_triage.utils.errors import sanitize_error
from phish_triage.utils.rate_limiter import virustotal_limiter, safe_browsing_limiter
from phish_triage.utils.sanitize import clean_untrusted_string
from phish_triage.utils.validators import validate_domain_strict, validate_ip, validate_url


TIMEOUT = 15.0


def _validate_indicator(indicator: str, indicator_type: str) -> str | None:
    """Validate indicator format. Returns error message or None."""
    if indicator_type == "ip":
        return validate_ip(indicator)
    elif indicator_type == "domain":
        return validate_domain_strict(indicator)
    elif indicator_type == "url":
        return validate_url(indicator)
    else:
        return f"Unknown indicator_type: {indicator_type}. Use 'url', 'domain', or 'ip'."
    return None


async def _check_virustotal(indicator: str, indicator_type: str, api_key: str) -> dict:
    """Query VirusTotal API v3."""
    if not await virustotal_limiter.acquire():
        wait = virustotal_limiter.wait_time()
        return {"error": "rate_limit", "detail": f"VirusTotal free tier limit: 4 requests/minute. Try again in ~{int(wait)}s."}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            headers = {"x-apikey": api_key}

            if indicator_type == "url":
                # URL must be base64-encoded for the ID
                url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
                resp = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            elif indicator_type == "domain":
                resp = await client.get(f"https://www.virustotal.com/api/v3/domains/{indicator}", headers=headers)
            elif indicator_type == "ip":
                resp = await client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}", headers=headers)
            else:
                return {"error": "invalid_type", "detail": f"Unknown type: {indicator_type}"}

            if resp.status_code == 429:
                return {"error": "rate_limit", "detail": "VirusTotal API rate limit hit."}
            if resp.status_code == 404:
                return {"detection_ratio": "0/0", "detections": [], "community_score": 0, "categories": {}, "last_analysis_date": None, "note": "Not found in VirusTotal database"}
            if resp.status_code != 200:
                return {"error": "api_error", "detail": f"HTTP {resp.status_code}: {resp.text[:200]}"}

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            # Get specific detections. Engine names are VT-controlled, but
            # `result` strings are partially attacker-influenced (engines often
            # echo back content extracted from the malware/URL).
            detections = []
            for engine, result in data.get("last_analysis_results", {}).items():
                if result.get("category") == "malicious":
                    detections.append({
                        "engine": clean_untrusted_string(engine, max_len=100),
                        "result": clean_untrusted_string(result.get("result", "malicious"), max_len=200),
                    })

            # Categories is a dict of {engine: category_string} — sanitize values.
            raw_categories = data.get("categories", {}) or {}
            categories = {
                clean_untrusted_string(k, max_len=100): clean_untrusted_string(v, max_len=100)
                for k, v in raw_categories.items()
            }

            # Numeric ratios, dates, and community scores are trusted (no
            # string injection surface). Engine names, result strings, and
            # category strings are attacker-influenced — wrap.
            return {
                "detection_ratio": f"{malicious}/{total}",
                "community_score": data.get("reputation", 0),
                "last_analysis_date": data.get("last_analysis_date"),
                "untrusted_api_response": {
                    "detections": detections[:10],
                    "categories": categories,
                },
            }
    except httpx.TimeoutException:
        return {"error": "timeout", "detail": "VirusTotal request timed out."}
    except Exception as e:
        return {"error": "virustotal_error", "detail": sanitize_error(e)}


async def _check_safe_browsing(indicator: str, api_key: str) -> dict:
    """Query Google Safe Browsing API v4."""
    if not await safe_browsing_limiter.acquire():
        return {"error": "rate_limit", "detail": "Google Safe Browsing rate limit reached."}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            body = {
                "client": {"clientId": "phish-triage-mcp", "clientVersion": "0.1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": indicator}],
                },
            }
            resp = await client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                json=body,
                headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
            )

            if resp.status_code != 200:
                return {"error": "api_error", "detail": f"HTTP {resp.status_code}: {resp.text[:200]}"}

            data = resp.json()
            matches = data.get("matches", [])

            return {
                "is_unsafe": len(matches) > 0,
                "untrusted_api_response": {
                    "threat_types": [
                        clean_untrusted_string(m.get("threatType", ""), max_len=100)
                        for m in matches
                    ],
                },
            }
    except httpx.TimeoutException:
        return {"error": "timeout", "detail": "Google Safe Browsing request timed out."}
    except Exception as e:
        return {"error": "safe_browsing_error", "detail": sanitize_error(e)}


async def check_reputation(indicator: str, indicator_type: str) -> dict:
    """Check URL/domain/IP reputation via VirusTotal and Google Safe Browsing.

    Args:
        indicator: URL, domain, or IP address to check.
        indicator_type: One of "url", "domain", "ip".

    Returns:
        Reputation data from VirusTotal and Google Safe Browsing.
    """
    validation_error = _validate_indicator(indicator, indicator_type)
    if validation_error:
        return {
            "error": "invalid_input",
            "detail": validation_error,
            "untrusted_input": {"indicator": indicator, "indicator_type": indicator_type},
        }

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    gsb_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

    # The indicator came from analyzing email content — attacker-authored.
    # VT and Safe Browsing sub-results have their own trust-tier wrapping.
    result: dict = {
        "untrusted_input": {"indicator": indicator, "indicator_type": indicator_type},
    }

    if vt_key:
        result["virustotal"] = await _check_virustotal(indicator, indicator_type, vt_key)
    else:
        result["virustotal"] = {"error": "not_configured", "detail": "VIRUSTOTAL_API_KEY environment variable is not set. Get a free API key from virustotal.com."}

    if gsb_key:
        # Safe Browsing works with URLs; for domains/IPs, construct a URL.
        # Indicator format/safety has already been checked by `_validate_indicator`
        # above (domain regex, IP private-range check). If that contract changes,
        # add a re-validation here — the constructed URL is sent to Google's API,
        # not used for an outbound fetch.
        sb_indicator = indicator
        if indicator_type == "domain":
            sb_indicator = f"http://{indicator}/"
        elif indicator_type == "ip":
            sb_indicator = f"http://{indicator}/"
        result["safe_browsing"] = await _check_safe_browsing(sb_indicator, gsb_key)
    else:
        result["safe_browsing"] = {"error": "not_configured", "detail": "GOOGLE_SAFE_BROWSING_API_KEY environment variable is not set. Get a free API key from Google Cloud Console."}

    return result
