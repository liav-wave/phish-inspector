"""URL/domain/IP reputation checks via VirusTotal and Google Safe Browsing."""

import base64
import os
import re

import httpx

from phish_triage.utils.rate_limiter import virustotal_limiter, safe_browsing_limiter


TIMEOUT = 15.0


def _validate_indicator(indicator: str, indicator_type: str) -> str | None:
    """Validate indicator format. Returns error message or None."""
    if indicator_type == "ip":
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
            return "Invalid IP address format"
        # Reject private IPs
        if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)', indicator):
            return "Refusing to check private/loopback IP"
    elif indicator_type == "domain":
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', indicator):
            return "Invalid domain format"
    elif indicator_type == "url":
        if not indicator.startswith(("http://", "https://")):
            return "URL must start with http:// or https://"
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

            # Get specific detections
            detections = []
            for engine, result in data.get("last_analysis_results", {}).items():
                if result.get("category") == "malicious":
                    detections.append({"engine": engine, "result": result.get("result", "malicious")})

            return {
                "detection_ratio": f"{malicious}/{total}",
                "detections": detections[:10],
                "community_score": data.get("reputation", 0),
                "categories": data.get("categories", {}),
                "last_analysis_date": data.get("last_analysis_date"),
            }
    except httpx.TimeoutException:
        return {"error": "timeout", "detail": "VirusTotal request timed out."}
    except Exception as e:
        return {"error": "virustotal_error", "detail": str(e)}


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
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json=body,
            )

            if resp.status_code != 200:
                return {"error": "api_error", "detail": f"HTTP {resp.status_code}: {resp.text[:200]}"}

            data = resp.json()
            matches = data.get("matches", [])

            return {
                "is_unsafe": len(matches) > 0,
                "threat_types": [m.get("threatType", "") for m in matches],
            }
    except httpx.TimeoutException:
        return {"error": "timeout", "detail": "Google Safe Browsing request timed out."}
    except Exception as e:
        return {"error": "safe_browsing_error", "detail": str(e)}


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
        return {"error": "invalid_input", "detail": validation_error, "indicator": indicator}

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    gsb_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

    result: dict = {"indicator": indicator, "indicator_type": indicator_type}

    if vt_key:
        result["virustotal"] = await _check_virustotal(indicator, indicator_type, vt_key)
    else:
        result["virustotal"] = {"error": "not_configured", "detail": "VIRUSTOTAL_API_KEY environment variable is not set. Get a free API key from virustotal.com."}

    if gsb_key:
        # Safe Browsing works with URLs; for domains/IPs, construct a URL
        sb_indicator = indicator
        if indicator_type == "domain":
            sb_indicator = f"http://{indicator}/"
        elif indicator_type == "ip":
            sb_indicator = f"http://{indicator}/"
        result["safe_browsing"] = await _check_safe_browsing(sb_indicator, gsb_key)
    else:
        result["safe_browsing"] = {"error": "not_configured", "detail": "GOOGLE_SAFE_BROWSING_API_KEY environment variable is not set. Get a free API key from Google Cloud Console."}

    return result
