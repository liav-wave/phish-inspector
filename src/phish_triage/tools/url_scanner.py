"""URLScan.io integration for URL analysis."""

import asyncio
import os
import re

import httpx

from phish_triage.utils.rate_limiter import urlscan_limiter


API_BASE = "https://urlscan.io/api/v1"
TIMEOUT = 15.0


def _validate_url(url: str) -> str | None:
    """Basic URL validation. Returns error message or None if valid."""
    if not url.startswith(("http://", "https://")):
        return "URL must start with http:// or https://"
    # Reject private/loopback IPs
    private_patterns = [
        r'https?://127\.',
        r'https?://10\.',
        r'https?://192\.168\.',
        r'https?://172\.(1[6-9]|2\d|3[01])\.',
        r'https?://localhost',
        r'https?://\[::1\]',
    ]
    for pattern in private_patterns:
        if re.match(pattern, url, re.IGNORECASE):
            return "Refusing to scan private/loopback address"
    return None


async def scan_url(url: str, visibility: str = "unlisted") -> dict:
    """Submit a URL to URLScan.io for analysis.

    Args:
        url: URL to scan.
        visibility: "public" or "unlisted" (default: "unlisted" for client privacy).

    Returns:
        Structured scan results including redirects, final destination, and verdict.
    """
    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        return {
            "error": "not_configured",
            "detail": "URLSCAN_API_KEY environment variable is not set. Get a free API key from urlscan.io.",
        }

    validation_error = _validate_url(url)
    if validation_error:
        return {"error": "invalid_input", "detail": validation_error, "url": url}

    if not await urlscan_limiter.acquire():
        wait = urlscan_limiter.wait_time()
        return {
            "error": "rate_limit",
            "detail": f"URLScan.io rate limit reached. Try again in ~{int(wait)}s.",
            "url": url,
        }

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            # Submit scan
            resp = await client.post(
                f"{API_BASE}/scan/",
                json={"url": url, "visibility": visibility},
                headers={"API-Key": api_key, "Content-Type": "application/json"},
            )

            if resp.status_code == 429:
                return {"error": "rate_limit", "detail": "URLScan.io API rate limit hit.", "url": url}
            if resp.status_code != 200:
                return {"error": "scan_submit_failed", "detail": f"HTTP {resp.status_code}: {resp.text[:200]}", "url": url}

            scan_data = resp.json()
            scan_uuid = scan_data.get("uuid")
            if not scan_uuid:
                return {"error": "scan_submit_failed", "detail": "No UUID in response", "url": url}

            result_url = f"{API_BASE}/result/{scan_uuid}/"

            # Poll for results with backoff
            delays = [5, 10, 15, 20, 25]
            for delay in delays:
                await asyncio.sleep(delay)
                result_resp = await client.get(result_url)
                if result_resp.status_code == 200:
                    data = result_resp.json()
                    page = data.get("page", {})
                    lists = data.get("lists", {})
                    verdicts = data.get("verdicts", {}).get("overall", {})

                    return {
                        "scan_id": scan_uuid,
                        "scan_url": f"https://urlscan.io/result/{scan_uuid}/",
                        "effective_url": page.get("url", url),
                        "redirect_chain": [r.get("url", "") for r in data.get("data", {}).get("requests", [])[:5]],
                        "page_domain": page.get("domain", ""),
                        "page_title": page.get("title", ""),
                        "server": page.get("server", ""),
                        "contacted_domains": lists.get("domains", [])[:20],
                        "is_malicious": verdicts.get("malicious", False),
                        "screenshot_url": f"https://urlscan.io/screenshots/{scan_uuid}.png",
                        "categories": lists.get("categories", []),
                        "url": url,
                    }

            return {
                "error": "scan_timeout",
                "detail": "URLScan.io scan did not complete within 75 seconds. Check manually.",
                "scan_id": scan_uuid,
                "scan_url": f"https://urlscan.io/result/{scan_uuid}/",
                "url": url,
            }
    except httpx.TimeoutException:
        return {"error": "timeout", "detail": "HTTP request to URLScan.io timed out.", "url": url}
    except Exception as e:
        return {"error": "scan_failed", "detail": str(e), "url": url}
