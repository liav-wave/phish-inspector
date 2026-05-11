"""Lightweight local redirect follower — no third-party API disclosure."""

from urllib.parse import urljoin

import httpx

from phish_triage.utils.errors import sanitize_error
from phish_triage.utils.validators import validate_url_with_dns


TIMEOUT = 10.0
USER_AGENT = "Mozilla/5.0 (compatible; phish-triage/0.1; +https://wavefrontsecurity.com)"
# Status codes that indicate a redirect.
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
# HEAD-specific errors that warrant a GET fallback.
HEAD_FALLBACK_CODES = frozenset({405, 403, 404})


async def follow_redirects(url: str, max_redirects: int = 10) -> dict:
    """Follow HTTP redirects locally without submitting to any third-party service.

    Issues HEAD requests (falling back to GET when servers reject HEAD) and
    records each hop in the redirect chain. All targets are validated against
    SSRF rules at every hop.

    Args:
        url: Starting URL to follow.
        max_redirects: Maximum number of redirects to follow (default 10).

    Returns:
        Redirect chain with final destination, or structured error.
    """
    validation_error = await validate_url_with_dns(url)
    if validation_error:
        return {"error": "invalid_input", "detail": validation_error, "url": url}

    chain: list[dict] = []
    current_url = url
    seen_urls: set[str] = set()

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            for _ in range(max_redirects + 1):
                if current_url in seen_urls:
                    return {
                        "url": url,
                        "final_url": current_url,
                        "redirect_chain": chain,
                        "total_redirects": len(chain),
                        "reached_final": False,
                        "error": "redirect_loop",
                        "detail": f"Redirect loop detected at {current_url}",
                    }
                seen_urls.add(current_url)

                # Try HEAD first, fall back to GET if the server rejects it.
                resp = await client.head(current_url)
                if resp.status_code in HEAD_FALLBACK_CODES:
                    resp = await client.get(current_url)

                hop = {
                    "url": current_url,
                    "status_code": resp.status_code,
                    "location": resp.headers.get("location"),
                    "server": resp.headers.get("server"),
                }

                if resp.status_code not in REDIRECT_CODES or "location" not in resp.headers:
                    # Final destination — not a redirect.
                    hop["location"] = None
                    chain.append(hop)
                    return {
                        "url": url,
                        "final_url": current_url,
                        "redirect_chain": chain,
                        "total_redirects": len(chain) - 1,  # last hop is the destination
                        "reached_final": True,
                    }

                chain.append(hop)

                # Resolve relative redirects and validate next hop, including
                # DNS resolution to catch attacker-controlled hostnames that
                # point at internal addresses.
                next_url = urljoin(current_url, resp.headers["location"])
                next_validation = await validate_url_with_dns(next_url)
                if next_validation:
                    return {
                        "url": url,
                        "final_url": current_url,
                        "redirect_chain": chain,
                        "total_redirects": len(chain),
                        "reached_final": False,
                        "error": "ssrf_blocked",
                        "detail": f"Redirect to blocked address: {next_validation}",
                    }

                current_url = next_url

        # Exceeded max_redirects without reaching a final destination.
        return {
            "url": url,
            "final_url": current_url,
            "redirect_chain": chain,
            "total_redirects": len(chain),
            "reached_final": False,
            "error": "max_redirects",
            "detail": f"Exceeded {max_redirects} redirects without reaching final destination",
        }

    except httpx.TimeoutException:
        return {
            "url": url,
            "final_url": current_url,
            "redirect_chain": chain,
            "total_redirects": len(chain),
            "reached_final": False,
            "error": "timeout",
            "detail": f"Request timed out after {TIMEOUT}s at {current_url}",
        }
    except Exception as e:
        return {
            "url": url,
            "final_url": current_url,
            "redirect_chain": chain,
            "total_redirects": len(chain),
            "reached_final": False,
            "error": "request_failed",
            "detail": sanitize_error(e),
        }
