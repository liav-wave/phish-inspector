"""Lightweight local redirect follower — no third-party API disclosure."""

from urllib.parse import urljoin

import httpx

from phish_triage.utils.errors import sanitize_error
from phish_triage.utils.sanitize import clean_untrusted_string
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
        return {
            "error": "invalid_input",
            "detail": validation_error,
            "untrusted_input": {"url": url},
        }

    chain: list[dict] = []
    current_url = url
    seen_urls: set[str] = set()

    def _wrap(reached_final: bool, error: str | None = None, detail: str | None = None) -> dict:
        """Build the trust-tiered response for any return point.

        See CLAUDE.md "Adversarial input": booleans/counts are trusted; the
        URL the analyst handed us is `untrusted_input`; the chain and the
        final URL we observed are `untrusted_api_response` (they came from
        attacker servers).
        """
        out: dict = {
            "total_redirects": len(chain) - 1 if reached_final else len(chain),
            "reached_final": reached_final,
            "untrusted_input": {"url": url},
            "untrusted_api_response": {
                "final_url": clean_untrusted_string(current_url, max_len=2048),
                "redirect_chain": chain,
            },
        }
        if error is not None:
            out["error"] = error
        if detail is not None:
            out["detail"] = detail
        return out

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            for _ in range(max_redirects + 1):
                if current_url in seen_urls:
                    return _wrap(
                        reached_final=False,
                        error="redirect_loop",
                        detail=f"Redirect loop detected at {clean_untrusted_string(current_url, max_len=2048)}",
                    )
                seen_urls.add(current_url)

                # Try HEAD first, fall back to GET if the server rejects it.
                resp = await client.head(current_url)
                if resp.status_code in HEAD_FALLBACK_CODES:
                    resp = await client.get(current_url)

                # url is server-built (we validated it before reaching here);
                # location and server are attacker-controlled response headers.
                hop = {
                    "url": clean_untrusted_string(current_url, max_len=2048),
                    "status_code": resp.status_code,
                    "location": clean_untrusted_string(resp.headers.get("location"), max_len=2048) or None,
                    "server": clean_untrusted_string(resp.headers.get("server"), max_len=200) or None,
                }

                if resp.status_code not in REDIRECT_CODES or "location" not in resp.headers:
                    # Final destination — not a redirect.
                    hop["location"] = None
                    chain.append(hop)
                    return _wrap(reached_final=True)

                chain.append(hop)

                # Resolve relative redirects and validate next hop, including
                # DNS resolution to catch attacker-controlled hostnames that
                # point at internal addresses.
                next_url = urljoin(current_url, resp.headers["location"])
                next_validation = await validate_url_with_dns(next_url)
                if next_validation:
                    return _wrap(
                        reached_final=False,
                        error="ssrf_blocked",
                        detail=f"Redirect to blocked address: {next_validation}",
                    )

                current_url = next_url

        return _wrap(
            reached_final=False,
            error="max_redirects",
            detail=f"Exceeded {max_redirects} redirects without reaching final destination",
        )

    except httpx.TimeoutException:
        return _wrap(
            reached_final=False,
            error="timeout",
            detail=f"Request timed out after {TIMEOUT}s",
        )
    except Exception as e:
        return _wrap(
            reached_final=False,
            error="request_failed",
            detail=sanitize_error(e),
        )
