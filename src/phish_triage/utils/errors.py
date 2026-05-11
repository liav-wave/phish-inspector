"""Error sanitization to prevent API key leakage in tool responses."""

import functools
import re


# Maximum length of an error detail string returned to the model. Matches the
# 200-char cap used in per-tool error paths. Applied here so the @sanitize_tool
# decorator's safety net also bounds the output, not just length-bounding tools
# that explicitly slice their error strings.
_MAX_ERROR_DETAIL_LEN = 200


# Header / query-param patterns where the credential follows a label.
_SENSITIVE_PARAM_RE = re.compile(
    r'(\?|&)(key|apikey|api_key|api-key|token|secret)=[^&\s"\']+',
    re.IGNORECASE,
)
_SENSITIVE_HEADER_RE = re.compile(
    # Redact the entire header value, not just the first whitespace-delimited
    # token, so that schemes like "Authorization: Bearer <token>" don't leak
    # the token after the scheme keyword. We stop at newline / comma / quote
    # to avoid redacting anything past the header itself.
    r'(API-Key|Authorization|x-apikey|Key|Bearer):\s*[^\r\n,"\']+',
    re.IGNORECASE,
)


# Bare credential shapes — for cases where the key value appears without a
# preceding label (e.g. dumped from an httpx headers dict-repr, or from a JSON
# decode error showing the request body). Patterns are anchored on the
# provider-specific prefix or fixed length so they do not over-redact normal
# strings.
_BARE_KEY_PATTERNS = [
    # Google API keys — `AIzaSy` + 33 of [A-Za-z0-9_-].
    re.compile(r'\bAIzaSy[0-9A-Za-z_\-]{33}\b'),
    # AbuseIPDB keys are 80 lowercase hex chars.
    re.compile(r'\b[0-9a-f]{80}\b'),
    # URLScan keys are UUIDv4 (the visible 8-4-4-4-12 form). Only the API key
    # field, not scan UUIDs returned in responses, looks like this; in error
    # messages we redact aggressively because the false-positive cost is low.
    re.compile(
        r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        re.IGNORECASE,
    ),
]


def sanitize_error(e: Exception) -> str:
    """Remove API keys and sensitive data from exception messages."""
    msg = str(e)
    msg = _SENSITIVE_PARAM_RE.sub(r'\1\2=REDACTED', msg)
    msg = _SENSITIVE_HEADER_RE.sub(r'\1: REDACTED', msg)
    for pat in _BARE_KEY_PATTERNS:
        msg = pat.sub('REDACTED', msg)
    return msg


def sanitize_tool(fn):
    """Decorator: catch-all for unhandled exceptions in MCP tool functions.

    Applied at the tool registration boundary in server.py. Individual tools
    still handle their own errors with try/except + sanitize_error(). This
    decorator is the safety net — if anything slips through, it returns a
    sanitized error dict instead of leaking a raw traceback.
    """
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except Exception as e:
            detail = sanitize_error(e)
            if len(detail) > _MAX_ERROR_DETAIL_LEN:
                detail = detail[:_MAX_ERROR_DETAIL_LEN] + "…[truncated]"
            return {"error": "internal_error", "detail": detail}
    return wrapper
