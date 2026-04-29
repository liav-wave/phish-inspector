"""Error sanitization to prevent API key leakage in tool responses."""

import functools
import re


_SENSITIVE_PARAM_RE = re.compile(
    r'(\?|&)(key|apikey|api_key|api-key|token|secret)=[^&\s"\']+',
    re.IGNORECASE,
)
_SENSITIVE_HEADER_RE = re.compile(
    r'(API-Key|Authorization|x-apikey|Key|Bearer):\s*\S+',
    re.IGNORECASE,
)


def sanitize_error(e: Exception) -> str:
    """Remove API keys and sensitive data from exception messages."""
    msg = str(e)
    msg = _SENSITIVE_PARAM_RE.sub(r'\1\2=REDACTED', msg)
    msg = _SENSITIVE_HEADER_RE.sub(r'\1: REDACTED', msg)
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
            return {"error": "internal_error", "detail": sanitize_error(e)}
    return wrapper
