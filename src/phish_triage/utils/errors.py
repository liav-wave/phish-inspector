"""Error sanitization to prevent API key leakage in tool responses."""

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
