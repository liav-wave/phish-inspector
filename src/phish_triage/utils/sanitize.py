"""Sanitize attacker-controllable strings before returning them to the model.

Tool results from URL scanning, email parsing, WHOIS, etc. include data that
the phisher controls (page titles, link text, registrant fields). When that
data flows back to Claude as MCP tool output, it becomes "untrusted observed
content" the attacker can use to manipulate the analysis verdict.

We mitigate by stripping control characters, zero-width characters, and ANSI
escape sequences, then truncating to a defensive maximum length. We do NOT
attempt to detect prompt-injection content semantically — that's the model's
job. We just remove the most common obfuscation tricks and bound the size.
"""

import re


_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0e-\x1f\x7f]')
# Zero-width / invisible characters used to hide content from humans:
# ZWSP, ZWNJ, ZWJ, WORD JOINER, BOM.
_ZERO_WIDTH_RE = re.compile('[​‌‍⁠﻿]')
_ANSI_CSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def clean_untrusted_string(s: object, max_len: int = 500) -> str:
    """Remove control/zero-width chars and ANSI escapes, then truncate.

    Accepts any object — non-strings are coerced via `str()` and treated the
    same. Returns an empty string for None or coercion failures.

    `max_len` is a per-field cap, not a per-response cap. Choose it relative
    to the field's expected size (a page title doesn't need 5000 chars).
    """
    if s is None:
        return ""
    try:
        text = s if isinstance(s, str) else str(s)
    except Exception:
        return ""
    text = _ANSI_CSI_RE.sub('', text)
    text = _CONTROL_CHARS_RE.sub('', text)
    text = _ZERO_WIDTH_RE.sub('', text)
    if len(text) > max_len:
        text = text[:max_len] + "…[truncated]"
    return text
