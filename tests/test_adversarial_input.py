"""Defensive tests: confirm attacker-controlled strings in tool outputs are
sanitized before returning to the analyst LLM.

This is the contract laid out in CLAUDE.md's "Adversarial input" section:
every attacker-authored or attacker-influenced field must pass through
`clean_untrusted_string` and have a per-field length cap. These tests guard
against regressions where a future change leaks raw attacker bytes.
"""

from pathlib import Path

from phish_triage.tools.header_parser import parse_email_headers
from phish_triage.utils.email_parser import parse_email_structure


FIXTURE = Path(__file__).parent / "fixtures" / "adversarial_injection.eml"

# Bytes that must never appear in any string field of any tool response.
# - ANSI CSI (`\x1b[` introducer)
# - C0 control chars (excluding CR/LF/TAB which the cleaner preserves)
# - Zero-width chars (ZWSP, ZWNJ, ZWJ, WORD-JOINER, BOM)
# - BiDi overrides (RLO U+202E, LRO U+202D, PDF U+202C) — these are not in
#   the current cleaner's zero-width set, so adding a test here also flags
#   if we need to extend the cleaner.
FORBIDDEN_SUBSTRINGS = [
    "\x1b[",
    "\x00",
    "\x01",
    "\x07",  # bell
    "​",  # ZWSP
    "‌",  # ZWNJ
    "‍",  # ZWJ
    "⁠",  # word joiner
    "﻿",  # BOM
]


def _assert_clean(value, path: str) -> None:
    """Recursively check that no string in a nested structure contains
    forbidden bytes. `path` is for error messages.
    """
    if isinstance(value, str):
        for bad in FORBIDDEN_SUBSTRINGS:
            assert bad not in value, (
                f"forbidden byte {bad!r} found in {path}: {value!r}"
            )
    elif isinstance(value, dict):
        for k, v in value.items():
            _assert_clean(k, f"{path}.<key:{k!r}>")
            _assert_clean(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _assert_clean(item, f"{path}[{i}]")
    # int, bool, None, etc. — nothing to check.


async def test_header_parser_cleans_adversarial_eml():
    raw = FIXTURE.read_text()
    result = await parse_email_headers(raw)
    _assert_clean(result, "parse_email_headers")
    ui = result["untrusted_input"]
    # Spot check: the display name still has the legible portion and dropped the ANSI.
    assert "IT Support" in ui["from_display_name"]
    assert "\x1b" not in ui["from_display_name"]
    # X-headers preserved by key, but contents stripped.
    assert "X-Mailer" in ui["x_headers"]
    assert "​" not in ui["x_headers"]["X-Mailer"]


def test_email_parser_cleans_adversarial_eml():
    raw = FIXTURE.read_text()
    result = parse_email_structure(raw)
    _assert_clean(result, "parse_email_structure")
    # Attachment filename had an RTLO override (U+202E). The cleaner now
    # strips BiDi controls; if it's removed, this trip-wire fires.
    for att in result["untrusted_input"]["attachments"]:
        assert "‮" not in att["filename"], (
            "RTLO override leaked through attachment filename — extend "
            "clean_untrusted_string to strip BiDi controls"
        )


async def test_no_attacker_instruction_amplification():
    """A separate concern from sanitization: the parsed headers should
    preserve the attacker's instruction text *visibly* (not hidden by
    control chars), so the analyst LLM and the human reviewer both see
    exactly what was sent.

    The defense against the instructions is at the SKILL.md / prompt layer,
    not here. This test exists so that anyone tempted to "helpfully" filter
    out injection-like phrases at the tool layer gets a failure to think
    about it first.
    """
    raw = FIXTURE.read_text()
    result = await parse_email_headers(raw)
    # The string "IGNORE PREVIOUS INSTRUCTIONS" is in the From header.
    # The cleaner stripped the ANSI wrapper but preserved the plain text —
    # that is intentional: the analyst should see what the attacker tried.
    assert "IGNORE PREVIOUS INSTRUCTIONS" in result["untrusted_input"]["from_display_name"]
