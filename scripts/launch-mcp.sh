#!/usr/bin/env bash
#
# Phish-triage launcher invoked by Claude Desktop via .mcp.json.
# Wraps `uv run` with `op run` so API keys come from 1Password — never .env on disk.
#
# Cowork inherits a minimal PATH from launchd, so we resolve uv and op by
# absolute path with PATH-fallback. Any errors here surface to Cowork as a
# spawn failure (Cowork reads stderr).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Locate uv. Default install path first, then PATH fallback.
UV="$HOME/.local/bin/uv"
if [[ ! -x "$UV" ]]; then
    UV="$(command -v uv 2>/dev/null || true)"
fi
if [[ -z "$UV" || ! -x "$UV" ]]; then
    echo "phish-triage: uv not found. Install via the official uv installer." >&2
    exit 1
fi

# Locate op (1Password CLI). Standard install path first, then PATH fallback.
OP="/usr/local/bin/op"
if [[ ! -x "$OP" ]]; then
    OP="$(command -v op 2>/dev/null || true)"
fi
if [[ -z "$OP" || ! -x "$OP" ]]; then
    echo "phish-triage: op (1Password CLI) not found. Enable in 1Password Settings → Developer." >&2
    exit 1
fi

cd "$PROJECT_DIR"
exec "$OP" run --env-file=client.env.template -- "$UV" run python -m phish_triage
