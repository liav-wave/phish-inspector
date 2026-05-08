#!/usr/bin/env bash
#
# Phish-triage launcher — .env variant (no 1Password CLI).
#
# Reads API keys from .env in the project root. The phish_triage server
# calls load_dotenv() at startup, which finds .env in cwd or any parent.
#
# Use this when 1Password CLI is not available. For the recommended
# production flow, use launch-mcp.sh (which sources keys from 1Password
# at runtime, never writing them to disk).
#
# This script is selected automatically by scripts/setup.sh if .env is
# present in the project root.

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

if [[ ! -f "$PROJECT_DIR/.env" ]]; then
    echo "phish-triage: $PROJECT_DIR/.env not found." >&2
    echo "  This launcher reads API keys from .env. Either:" >&2
    echo "    - Copy .env.example to .env and fill in the keys, or" >&2
    echo "    - Use launch-mcp.sh (1Password) by removing .env and re-running setup.sh." >&2
    exit 1
fi

cd "$PROJECT_DIR"
exec "$UV" run python -m phish_triage
