#!/usr/bin/env bash
#
# Phish-triage one-time setup. Generates .mcp.json with absolute paths.
#
# WHAT THIS DOES:
#   - Resolves this project's absolute path
#   - Generates .mcp.json from .mcp.json.example with that path substituted
#   - Validates the result is valid JSON
#   - Reports whether `uv` and `op` (1Password CLI) are available
#
# WHAT THIS DOES NOT DO:
#   - No network requests
#   - No privilege escalation, no sudo
#   - No package installs
#   - Does not modify any file outside this project directory
#
# Run from anywhere:  bash scripts/setup.sh   (or)   ./scripts/setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

EXAMPLE="$PROJECT_DIR/.mcp.json.example"
TARGET="$PROJECT_DIR/.mcp.json"

if [[ ! -f "$EXAMPLE" ]]; then
    echo "setup: $EXAMPLE not found." >&2
    echo "       Are you running this from inside the phish-triage project?" >&2
    exit 1
fi

if [[ -e "$TARGET" ]]; then
    echo "setup: $TARGET already exists. Refusing to overwrite."
    echo "       Delete it manually if you want to regenerate."
    exit 0
fi

# Decide which launcher to wire into .mcp.json based on what's available.
# Priority: if .env is present, use the env launcher (debug/first-deploy
# path). Otherwise, if 1Password CLI is reachable, use the op launcher
# (production path). If neither, fail with both remediation paths.
if [[ -f "$PROJECT_DIR/.env" ]]; then
    LAUNCHER="launch-mcp-env.sh"
    LAUNCHER_REASON=".env present in project root"
elif [[ -x "/usr/local/bin/op" ]] || command -v op >/dev/null 2>&1; then
    LAUNCHER="launch-mcp.sh"
    LAUNCHER_REASON="1Password CLI available"
else
    echo "setup: cannot pick a launcher. Neither path is available:" >&2
    echo "  - $PROJECT_DIR/.env not present" >&2
    echo "  - 1Password CLI (op) not found in /usr/local/bin or PATH" >&2
    echo "" >&2
    echo "Either:" >&2
    echo "  cp .env.example .env  # then fill in the keys" >&2
    echo "OR" >&2
    echo "  enable 1Password CLI: 1Password app -> Settings -> Developer" >&2
    exit 1
fi

# Substitute placeholders. We use | as the sed delimiter to avoid clashing
# with / in absolute paths. macOS paths essentially never contain |.
sed -e "s|__PROJECT_DIR__|$PROJECT_DIR|g" \
    -e "s|__LAUNCHER__|$LAUNCHER|g" \
    "$EXAMPLE" > "$TARGET"

# Validate the result is parseable JSON. If not, remove and bail.
if ! python3 -m json.tool "$TARGET" > /dev/null 2>&1; then
    echo "setup: generated $TARGET is not valid JSON. Removing." >&2
    rm -f "$TARGET"
    exit 1
fi

echo "setup: wrote $TARGET"
echo "       launcher: $LAUNCHER  ($LAUNCHER_REASON)"
echo

# Helpful but non-fatal checks for runtime dependencies.
echo "Runtime dependency check:"
if [[ -x "$HOME/.local/bin/uv" ]]; then
    echo "  uv:  $("$HOME/.local/bin/uv" --version 2>/dev/null) at $HOME/.local/bin/uv"
elif command -v uv >/dev/null 2>&1; then
    echo "  uv:  $(uv --version 2>/dev/null) at $(command -v uv)"
else
    echo "  uv:  NOT FOUND — install via the official uv installer (see docs/install-quickstart.md)"
fi

if [[ -x "/usr/local/bin/op" ]]; then
    echo "  op:  $(/usr/local/bin/op --version 2>/dev/null) at /usr/local/bin/op"
elif command -v op >/dev/null 2>&1; then
    echo "  op:  $(op --version 2>/dev/null) at $(command -v op)"
else
    echo "  op:  NOT FOUND — enable in 1Password app: Settings → Developer"
fi

echo
echo "Next steps:"
echo "  1. Run 'uv sync --frozen' to install pinned Python dependencies"
echo "  2. Open this directory in Claude Desktop's Code tab"
