#!/usr/bin/env bash
#
# Wavefront / phish-triage — pre-deploy machine inspection.
#
# WHAT THIS SCRIPT DOES:
#   Reports versions and presence of tools we may need to deploy the
#   phish-triage Claude skill. Output goes to your terminal only.
#
# WHAT THIS SCRIPT DOES NOT DO:
#   - No files are read for content (existence checks only).
#   - No network requests (no curl, wget, ssh, etc.).
#   - No files are created, modified, or deleted.
#   - No sudo, no admin prompts, no privilege escalation.
#   - No data is transmitted anywhere — copy/paste of output is manual.
#
# HOW TO RUN:
#   1. Open this file in a text editor and read it end-to-end.
#   2. In Terminal, cd to the directory containing this file.
#   3. Run:    bash preflight-check.sh
#   4. Copy the full output and send it back to Liav.

set -u

# Print a version line for a command, or "not present" if missing.
# The list of commands is hardcoded below — no user input is interpolated.
check_tool() {
    local cmd="$1"
    if command -v "$cmd" >/dev/null 2>&1; then
        local ver
        ver=$("$cmd" --version 2>&1 | head -1)
        printf "  %-10s %s  (%s)\n" "$cmd" "$ver" "$(command -v "$cmd")"
    else
        printf "  %-10s not present\n" "$cmd"
    fi
}

echo "=== phish-triage preflight check ==="
echo "Run at: $(date '+%Y-%m-%d %H:%M:%S %Z')"

echo
echo "--- System ---"
echo "  macOS:        $(sw_vers -productVersion 2>/dev/null || echo unknown)"
echo "  Architecture: $(uname -m)"
echo "  Shell:        ${SHELL:-unknown}"

echo
echo "--- Claude Desktop ---"
if [ -d "/Applications/Claude.app" ]; then
    CD_PATH="/Applications/Claude.app"
elif [ -d "$HOME/Applications/Claude.app" ]; then
    CD_PATH="$HOME/Applications/Claude.app"
else
    CD_PATH=""
fi
if [ -n "$CD_PATH" ]; then
    CD_VERSION=$(defaults read "$CD_PATH/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo unknown)
    echo "  Claude.app:   installed at $CD_PATH (version $CD_VERSION)"
else
    echo "  Claude.app:   NOT INSTALLED"
fi

echo
echo "--- Required runtime ---"
check_tool python3
check_tool uv
check_tool git

echo
echo "--- Optional / nice to have ---"
check_tool brew
check_tool node
check_tool gcloud

echo
echo "--- Xcode Command Line Tools ---"
if xcode-select -p >/dev/null 2>&1; then
    echo "  CLT path:     $(xcode-select -p)"
else
    echo "  CLT:          not present"
fi

echo
echo "--- Storage ---"
df -h "$HOME" | sed 's/^/  /'

echo
echo "=== end of report ==="
echo
echo "Copy everything from the first === line to this line and send back to Liav."
