#!/usr/bin/env bash
#
# Build a client-ready tarball of phish-triage from the current HEAD.
#
# Uses `git archive` so the tarball contains only tracked files at HEAD —
# no `.env`, no `spamspamspam/`, no `.venv/`, no untracked dev artifacts.
# Additionally excludes paths listed below at archive time.
#
# Usage:
#   scripts/build-tarball.sh <client-codename>
# Example:
#   scripts/build-tarball.sh griffon
#
# Output: phish-triage-v<version>-<codename>.tar.gz in the project root,
# where <version> is read from pyproject.toml.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <client-codename>" >&2
    exit 1
fi

CODENAME="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Read version from pyproject.toml
VERSION="$(grep -E '^version\s*=' pyproject.toml | head -1 | sed -E 's/^version\s*=\s*"([^"]+)"/\1/')"
if [[ -z "$VERSION" ]]; then
    echo "build-tarball: could not parse version from pyproject.toml" >&2
    exit 1
fi

# Refuse to build if working tree is dirty — clients should get reproducible
# tarballs that match a committed state.
if ! git diff --quiet HEAD -- . ':(exclude)docs/internal/desktop-skill-deploy.md' \
                              ':(exclude)docs/phish-triage-guide.md'; then
    echo "build-tarball: working tree has uncommitted changes." >&2
    echo "  Commit or stash before building a client tarball." >&2
    git status --short >&2
    exit 1
fi

OUTPUT="phish-triage-v${VERSION}-${CODENAME}.tar.gz"

# git archive includes only tracked files. We additionally drop paths that are
# tracked but should not ship to clients (the legacy Cloud Run path).
# Add to this list as the repo evolves.
EXCLUDES=(
    ':(exclude)wip'
    ':(exclude)wip/**'
    ':(exclude).claude/settings.local.json'
    ':(exclude)spamspamspam'
    ':(exclude)spamspamspam/**'
)

git archive --format=tar.gz --prefix=phish-triage/ \
    -o "$OUTPUT" HEAD -- . "${EXCLUDES[@]}"

echo "build-tarball: wrote $OUTPUT"
echo
echo "Contents (top-level):"
tar -tzf "$OUTPUT" | awk -F/ '{print $2}' | sort -u | sed 's/^/  /'
