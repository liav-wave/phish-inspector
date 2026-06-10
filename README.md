# 🐟 Inspector

An MCP server providing email phishing analysis and enrichment tools — DNS,
WHOIS, URL scanning, IP reputation, redirect following — for use from Claude
Desktop or Claude Code. Internal Wavefront Security tool.

## Form factor

Per-client deployments run as a **local stdio MCP server** on the client's
laptop. Claude Desktop launches `python -m phish_triage` as a subprocess; email
content is processed locally and never traverses Wavefront infrastructure. The
only outbound network traffic is to the third-party enrichment APIs (URLScan,
Google Safe Browsing, AbuseIPDB) and public DNS / WHOIS.

## Layout

| Path | What's here |
|---|---|
| `src/phish_triage/` | The MCP server (FastMCP), enrichment tools, and shared utils |
| `tests/` | Pytest suite; fixtures are fully synthetic |
| `scripts/launch-mcp.sh` | Steady-state launcher: API keys via 1Password CLI |
| `scripts/launch-mcp-env.sh` | First-deploy launcher: API keys via `.env` |
| `scripts/setup.sh` | Generates `.mcp.json`, picks launcher, validates deps |
| `scripts/build-tarball.sh` | Build a client tarball from the current HEAD |
| `.claude/skills/phish-triage/` | The Claude skill the client drops into Claude Desktop |
| `docs/phish-triage-guide.md` | Client-facing user guide (ships in tarball) |
| `docs/internal/desktop-skill-deploy.md` | Operator runbook for the active deployment |
| `wip/cloud-run/` | Legacy hosted-variant deployment, not in active use |

## Develop

```
uv sync                 # install pinned deps
uv run pytest           # full test suite
uv run pip-audit        # dependency vulnerability scan
```

`CLAUDE.md` covers security and privacy guidelines that apply to all changes
in this repo — read it before contributing. `~/.claude/rules/supply-chain-security.md`
covers dependency-vetting policy.

## Deploy

For a new client:

```
scripts/build-tarball.sh <codename>     # produces phish-triage-vX.Y.Z-<codename>.tar.gz
```

Then follow `docs/internal/desktop-skill-deploy.md` for the per-client steps
(API key handoff, 1Password vault structure, hand-off package).
