# Phish Triage MCP Server

An MCP server providing email phishing analysis and enrichment tools.

## Build & Run

```
uv sync                              # install dependencies (from lockfile)
uv run python -m phish_triage.server # run MCP server (stdio mode)
uv run pytest                        # run tests
uv run pip-audit                     # check for known vulnerabilities
```

## Project-Specific Dependency Vetting

Use the vet_packages.py tool to check everything prior to installing. Do not proceed if you cannot use the tool. 


Global supply chain security rules are enforced via `~/.claude/rules/supply-chain-security.md`. See that file for the full policy and rationale.

## Architecture

- `src/phish_triage/server.py` — FastMCP server, tool registrations
- `src/phish_triage/tools/` — one module per enrichment tool (DNS, WHOIS, URLScan, etc.)
- `src/phish_triage/utils/` — email parsing, rate limiting
- `tests/fixtures/` — sample .eml files for testing

Claude (via Claude Desktop or Claude Code) is the orchestrator. It receives a suspicious email, decides which tools to call, and synthesizes the results. The tools just return data — Claude does the analysis.

## Key Conventions

- All dependencies pinned to exact versions. Lockfile (`uv.lock`) committed.
- All external API calls mocked in tests. Never hit real APIs in CI.
- Every tool function catches all exceptions and returns structured error JSON.
- API keys loaded via environment variables. Never log or include keys in responses.
- URLs submitted to URLScan.io default to "unlisted" visibility (client privacy).

## Testing

```
uv run pytest                         # full suite
uv run pytest tests/test_dns.py       # single module
uv run pytest -x                      # stop on first failure
```
