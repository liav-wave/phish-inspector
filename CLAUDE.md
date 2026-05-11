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
- `src/phish_triage/utils/` — email parsing, rate limiting, input validation, error sanitization
- `tests/fixtures/` — sample .eml files for testing

Claude (via Claude Desktop or Claude Code) is the orchestrator. It receives a suspicious email, decides which tools to call, and synthesizes the results. The tools just return data — Claude does the analysis.

## Security & Privacy Guidelines

These rules apply to all development on this project. Email content processed by this tool belongs to Wavefront's nonprofit clients and must be treated as confidential.

### Email content must never be persisted or leaked

- **No logging of email content.** Tools must never log email bodies, headers, addresses, or any PII from emails being analyzed. Structured result dicts are fine; raw input is not.
- **No email content in error messages.** Exception handlers must use `sanitize_error()` from `utils/errors.py` — never `str(e)` directly, which may embed request bodies or headers.
- **No email content in git.** Never commit real emails containing actual PII. Test fixtures must be fully synthetic or sanitized (see Test Data below).
- **No email content in analytics, metrics, or telemetry.** If observability is added in the future, it must only track tool names, latency, and error codes — never input data.

### Error messages must always be sanitized

Error sanitization has two layers (both in `src/phish_triage/utils/errors.py`):

1. **`@sanitize_tool` decorator** — applied to every tool in `server.py`. This is the safety net: any unhandled exception is caught and its message is scrubbed of API keys, auth headers, and URL query parameters before being returned as a structured error dict. New tools get this automatically when decorated.

2. **`sanitize_error(e)`** — used explicitly in per-tool try/except blocks for known error paths. This is defense-in-depth; even if removed, the decorator catches the exception.

When adding a new tool to `server.py`, stack the decorators: `@mcp.tool()` then `@sanitize_tool` on the next line. The per-tool `sanitize_error()` calls in individual tool modules are optional but recommended for clear error categorization.

### API keys must be protected

- API keys are loaded from environment variables, never hardcoded.
- For the active stdio deployment, keys come from the client's `.env` file (mode `0600`) or, in the steady-state 1Password-backed launcher (`scripts/launch-mcp.sh`), from a `Wavefront-Clients` vault via `op run` — never written to disk in the latter.
- For the legacy Cloud Run path (`wip/cloud-run/`), keys come from Secret Manager via `--set-secrets` — never `--set-env-vars`.
- The Google Safe Browsing API key is passed via `x-goog-api-key` header, not as a URL query parameter.
- Error messages are sanitized to prevent key leakage (see above).
- `.env` is in `.gitignore`. Only `.env.example` (with empty values) is committed.

### Third-party data disclosure

When this tool analyzes an email, it sends specific indicators to external services:

| Service | What is sent | Visibility |
|---|---|---|
| URLScan.io | URLs extracted from the email | "unlisted" (accessible only by scan UUID) |
| VirusTotal | URLs, domains, or IPs | Queryable by other VT users |
| Google Safe Browsing | URLs/domains | Sent to Google API |
| AbuseIPDB | IP addresses | Queried against abuse database |
| Public WHOIS servers | Domain names | Public protocol |
| Public DNS | Domain names | Standard DNS queries |

No raw email content, headers, or bodies are sent to any third-party service. Only extracted indicators (URLs, domains, IPs) are transmitted. However, if a phishing URL contains a unique tracking token, the attacker may observe the scan in their logs.

### Async code must not block the event loop

- All blocking I/O (DNS queries, WHOIS socket lookups) must be wrapped in `asyncio.to_thread()`.
- `dns_lookup.py` uses `_aquery()` (async wrapper around blocking `dnspython`).
- `whois_lookup.py` uses `asyncio.wait_for(asyncio.to_thread(...), timeout=15.0)`.
- Never add synchronous network calls in an `async def` function without wrapping them.
- HTTP calls use `httpx.AsyncClient` which is natively async.

### Tool response size limits

Tool responses should be bounded to avoid large payloads that might be cached or logged by MCP transport layers:

- Redirect chains: cap at 5 entries (`url_scanner.py`)
- Contacted domains: cap at 20 entries (`url_scanner.py`)
- VT detections: cap at 10 entries (`reputation.py`)
- Error detail strings: truncate API responses at 200 chars

When adding new tools or modifying existing ones, apply similar caps to any list or text field that could grow unboundedly.

### Input validation

- URL and IP validation uses `utils/validators.py` which is built on Python's `ipaddress` module — it correctly handles hex IPs, decimal IPs, IPv4-mapped IPv6, shorthand notation, and all reserved ranges.
- Never use regex-based IP validation for security decisions. The `ipaddress` module exists for this reason.
- All tools that accept URLs validate the scheme (`http://` or `https://` only) and reject private/loopback/reserved addresses.

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

## Test Data Hygiene

- **Never use real employee names or email addresses** in test fixtures. Use obviously synthetic identifiers (`analyst@example.com`, `Jane Doe`, `Bob Smith`).
- **Never commit real phishing emails containing actual victim PII.** If you need realistic test data, sanitize all identifying information first: replace real addresses, names, IPs, and domains with synthetic equivalents.
- The `tests/fixtures/` directory contains fully synthetic `.eml` files. The `spamspamspam/` directory contains real-world spam samples for manual testing — these must not contain PII beyond the spam sender's own addresses.
- Test fixtures should cover the analysis pipeline (header parsing, indicator extraction, enrichment mocking) without requiring real sensitive data.

## Incident Response: API Key Compromise

If an API key is suspected compromised:

1. **Rotate at the provider.** Generate a new key at the provider (URLScan.io, VirusTotal, Google Cloud Console, AbuseIPDB).
2. **Update each client deployment** with the new key:
   - **`.env` clients (first-deploy form-factor):** push a fresh `.env` to the client over a secure channel (1Password share or similar). They replace the existing `.env` and restart Claude Desktop. Confirm `.env` lands with mode `0600`.
   - **1Password-backed clients (`launch-mcp.sh`):** update the relevant item under `Wavefront-Clients/<CODENAME>_<KEY_NAME>` and ask the client to restart Claude Desktop so the next `op run` picks up the new value.
3. **Revoke the old key** at the provider after confirming the new key is working in at least one client.
4. **Check provider-side dashboards** (URLScan, VT, GSB, AbuseIPDB) for unusual query volume or query origins prior to rotation — that's the only audit trail available for the desktop deployment.
5. **Notify the client** if the compromise may have exposed indicators submitted from their email triage to unauthorized parties.

For the legacy Cloud Run path, the rotation procedure (Secret Manager versions + `gcloud logging read`) is documented in `wip/cloud-run/deploy-runbook.md`.

## Deployment

The active per-client deployment is a local-stdio MCP server launched by Claude
Desktop from a tarball extracted on the client laptop. End-to-end procedure:

- Client-facing user guide: `docs/phish-triage-guide.md`
- Internal operator runbook: `docs/internal/desktop-skill-deploy.md`
- Build a client tarball from the current HEAD: `scripts/build-tarball.sh <codename>`

The legacy Cloud Run / hosted-variant deployment is preserved in `wip/cloud-run/`
but is not in active use. Read `wip/cloud-run/SECURITY-DEBT.md` before
resurrecting it for any client.
