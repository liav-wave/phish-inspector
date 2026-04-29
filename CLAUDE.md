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
- In production (Cloud Run), keys come from Secret Manager via `--set-secrets` — never `--set-env-vars`.
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

1. **Rotate immediately.** Generate a new key at the provider (URLScan.io, VirusTotal, Google Cloud Console, AbuseIPDB) and update Secret Manager:
   ```bash
   echo -n "NEW_KEY" | gcloud secrets versions add <secret-name> --data-file=-
   ```
2. **Redeploy** to pick up the new secret version: `./scripts/deploy.sh`
3. **Audit access logs.** Check Secret Manager access logs for unauthorized reads:
   ```bash
   gcloud logging read 'resource.type="audited_resource" AND protoPayload.serviceName="secretmanager.googleapis.com"' --limit=50
   ```
4. **Check Cloud Run logs** for unusual tool invocation patterns (high volume, unusual IPs/domains being scanned).
5. **Revoke the old key** at the provider after confirming the new key is working.
6. **Notify the team** if the compromise may have exposed client email indicators to unauthorized parties.

## Deployment (Cloud Run)

Prerequisites: `gcloud` CLI authenticated, a GCP project with Cloud Run and Secret Manager enabled.

```bash
export GCP_PROJECT_ID=your-project-id

# One-time: create secrets in Secret Manager (paste each key when prompted)
echo -n "YOUR_KEY" | gcloud secrets create urlscan-api-key --data-file=-
echo -n "YOUR_KEY" | gcloud secrets create virustotal-api-key --data-file=-
echo -n "YOUR_KEY" | gcloud secrets create google-safe-browsing-api-key --data-file=-
echo -n "YOUR_KEY" | gcloud secrets create abuseipdb-api-key --data-file=-

# Deploy (uses --set-secrets to inject keys from Secret Manager)
./scripts/deploy.sh

# Grant a user access
gcloud run services add-iam-policy-binding phish-triage \
  --region=us-central1 \
  --member='user:someone@yourco.com' \
  --role='roles/run.invoker'
```

Staff connect via Claude Desktop/Code MCP config:
```json
{
  "mcpServers": {
    "phish-triage": {
      "type": "streamable-http",
      "url": "https://phish-triage-HASH-uc.a.run.app/mcp",
      "headers": {
        "Authorization": "Bearer $(gcloud auth print-identity-token)"
      }
    }
  }
}
```

Local Docker test: `docker build -t phish-triage . && docker run -p 8080:8080 phish-triage`
