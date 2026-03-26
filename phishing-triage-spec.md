# Phishing Email Triage MCP Server — Claude Code Spec

## Overview

Build an MCP server that provides email phishing analysis tools. Claude (via Claude Desktop or Claude Code) acts as the orchestrator — it receives a suspicious email from a user, calls these tools to gather technical intelligence, and synthesizes the results into a risk assessment.

The server exposes individual enrichment tools (DNS lookup, WHOIS, URL scanning, etc.) that Claude calls as needed. Claude decides which tools to invoke based on what it finds in the email.

## Language & Framework

**Python 3.11+** with **FastMCP** (from the `mcp` package).

Rationale: Python has the best library ecosystem for DNS, WHOIS, and email header parsing. FastMCP provides decorator-based tool definitions — minimal boilerplate. The `mcp` package on PyPI (currently v1.26.x) includes FastMCP.

## Project Structure

```
phish-triage-mcp/
├── pyproject.toml          # Project config, dependencies (use uv for package management)
├── uv.lock                 # LOCKED dependency versions with SHA256 hashes — COMMIT THIS
├── Dockerfile              # Containerized development and deployment
├── docker-compose.yml      # Local dev with container isolation
├── README.md               # Setup instructions for developers and testers
├── .env.example            # Template for API keys (NEVER commit actual .env)
├── .claude/
│   └── settings.json       # Project-level Claude Code deny rules
├── CLAUDE.md               # Project-level Claude Code instructions (build, test, architecture)
├── scripts/
│   └── vet_package.py      # Pre-install package vetting (zero deps, runs before install)
├── dist/
│   └── claude-rules/
│       └── supply-chain-security.md  # Global security rule — distribute to clients
├── src/
│   └── phish_triage/
│       ├── __init__.py
│       ├── server.py       # FastMCP server definition + tool registrations
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── dns_lookup.py
│       │   ├── whois_lookup.py
│       │   ├── header_parser.py
│       │   ├── url_scanner.py       # URLScan.io integration
│       │   ├── reputation.py        # VirusTotal + Google Safe Browsing
│       │   └── abuse_ip.py          # AbuseIPDB
│       └── utils/
│           ├── __init__.py
│           ├── email_parser.py      # Extract URLs, domains, IPs from raw email
│           └── rate_limiter.py      # Simple rate limiting for external API calls
└── tests/
    ├── test_dns.py
    ├── test_header_parser.py
    ├── test_url_scanner.py
    └── fixtures/
        ├── phishing_email_1.eml     # Test fixture: obvious phish
        ├── phishing_email_2.eml     # Test fixture: sophisticated spearphish
        └── legitimate_email.eml     # Test fixture: clean email
```

## Dependencies

**CRITICAL: All dependencies must be pinned to exact versions.** No `>=` ranges. Use `uv lock` to generate a lockfile with SHA256 hashes for every package (including transitive dependencies). This is non-negotiable given the current supply chain threat landscape — see the Security section below.

```toml
[project]
name = "phish-triage-mcp"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "mcp==1.26.0",             # MCP SDK including FastMCP — pin exact
    "dnspython==2.7.0",        # DNS resolution
    "python-whois==0.9.5",     # WHOIS lookups (small package — candidate for vendoring)
    "httpx==0.28.1",           # Async HTTP client for API calls
    "python-dotenv==1.0.1",    # Environment variable management
]

[project.optional-dependencies]
dev = [
    "pytest==8.3.4",
    "pytest-asyncio==0.24.0",
    "pip-audit==2.7.3",        # Vulnerability scanning for dependencies
    "pipdeptree==2.24.0",      # Dependency tree inspection
]
```

**After initial setup, immediately run:**
1. `uv lock` — generates `uv.lock` with hashes. Commit this file.
2. `uv tree` — inspect the full transitive dependency tree. Review what you're pulling in.
3. `pip-audit` — check for known vulnerabilities in all dependencies.

**Before any dependency upgrade:**
1. Check that the new version has a corresponding tag/release on the package's GitHub repo (the LiteLLM attack had no matching GitHub release).
2. Review the changelog and diff between versions.
3. Run `pip-audit` after upgrading.
4. Re-run all tests.

## Tool Definitions

Each tool should be a standalone async function decorated with `@mcp.tool()`. Keep tool descriptions precise — Claude reads these to decide when to use each tool. All tools must handle errors gracefully and return structured, parseable results. Never let an exception bubble up and crash the server.

### Tool 1: `parse_email_headers`

**Purpose:** Parse raw email headers into structured data. This is typically the first tool Claude should call.

**Input:**
- `raw_headers` (str): Raw email headers (from Gmail's "Show original")

**Output:** JSON object containing:
- `from_address`: Parsed sender email
- `from_display_name`: Display name
- `reply_to`: Reply-To address (if different from From)
- `return_path`: Return-Path header
- `received_hops`: List of relay servers the email passed through, with timestamps
- `authentication_results`: Parsed Authentication-Results header (SPF, DKIM, DMARC verdicts)
- `message_id`: Message-ID header
- `x_headers`: Any X- prefixed headers that may indicate spam scoring

**Implementation notes:**
- Use Python's built-in `email` module (`email.parser.HeaderParser`) for parsing
- SPF/DKIM/DMARC results are in the `Authentication-Results` header — parse this carefully, format varies by provider
- For Gmail-originated emails, also check `ARC-Authentication-Results`
- Extract the originating IP from the earliest `Received` header

### Tool 2: `dns_lookup`

**Purpose:** Query DNS records for a domain to check mail authentication configuration and legitimacy.

**Input:**
- `domain` (str): Domain to query
- `record_types` (list[str], optional): Which record types to query. Default: `["MX", "TXT", "A", "NS"]`

**Output:** JSON object containing:
- `mx_records`: MX records with priorities
- `spf_record`: SPF TXT record (parsed from TXT records, starts with `v=spf1`)
- `dmarc_record`: DMARC record (query `_dmarc.{domain}`)
- `dkim_selector_hints`: Note that DKIM requires a selector — if we have one from the email headers, query it. Otherwise note that DKIM DNS verification requires the selector from the email headers.
- `a_records`: A records (IP addresses)
- `ns_records`: Nameservers
- `has_mail_config`: Boolean — does this domain have MX records and SPF/DMARC configured?

**Implementation notes:**
- Use `dnspython` (`dns.resolver`)
- Always query `_dmarc.{domain}` as a TXT record for DMARC policy
- If we have a DKIM selector (from parsed headers), query `{selector}._domainkey.{domain}`
- Handle `NXDOMAIN` and `NoAnswer` gracefully — these are informative results, not errors
- Set reasonable timeouts (5s per query)

### Tool 3: `whois_lookup`

**Purpose:** Get domain registration information to assess domain age and legitimacy.

**Input:**
- `domain` (str): Domain to query

**Output:** JSON object containing:
- `registrar`: Registrar name
- `creation_date`: When the domain was registered
- `expiration_date`: When registration expires
- `updated_date`: Last update
- `domain_age_days`: Calculated age in days
- `registrant_country`: Country code if available
- `privacy_protected`: Boolean — is WHOIS privacy enabled?
- `name_servers`: Nameservers from WHOIS (can cross-reference with DNS)

**Implementation notes:**
- Use `python-whois`
- Domain age is a strong signal: domains less than 30 days old used in email are very suspicious
- WHOIS privacy itself is not suspicious (it's common), but combined with a very new domain it's a flag
- Handle rate limiting — some WHOIS servers will block rapid queries. Add a small delay between calls.

### Tool 4: `scan_url`

**Purpose:** Submit a URL to URLScan.io for analysis. Returns scan results including redirects, final destination, page content, and contacted domains.

**Input:**
- `url` (str): URL to scan
- `visibility` (str, optional): "public" or "unlisted". Default: "unlisted"

**Output:** JSON object containing:
- `scan_id`: URLScan.io scan ID
- `scan_url`: Link to full results on URLScan.io
- `effective_url`: Final URL after redirects
- `redirect_chain`: List of URLs in the redirect chain
- `page_domain`: Domain of the final page
- `page_title`: HTML title of the final page
- `server`: Server header
- `contacted_domains`: List of domains the page contacted (scripts, resources)
- `is_malicious`: URLScan.io's verdict if available
- `screenshot_url`: URL to the page screenshot on URLScan.io
- `categories`: Any categorization tags

**Implementation notes:**
- URLScan.io API: POST to `https://urlscan.io/api/v1/scan/` with `{"url": url, "visibility": visibility}`
- Scanning is async — the POST returns a scan UUID, then poll `https://urlscan.io/api/v1/result/{uuid}/` until complete
- Implement polling with backoff: wait 5s, then 10s, then 15s, up to 60s total. URLScan typically takes 10-20s.
- Free tier: 100 scans/day, 1000 searches/day — implement rate limiting
- Requires API key (free registration at urlscan.io)
- If the URL looks like a credential harvesting page (login form on a non-standard domain), flag it explicitly

### Tool 5: `check_reputation`

**Purpose:** Check URL/domain/IP reputation against VirusTotal and Google Safe Browsing.

**Input:**
- `indicator` (str): URL, domain, or IP to check
- `indicator_type` (str): One of "url", "domain", "ip"

**Output:** JSON object containing:
- `virustotal`: Object with:
  - `detection_ratio`: e.g., "3/89" (3 engines flagged it out of 89)
  - `detections`: List of engines that flagged it and their categories
  - `community_score`: Community reputation score
  - `categories`: How VT categorizes this resource
  - `last_analysis_date`: When it was last scanned
- `safe_browsing`: Object with:
  - `is_unsafe`: Boolean
  - `threat_types`: List of threat types if flagged (MALWARE, SOCIAL_ENGINEERING, etc.)

**Implementation notes:**
- VirusTotal API v3: 
  - URL: POST to `https://www.virustotal.com/api/v3/urls` with the URL, then GET the analysis
  - Domain: GET `https://www.virustotal.com/api/v3/domains/{domain}`
  - IP: GET `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
  - Free tier: 4 requests/minute, 500 requests/day — rate limiting is critical
  - Requires API key
- Google Safe Browsing API v4:
  - POST to `https://safebrowsing.googleapis.com/v4/threatMatches:find`
  - Free for up to 10,000 requests/day
  - Requires API key (from Google Cloud Console)
- If VirusTotal rate limit is hit, return a clear message saying so rather than failing silently

### Tool 6: `check_abuse_ip`

**Purpose:** Check IP address reputation via AbuseIPDB.

**Input:**
- `ip_address` (str): IP to check
- `max_age_in_days` (int, optional): How far back to check reports. Default: 90

**Output:** JSON object containing:
- `abuse_confidence_score`: 0-100 score (higher = more likely abusive)
- `total_reports`: Number of abuse reports
- `last_reported_at`: Most recent report date
- `isp`: ISP name
- `country_code`: Country
- `usage_type`: e.g., "Data Center/Web Hosting/Transit"
- `domain`: Reverse DNS domain
- `is_tor`: Boolean — is this a known Tor exit node?
- `categories`: Types of abuse reported (spam, brute force, etc.)

**Implementation notes:**
- AbuseIPDB API: GET `https://api.abuseipdb.com/api/v2/check` with `ipAddress` and `maxAgeInDays` params
- Free tier: 1000 checks/day
- Requires API key
- "Data Center/Web Hosting" usage type for a mail sender is mildly suspicious — legitimate orgs usually send from dedicated mail infrastructure

### Tool 7: `extract_email_indicators`

**Purpose:** Utility tool that extracts all actionable indicators from a raw email for further analysis. Saves Claude from having to regex out URLs and domains itself.

**Input:**
- `raw_email` (str): Full raw email content (headers + body) OR just the body

**Output:** JSON object containing:
- `urls`: List of all URLs found in the body (both href and display text)
- `url_mismatches`: Cases where display text shows a different URL than the href
- `domains`: Unique domains referenced in URLs
- `sender_domain`: Domain from the From address
- `ip_addresses`: Any IP addresses found in headers or body
- `attachments`: List of attachment filenames and MIME types (from headers)
- `has_html`: Boolean — does the email have an HTML part?
- `has_tracking_pixels`: Boolean — are there 1x1 images or hidden images?

**Implementation notes:**
- Use Python's `email` module to parse MIME structure
- Extract URLs from both plain text and HTML parts
- For HTML parts, use `html.parser` or a simple regex to find `href` attributes — compare href value to display text for mismatches
- Check for common tracking pixel patterns (1x1 image, hidden image, images from known tracking domains)

## Transport Configuration

The server should support both STDIO (for local dev with Claude Desktop) and Streamable HTTP (for remote/hosted deployment). Use FastMCP's built-in transport support:

```python
# server.py
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "Phishing Triage",
    description="Email phishing analysis and enrichment tools"
)

# ... register tools ...

if __name__ == "__main__":
    import sys
    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if transport == "http":
        mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)
    else:
        mcp.run()  # default: stdio
```

This allows:
- `python -m phish_triage.server` → STDIO mode for Claude Desktop
- `python -m phish_triage.server http` → HTTP mode for remote access

## Claude Desktop Integration (Local Testing)

For local testing, users add this to their `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "phish-triage": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/phish-triage-mcp", "python", "-m", "phish_triage.server"],
      "env": {
        "URLSCAN_API_KEY": "your-key-here",
        "VIRUSTOTAL_API_KEY": "your-key-here",
        "GOOGLE_SAFE_BROWSING_API_KEY": "your-key-here",
        "ABUSEIPDB_API_KEY": "your-key-here"
      }
    }
  }
}
```

## Environment Variables

All API keys loaded via `python-dotenv`. The server should check for required keys at startup and log clear warnings if any are missing (but still start — tools with missing keys should return a helpful error when called, not crash the server).

```
URLSCAN_API_KEY=          # Required for scan_url tool
VIRUSTOTAL_API_KEY=       # Required for check_reputation tool
GOOGLE_SAFE_BROWSING_API_KEY=  # Required for check_reputation tool (Safe Browsing)
ABUSEIPDB_API_KEY=        # Required for check_abuse_ip tool
```

## Error Handling Requirements

- **Every tool must catch all exceptions** and return a structured error response rather than throwing. Example: `{"error": "WHOIS lookup failed", "detail": "Connection timed out", "domain": "example.com"}`
- **Timeouts:** All external API calls should have a 15-second timeout. DNS queries should have a 5-second timeout.
- **Rate limiting:** Implement a simple in-memory rate limiter (token bucket or sliding window) for each external API. If a rate limit is hit, return a message like `{"error": "rate_limit", "detail": "VirusTotal free tier limit: 4 requests/minute. Try again in ~30 seconds.", "indicator": "..."}`
- **Missing API keys:** If a tool is called but its required API key is not configured, return `{"error": "not_configured", "detail": "VIRUSTOTAL_API_KEY environment variable is not set. This tool requires a free API key from virustotal.com."}`

## Testing

Include test fixtures with sample `.eml` files:

1. **Obvious phishing:** Misspelled domain, urgency language, link to credential harvester
2. **Sophisticated spearphishing:** Correct domain appearance, plausible context, but reply-to mismatch and suspicious link
3. **Legitimate email:** Clean authentication, known domain, no suspicious indicators

Tests should cover:
- Header parsing (especially Authentication-Results parsing, which varies by provider)
- DNS lookup handling of NXDOMAIN and missing records
- URL extraction from both plain text and HTML email bodies
- URL mismatch detection
- Graceful handling of API timeouts and missing keys
- Rate limiter behavior

Use `pytest-asyncio` for async tool tests. Mock external API calls in tests — don't hit real APIs in CI.

## Security Considerations (Application)

- **No email content is stored.** Everything is processed in memory and discarded.
- **API keys are never logged or included in tool responses.**
- **URLs submitted to URLScan.io default to "unlisted" visibility** so they don't appear in public search results. This matters because the email content may reveal information about the client.
- **Rate limiting protects against accidental API key exhaustion.**
- **Input validation:** Validate domains, IPs, and URLs before sending to external services. Don't blindly pass user input to API calls.

---

## Supply Chain Security & Development Environment

### Context: Why This Matters Right Now

On March 24, 2026, the LiteLLM Python package (97M monthly downloads) was compromised via a poisoned Trivy GitHub Action in its CI/CD pipeline. The attacker used a stolen PyPI publishing token to upload malicious versions that exfiltrated SSH keys, cloud credentials, Kubernetes configs, database passwords, and more — triggered on `pip install` with no user interaction. The attack was discovered by accident (a bug in the malware caused a crash). A developer running an MCP plugin inside Cursor was hit as a transitive dependency — they never installed LiteLLM directly.

We are a cybersecurity consultancy building a security tool. Getting compromised by a supply chain attack while building phishing detection tooling would be catastrophic for client trust. Treat this section as mandatory, not aspirational.

### Dependency Management Rules

1. **Pin every dependency to exact versions.** No version ranges. Ever. The `uv.lock` lockfile with SHA256 hashes is the authoritative record of what we run.

2. **Audit the dependency tree before starting.** Run `uv tree` and review every transitive dependency. Our 5 direct deps will pull in ~15-25 transitive deps. Know what they are.

3. **Verify new packages before adding.** Before adding any dependency:
   - Check the package's GitHub repo: is it actively maintained? Who are the maintainers?
   - Check download stats and community trust signals
   - Inspect the transitive dependency tree it would add
   - Prefer packages with few or zero dependencies of their own

4. **Treat every version upgrade as a code review.** Before bumping a version:
   - Confirm the new version has a corresponding GitHub tag/release (the LiteLLM malicious versions had no GitHub release)
   - Read the changelog
   - Run `pip-audit` after upgrading
   - Re-run full test suite

5. **Consider vendoring small dependencies.** `python-whois` is a small package (~500 lines of core logic). Vendoring it (copying the source into our repo) eliminates one supply chain link. Evaluate this for any dependency under ~1000 LoC where we only use core functionality.

6. **Use Datadog's Supply Chain Firewall (SCFW).** It's open source, wraps `pip install`, and blocks known-malicious packages automatically. Low friction, high value. Install it on all development machines: https://github.com/DataDog/supply-chain-firewall

### Pre-Install Vetting (MANDATORY)

The tools above (`pip-audit`, `safety`) run *after* installation — but Python and npm can both execute arbitrary code *during* install (via `setup.py`, `.pth` files, pre/post-install scripts). By the time those tools run, malicious code has already executed. We need a gate *before* download.

**Custom vetting script: `scripts/vet_package.py`**

Include in this repo. A zero-dependency Python script that queries PyPI and npm registry APIs (no code is downloaded or executed) and checks:

- **Version age**: Rejects versions published less than 7 days ago. The LiteLLM malicious versions were live for ~3 hours. A 7-day quarantine window would have caught them.
- **GitHub tag verification**: Checks whether the version has a corresponding release tag on the package's GitHub repo. The LiteLLM attack published directly to PyPI with no GitHub release — this check catches that exact pattern.
- **Known vulnerabilities**: Queries the OSV.dev database by package name and version via API, before any code is downloaded.
- **Install scripts (npm)**: Flags packages with `preinstall`/`postinstall` hooks that execute arbitrary code on `npm install`.
- **Package metadata**: Flags missing maintainers, very new packages, yanked/deprecated versions, single-maintainer risk.

Usage:
```bash
# Vet a single package (auto-detects PyPI vs npm)
python scripts/vet_package.py mcp==1.26.0

# Vet an npm package
python scripts/vet_package.py express@4.18.2 --ecosystem npm

# Vet all dependencies in a requirements file
python scripts/vet_package.py -r requirements.txt

# Vet all dependencies in package.json
python scripts/vet_package.py -r package.json
```

Exit codes: 0=PASS, 1=WARN, 2=FAIL, 3=ERROR. CI can gate on this.

**Enforcement via Claude Code rules (modular, distributable):**

Package vetting is enforced via two layers:

1. **Global security rule** (`~/.claude/rules/supply-chain-security.md`): A standalone, self-contained policy document that enforces pre-install vetting across all projects on the machine. This file:
   - Explains the threat landscape and why the rules exist (references LiteLLM, npm attacks)
   - Defines 7 mandatory rules covering vetting, pinning, install scripts, credential access
   - Includes manual fallback procedures for when `vet_package.py` isn't available
   - Contains administrator deployment instructions (per-machine and managed/non-overridable paths)
   - Is written to be distributed to clients as a Wavefront security deliverable

   Install: `cp dist/claude-rules/supply-chain-security.md ~/.claude/rules/`

2. **Project-level CLAUDE.md** (`./CLAUDE.md`): Contains only project-specific instructions — build commands, architecture overview, test commands, key conventions. References the global rule for security policy rather than duplicating it.

The global rule is the distributable security control. Give it to clients along with `vet_package.py` and they have a complete pre-install gate for any project using Claude Code. It works with or without the vetting script (includes manual API-query fallbacks).

**Additional tools for defense in depth:**

For PyPI:
- `uv pip compile --exclude-newer "7d"` — tells `uv` to ignore any package version published in the last 7 days during dependency resolution. This is the simplest, most effective single control.
- **Datadog SCFW** (see above) — wraps `pip install`, blocks known-malicious packages at install time.
- **pipask** (`pip install pipask`) — interactive pre-install checker that queries PyPI metadata APIs. Good for evaluating packages you're considering adding.

For npm:
- **Socket Firewall** (`npm i -g sfw`) — wraps npm/yarn/pnpm, performs deep analysis including malicious code detection, install script risks, and obfuscated code detection. Also supports pip. The single best npm pre-install tool available.
- **npq** (`npm i -g npq`) — pre-install auditor that checks vulnerability databases, package age, typosquatting risk, registry signatures, and install scripts. Can be aliased to replace `npm install`.
- **pnpm `minimumReleaseAge`** — if using pnpm, this config option enforces a minimum age for all packages including transitive dependencies.

**Recommended layered setup for this project:**

1. `vet_package.py` run manually or via CLAUDE.md before adding any new dependency
2. `uv pip compile --exclude-newer "7d"` for all dependency resolution
3. SCFW or Socket Firewall wrapping the package manager
4. `uv lock` with SHA256 hashes — only install what's been vetted
5. `pip-audit` in CI as a post-install safety net

### Development Machine Hygiene

This machine is currently clean — no user tokens or secrets beyond what's needed. It is connected to Wavefront's Google Workspace and other systems. Protect that access surface.

1. **Never store API keys in environment variables or `.env` files on the host.** The LiteLLM malware specifically harvested `.env` files and environment variables. Options:
   - Use a secrets manager (1Password CLI, `op run` is low-friction)
   - Pass API keys via Claude Desktop's config `env` block (which limits exposure to the MCP server process)
   - At minimum, store `.env` files outside the project directory and outside the home directory if possible

2. **Develop inside a container.** Use Docker or a devcontainer for all build and test activity. This limits blast radius if any dependency is compromised — the container doesn't have access to your Google Workspace session, browser cookies, SSH keys, or other system credentials. A minimal Dockerfile is included below.

3. **Keep the development machine minimal.** Don't install unnecessary packages globally. Don't leave credentials cached that aren't actively needed. Audit what's on the machine periodically.

4. **Separate build and runtime.** In CI, build the package in an isolated environment, produce a locked wheel, and deploy only the artifact. The CI runner should have no access to production secrets beyond what's needed for the build.


**2. Enable sandboxing immediately.**

Run `/sandbox` in Claude Code to enable OS-level filesystem and network isolation. On macOS this uses Seatbelt; on Linux it uses bubblewrap (`bwrap`). This restricts Claude Code's bash tool to only write within the project directory and only access approved network domains.

Sandboxing provides two critical protections:
- **Filesystem isolation:** Claude Code can read system files but can only write within the working directory. Even if a prompt injection tricks Claude into running malicious commands, it cannot modify files outside the project.
- **Network isolation:** All network access goes through a proxy. New domains trigger permission prompts. A compromised dependency cannot silently exfiltrate data to an unapproved host.

**3. Configure deny rules in settings.**

Create or update `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "bash:cat ~/.ssh/*",
      "bash:cat .env*",
      "bash:cat *credentials*",
      "bash:cat *secret*",
      "bash:cat **/tokens.json",
      "bash:cat ~/.config/gcloud/*",
      "bash:cat ~/.aws/*",
      "bash:cat ~/.kube/*",
      "bash:curl *",
      "bash:wget *",
      "edit:.env",
      "edit:.env.local",
      "edit:**/credentials.json",
      "edit:**/tokens.json"
    ]
  }
}
```

These rules block Claude Code from reading sensitive credential files or making arbitrary network requests via bash, even if a prompt injection attempts it. Deny rules always take priority over allow rules.

**4. Use Normal mode, not Bypass.**

Stay in Normal mode (the default). Review permission prompts. Yes, it's slower. For a security tool connected to systems with access to client data, approval fatigue is preferable to an unreviewed command exfiltrating your Google Workspace session token.

If you need faster iteration for well-understood tasks, use Accept Edits mode (auto-approves file edits but still prompts for shell commands).

**Never use Bypass mode** on this project. It removes all permission checks. On a machine connected to Wavefront infrastructure, this is unacceptable risk.

**5. Review CLAUDE.md files.**

If you pull in any submodules, external repos, or reference projects, check their `.claude/` directories and any `CLAUDE.md` files. These can contain instructions that influence Claude Code's behavior and are a prompt injection vector.

**6. Keep Claude Code updated.**

Version 2.3 (January 2026) fixed a sandbox bypass vulnerability. Run the latest version. Check for updates regularly.

### Containerized Development Setup

Add this `Dockerfile` to the project root:

```dockerfile
FROM python:3.11-slim

# Don't run as root
RUN useradd --create-home appuser

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /home/appuser/app

# Copy dependency files first (layer caching)
COPY pyproject.toml uv.lock ./

# Install dependencies with locked versions
RUN uv sync --frozen

# Copy application code
COPY src/ ./src/
COPY tests/ ./tests/

# Switch to non-root user
USER appuser

# Default: run MCP server in stdio mode
CMD ["uv", "run", "python", "-m", "phish_triage.server"]
```

And a `docker-compose.yml` for development:

```yaml
services:
  phish-triage:
    build: .
    env_file:
      - .env  # API keys — this file stays OUTSIDE the image
    volumes:
      - ./src:/home/appuser/app/src  # Live code reload
      - ./tests:/home/appuser/app/tests
    # No access to host filesystem beyond the mounted volumes
    # No access to host network services (Google Workspace, etc.)
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
```

Key properties:
- Runs as non-root user
- Read-only filesystem (except /tmp)
- No privilege escalation
- Only the project code and `.env` file are accessible — no host SSH keys, no browser cookies, no Google Workspace tokens
- If a dependency is compromised, the attacker gets: the API keys in `.env` (rotate-able) and whatever is in the container (nothing of value beyond the project)

### Secret Rotation Plan

If you suspect any compromise:

1. **Immediately rotate all API keys** (URLScan.io, VirusTotal, Google Safe Browsing, AbuseIPDB)
2. **Check Google Workspace audit logs** for unauthorized access
3. **Review the machine's outbound network connections** during the suspected window
4. **Check for persistence mechanisms:** Look for unexpected files in `~/.config/`, unexpected systemd services, unexpected cron jobs
5. **Notify David and Francesca** — as a security consultancy, a compromise affects client trust even if no client data was accessed

---

## Future Enhancements (Out of Scope for v1)

- DKIM signature verification (requires the actual email, not just headers)
- Attachment sandboxing (would need a sandbox service like Joe Sandbox or Any.Run)
- Integration with threat intelligence feeds (AlienVault OTX, Abuse.ch)
- Per-client domain allowlists (known-good sender domains)
- Web app frontend for client-facing deployment
- Persistent audit logging of analyses performed

