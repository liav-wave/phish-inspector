# Phish Triage — User Guide

A Claude-driven assistant for analyzing suspicious emails. You paste an email, Claude runs it through ~7 enrichment checks (DNS, WHOIS, URL scanning, IP reputation, etc.) and returns a verdict with reasoning.

This guide covers: install, day-to-day use, what data is sent where, and how to read the output.

---

## Install

You'll need:

- Claude Desktop installed (any recent version)
- macOS (Apple Silicon or Intel)
- The phish-triage tarball (`phish-triage-v<X.Y.Z>-griffon.tar.gz`) — sent separately by Wavefront
- Three API keys (URLScan, AbuseIPDB, Google Safe Browsing) — sent separately by Wavefront over a secure channel

### Steps
1. **Install uv** (the Python package manager phish-triage uses) via the official installer:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
   If your security policy disallows curl-pipe-shell, download the signed `.pkg` from https://github.com/astral-sh/uv/releases and verify the Apple notarization signature before running.

2. **Extract the tarball** somewhere stable:
   ```bash
   mkdir -p ~/wavefront
   cd ~/wavefront
   tar -xzf ~/Downloads/phish-triage-v<X.Y.Z>-griffon.tar.gz
   cd phish-triage
   ```

3. **Initial set up: Drop the API keys into a local `.env`:**
   For initial testing of this system only, we recommend API keys be place in the .env file in the project. Once we have validated the tool and deployment pipeline, we'll be migrating to API key management using 1Password's Command Line Interface tool. 

   ```bash
   cp .env.example .env
   # Open .env in any editor and paste in the three keys Wavefront sent.
   # The file should end up looking like:
   #   URLSCAN_API_KEY=019d...
   #   ABUSEIPDB_API_KEY=a528...
   #   GOOGLE_SAFE_BROWSING_API_KEY=AIzaSy...
   chmod 600 .env  # restrict to your user only
   ```
   `.env` is gitignored and stays local on your machine. The keys are valuable — if your laptop is lost or compromised, contact Wavefront immediately so we can rotate.


4. **Install pinned Python dependencies:**
   ```bash
   uv sync --frozen
   ```
   This installs the exact versions from the committed lockfile. ~1 minute typically.

5. **Generate the Claude Desktop config:**
   ```bash
   bash scripts/setup.sh
   ```
   Expected output includes `launcher: launch-mcp-env.sh (.env present in project root)`. The script writes `.mcp.json` with absolute paths for your machine and reports whether the runtime dependencies are reachable. It does not make network requests, install packages, or modify anything outside this project directory — feel free to read it first (`less scripts/setup.sh`).

6. **Open the project in Claude Desktop.** If it was already running, Cmd+Q and reopen. Open `~/wavefront/phish-triage` as the working directory in the Code tab. The MCP server and the skill load automatically.

7. **Smoke test.** In a Code-tab conversation, paste a sample email and ask Claude to triage it. The skill should auto-trigger and the analysis tools should fire.

### Updating, recovering, switching to 1Password

- **New version from Wavefront** arrives as a fresh tarball. Extract alongside the old one, copy your existing `.env` over, re-run `uv sync --frozen` and `bash scripts/setup.sh`.
- **MCP server stops responding mid-session:** Cmd+Q Claude Desktop and reopen. That re-spawns the MCP server child process — clean reset.
- **Migrating to 1Password (recommended once Wavefront has your vault ready):** delete `.env`, accept the 1Password vault invite, enable 1Password CLI in the 1Password app *(Settings → Developer)*, then re-run `bash scripts/setup.sh`. It'll detect the missing `.env` plus the available `op` and switch the launcher automatically. After that, API keys never live on disk.

---

## Use

When you have a suspicious email:

1. **Get the raw source.** In Gmail: open the email → three-dot menu → "Show original" → copy everything. Other clients have similar options — search "show original headers" for yours.

2. **Paste into Cowork** with a prompt like "Triage this email" or "Is this phishing?". The skill auto-triggers on phishing-related language; you don't need to invoke it explicitly.

3. **Wait ~30–60 seconds.** Header parsing and DNS/WHOIS are fast. URL scans take 10–20s each, so a multi-link email can take a couple of minutes.

4. **Read the verdict.** See "Output" below.

### A few notes

- **Links:** Claude will offer to scan up to 3 URLs through URLScan.io. You can decline if you're worried about tipping off the attacker (see Privacy below). You can also ask Claude to "just follow the redirects locally" — that uses a local HTTP client that doesn't render the page or contact any third party.
- **Screenshots don't work.** The tools need raw email text. If a colleague forwarded a phishing email, ask them for the original source.
- **Attachments are not opened.** Claude will report attachment names and types but never decode contents. Treat them as untrusted.

---

## What gets sent where

When you paste an email, Claude extracts indicators (URLs, domains, IP addresses) from it and queries external services to enrich them. **Raw email content — bodies, addresses, attachment data — never leaves your machine.** Only extracted indicators are transmitted.

| Service | What is sent | What they do with it |
|---|---|---|
| URLScan.io | URLs from the email | Visits the URL in a sandboxed browser, captures the page and network activity. Submitted as "unlisted" — not publicly searchable, but accessible to anyone with the scan UUID. |
| Google Safe Browsing | URLs / domains | Looked up against Google's threat database. Standard API logging only. |
| AbuseIPDB | IP addresses | Looked up against a crowd-sourced abuse-report database. |
| Public WHOIS servers | Domain names | Standard WHOIS — public protocol, public infrastructure. |
| Public DNS | Domain names | Standard DNS lookups (MX, SPF, DMARC, etc.). |

**Not in use for your deployment:** VirusTotal. Wavefront has paused this integration pending review of its terms of service.

### Privacy risk: tracking tokens

Some phishing URLs contain unique per-recipient identifiers (long random strings in the path or query). When URLScan visits the URL, the attacker may see the visit in their server logs and realize the email is being investigated. Claude will flag this risk before scanning. If it matters, ask Claude to use the local redirect-follower instead.

### What Wavefront sees

Nothing. The phish-triage MCP server runs entirely on your machine — there is no Wavefront-hosted backend. Email content, extracted indicators, and verdicts all stay local; only the third-party services in the table above receive anything (and only the indicators, never the email itself).

Wavefront's only operational role is shipping you tarball updates and rotating API keys when needed.

---

## Output

A typical report looks like this:

```
## Phishing Analysis: [Subject Line]

**Verdict: PHISHING / SUSPICIOUS / LIKELY LEGITIMATE / PHISHING SIMULATION**
**Confidence: HIGH / MEDIUM / LOW**

### Summary
[2–3 sentence assessment]

### Sender Analysis
- From, Return-Path, Reply-To
- Authentication: SPF / DKIM / DMARC results
- Sender domain age

### Infrastructure
- Originating IP, ISP, abuse score, relay chain

### Content Indicators
- URLs, mismatches, tracking pixels, attachments

### Red Flags
- [Specific findings]

### Recommendations
- [What to do]
```

### Reading the verdict

| Verdict | What it means | What to do |
|---|---|---|
| **PHISHING** (HIGH) | Multiple strong signals converge: failed authentication, lookalike domain, malicious URLs, etc. | Don't click anything. Report to your security team. Delete or quarantine. |
| **SUSPICIOUS** | Some red flags but not conclusive — could be misconfigured legitimate mail, or a sophisticated attack. | Don't act on the email's request. Verify out-of-band — call the supposed sender. |
| **LIKELY LEGITIMATE** | Authentication passes, infrastructure looks normal, no convergent red flags. | Reasonable to engage, but use normal judgment for sensitive actions. |
| **PHISHING SIMULATION** | Detected the fingerprints of an authorized phishing-test platform (e.g., CanIPhish). | This was a test. The techniques are real — note what almost tricked you. |

### Confidence levels

- **HIGH** — multiple independent signals agree. Trust the verdict.
- **MEDIUM** — signals are mixed or some enrichments failed. Use judgment.
- **LOW** — limited data (e.g., domain too new for WHOIS, URLScan rate-limited). Get a second opinion or re-run later.

### When the report says "not configured" or "rate limit"

Some checks may be unavailable due to missing API keys (a Wavefront-side configuration choice) or rate limits hit by recent use. Claude will still produce a verdict from whatever data is available; the confidence rating will reflect the gaps. If a critical check failed and you need it, ask Claude to retry that specific enrichment.

### Asking follow-up questions

The report is the start of the conversation, not the end. You can ask:

- "Why did DMARC fail?"
- "What's a lookalike domain?"
- "Should I report this somewhere?"
- "Re-scan the second URL."

The skill stays loaded for the rest of the conversation — Claude has all the analysis context.

---

## Getting help

- Bugs, weird output, or missing tools — contact your Wavefront point of contact.
- If a tool returns an error, send the error message (not the email content) to Wavefront.
- To add or remove a check, ask — that's a Wavefront-side configuration change.
