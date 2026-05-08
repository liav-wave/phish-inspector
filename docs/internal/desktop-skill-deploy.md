# Phish-Triage — Claude Desktop Skill Deploy Runbook

**Form-factor:** project-local stdio MCP server, loaded by Claude Desktop's Code tab when the project directory is the working directory. Skill auto-loads from `.claude/skills/phish-triage/SKILL.md`. API keys retrieved at runtime via 1Password CLI; never written to disk.

**This runbook uses GRIFFON / Paul as the worked example.** It supersedes the earlier `deploy-runbook.md`, which was scoped for a Cloud Run + IAP architecture we backed out of.

---

## What gets installed on Paul's machine

| Component | Why | Install route |
|---|---|---|
| Xcode Command Line Tools | git + native compilation for any Python wheels | macOS-native installer (Apple, signed) |
| `uv` | Pinned-version Python deps from `uv.lock` | Official uv installer (download → review → run) |
| 1Password CLI (`op`) | API key retrieval at runtime, no disk plaintext | 1Password 8 app's Developer toggle (already installed) |
| Phish-triage source | The MCP server itself | git clone or tarball (decision below) |
| Wavefront 1Password vault access | Where the API keys live | Invite Paul before the meeting |

What does **not** get installed: Node.js, mcp-remote, gcloud, Homebrew, any package manager Paul didn't already have.

---

## Pre-meeting prep (Wavefront side)

These all need to happen *before* the meeting. The meeting timeline assumes they're done.

### 1. 1Password vault structure

Each API key is its own item in the `Wavefront-Clients` vault, with a single `credential` field (1Password's default for API_Credential-category items):

```
Wavefront-Clients/  (vault)
├─ GRIFFON_URLSCAN_API_KEY               (item, field: credential)
├─ GRIFFON_ABUSEIPDB_API_KEY             (item, field: credential)
└─ GRIFFON_GOOGLE_SAFE_BROWSING_API_KEY  (item, field: credential)
```

Resulting `op://` references (committed in `client.env.template`):
```
op://Wavefront-Clients/GRIFFON_URLSCAN_API_KEY/credential
op://Wavefront-Clients/GRIFFON_ABUSEIPDB_API_KEY/credential
op://Wavefront-Clients/GRIFFON_GOOGLE_SAFE_BROWSING_API_KEY/credential
```

For SABLE/SAPLING/etc., the convention is `<CODENAME>_<KEY_NAME>` per item.

### 2. Provision API keys

For GRIFFON: URLScan.io, AbuseIPDB, Google Safe Browsing. (VirusTotal still skipped per the open ToS issue.) Paste keys into the 1Password item from step 1.

### 3. Invite Paul to the vault

Add `paul@griffon.example` (his Workspace email) as a guest with read access to the GRIFFON section only. He'll accept in his desktop 1Password app at the start of the meeting.

### 4. Source delivery: tarball

Paul does not have git (no Xcode CLT yet, so `/usr/bin/git` is just an install-prompt stub). Ship a tarball.

Generate from a tagged commit so we have a fixed reference for support:

```bash
cd /Users/liav/projects/phishing-audit
git tag -a v0.1.0-griffon -m "Initial GRIFFON deploy"
git archive --format=tar.gz --prefix=phish-triage/ v0.1.0-griffon \
    -o /tmp/phish-triage-v0.1.0-griffon.tar.gz
```

`git archive` only includes tracked files, so Liav's local untracked `.mcp.json` (gitignored after the migration in step 6) won't ship.

### 5. (folded into 4)

### 6. Land the deploy artifacts on `main`, then re-tag

The artifact files are written and smoke-tested in the working tree but not yet committed. Sequence:

```bash
cd /Users/liav/projects/phishing-audit

# Remove the existing .mcp.json from git tracking — it has Liav's hardcoded
# paths and shouldn't ship to clients. The file stays on disk locally.
git rm --cached .mcp.json

# Stage the new files (note specific paths — never `git add -A`).
git add .gitignore \
        .mcp.json.example \
        scripts/setup.sh \
        scripts/launch-mcp.sh \
        client.env.template \
        docs/internal/desktop-skill-deploy.md

git commit -m "<message per repo style>"

# Re-tag now that the artifacts are committed.
git tag -a v0.1.0-griffon -m "Initial GRIFFON deploy"

# Then build the tarball (per step 4).
```

Files in the commit:

- `.gitignore` — adds `.mcp.json` so per-user copies stay local
- `.mcp.json.example` — template with `__PROJECT_DIR__` placeholder
- `scripts/setup.sh` — generates `.mcp.json` from the example, validates JSON, checks for uv + op
- `scripts/launch-mcp.sh` — runtime wrapper invoked by Claude Desktop (does `op run -- uv run ...`)
- `client.env.template` — 1Password secret references (vault paths)
- `docs/internal/desktop-skill-deploy.md` — this runbook

---

## Files in the working tree (ready to commit)

All five exist in the working tree, smoke-tested. Read directly in the repo:

| Path | Purpose |
|---|---|
| `scripts/launch-mcp.sh` | Runtime wrapper. Locates `uv` and `op`, then `op run --env-file=client.env.template -- uv run python -m phish_triage`. Errors surface to Cowork via stderr. |
| `scripts/setup.sh` | One-time install-side script. Generates `.mcp.json` from `.mcp.json.example` with the absolute project path substituted; validates the JSON; reports whether `uv` and `op` are reachable. No network, no privilege escalation, no package installs. |
| `.mcp.json.example` | Template with `__PROJECT_DIR__` placeholder. |
| `client.env.template` | 1Password `op://` secret references for the three API keys. |
| `.gitignore` (modified) | Adds `.mcp.json` so per-user copies stay local. |

`docs/internal/desktop-skill-deploy.md` (this file) is also in the to-commit set.

The existing `.mcp.json` (with Liav's hardcoded paths) needs `git rm --cached` as part of the same commit so the tarball doesn't ship Liav's paths to clients. The file stays on disk locally; setup.sh refuses to overwrite an existing `.mcp.json`.

---

## Meeting walkthrough

### Phase 0 — Confirm preflight (~2 min)

Re-run the preflight script if it's been more than a day since the last one. Confirms machine state matches what we planned for.

### Phase 1 — Xcode CLT (~10 min, runs in background)

Trigger the install dialog (which Paul already saw from the preflight bug — apologies, again). Click Install. While it downloads, continue with phase 2.

```bash
# Trigger CLT install (will pop a dialog if not already running)
xcode-select --install
```

If dialog already showed and is dismissed: open System Settings → Software Update → Command Line Tools to retrigger.

CLT install must complete before phase 5 (`uv sync` may need it for native wheels).

### Phase 2 — Install uv (~3 min)

Per supply-chain rule 7 (no curl-pipe-bash), use the download-first pattern:

```bash
# 1. Download the installer to a known path
curl -LsSf https://astral.sh/uv/install.sh -o ~/Downloads/uv-install.sh

# 2. Verify it's a reasonable shell script
file ~/Downloads/uv-install.sh
wc -l ~/Downloads/uv-install.sh    # should be a few hundred lines

# 3. Read it (Paul or his security reviewer can eyeball it)
less ~/Downloads/uv-install.sh

# 4. Run it
sh ~/Downloads/uv-install.sh

# 5. Clean up
rm ~/Downloads/uv-install.sh

# 6. Make uv available in current shell
source ~/.zshrc
```

After install: `uv --version` should print a version. uv binary lives at `~/.local/bin/uv`.

### Phase 3 — Enable 1Password CLI (~1 min)

In Paul's 1Password 8 desktop app:

1. Open Settings → Developer.
2. Toggle on "Connect with 1Password CLI" (or similar — exact name varies by app version).
3. This installs `op` to `/usr/local/bin/op` and pre-authenticates it against the desktop app's session.

Verify:

```bash
op --version
op vault list   # should list vaults Paul has access to
```

If `op vault list` shows the Wavefront-Clients vault (or whatever we named it), the invite has been accepted and we're set.

### Phase 4 — Get the source onto Paul's machine (~3 min)

We hand Paul `phish-triage-v0.1.0-griffon.tar.gz` over a secure channel (1Password share, Signal, encrypted email). He extracts:

```bash
mkdir -p ~/wavefront
cd ~/wavefront
tar -xzf ~/Downloads/phish-triage-v0.1.0-griffon.tar.gz
mv phish-triage phish-triage     # tarball already uses --prefix=phish-triage/
cd phish-triage
```

(The tarball is generated via `git archive` from the `v0.1.0-griffon` tag; it includes only tracked files. `.mcp.json` is excluded by gitignore, so Paul gets the `.example` and runs setup.sh in the next phase to generate his own.)

### Phase 5 — Install pinned Python dependencies (~2 min, longer if CLT just finished)

```bash
cd ~/wavefront/phish-triage
uv sync --frozen
```

`--frozen` ensures uv installs exactly what's in `uv.lock` and doesn't update anything. This is the supply-chain hygiene step — Paul gets the exact versions we vetted.

### Phase 6 — Configure Claude Desktop (~1 min)

Run the setup script. It generates `.mcp.json` from `.mcp.json.example` with Paul's absolute path filled in, validates the JSON, and reports whether uv and op are reachable.

```bash
cd ~/wavefront/phish-triage
bash scripts/setup.sh
```

Expected output: `setup: wrote /Users/paul/wavefront/phish-triage/.mcp.json` followed by the runtime dependency check showing both uv and op found.

If Paul wants to review the script before running (recommended once, especially if his org has security review), `less scripts/setup.sh` — it's ~60 lines, no network calls, no privilege escalation, no package installs.

The skill (`~/wavefront/phish-triage/.claude/skills/phish-triage/SKILL.md`) is already in place from the tarball — nothing more to do.

### Phase 7 — Smoke test (~5 min)

1. Open Claude Desktop.
2. Switch to Code tab in the sidebar.
3. Open the project at `~/wavefront/phish-triage`.
4. Trust prompt appears the first time — Paul allows.
5. In a fresh chat, ask: "Can you ping the phish-triage tools?" or "Triage this email: [paste a synthetic phishing sample]."
6. Expect: Claude detects the phishing context, the skill triggers, tool calls land. 1Password may show a Touch ID prompt the first time keys are fetched in a session.

### Phase 8 — Failure-mode briefing (~5 min)

Walk Paul through the table below so he knows what to do without us:

| Symptom | Cause | Fix |
|---|---|---|
| "MCP server failed to start" | Wrapper script can't find uv or op | Re-run `xcode-select --install` (CLT) and re-source `~/.zshrc`. Then quit + reopen Claude Desktop. |
| "Authentication required" or 1Password prompt loops | 1Password app locked or Paul logged out | Unlock 1Password, ensure Touch ID is set up. |
| Tools work but skill doesn't auto-trigger | Wrong working directory in Code tab | Make sure the Code tab is rooted at `~/wavefront/phish-triage`, not somewhere else. |
| Tool returns `{"error": "not_configured"}` | `op` couldn't resolve a key | Run `op vault list` and confirm the vault is still accessible. |
| Things were working, now broken after macOS update | Apple update sometimes invalidates CLT | `xcode-select --install` again. |

Paul's escalation path: Slack/email Liav with the symptom + last server log line.

---

## Realistic timing

| Phase | Time on a good day | Time if surprises |
|---|---|---|
| 0. Preflight | 2 min | 2 min |
| 1. CLT install | 10 min (background) | 15 min |
| 2. uv install | 3 min | 8 min |
| 3. 1Password CLI | 1 min | 5 min if vault invite needs re-sending |
| 4. Source clone | 3 min | 5 min if git auth tangles |
| 5. uv sync | 2 min | 5 min if a wheel needs to compile |
| 6. Config | 3 min | 5 min |
| 7. Smoke test | 5 min | 10 min if a path is wrong |
| 8. Failure modes briefing | 5 min | 5 min |
| **Total** | **~35 min** | **~60 min** |

CLT downloads in parallel with phases 2-4, so the wall-clock time is dominated by whichever of (CLT, the rest) is longest.

---

## Decisions resolved (2026-05-06)

1. **Source delivery:** tarball. Paul has no git.
2. **`.mcp.json` strategy:** per-user, gitignored. Generated from `.mcp.json.example` by `scripts/setup.sh` (committed).
3. **Vault path naming:** per-key items `GRIFFON_<KEY_NAME>` in vault `Wavefront-Clients`, field `credential`. Matches actual vault structure as confirmed during setup.
4. **Repo tag:** `v0.1.0-griffon`.

## Open before the meeting

- Verify the `client.env.template` op:// paths match the real 1Password vault names exactly. Adjust if needed before committing.
- Generate the tarball after the commit + tag.
- Decide secure channel for tarball delivery to Paul (1Password share recommended).

---

## Updates after first deploy

When we ship a phish-triage update:

1. Wavefront-side: tag a new release (`v0.1.1-griffon` or similar).
2. Notify Paul (email or message).
3. He runs:
   ```bash
   cd ~/wavefront/phish-triage
   git fetch
   git checkout v0.1.1-griffon
   uv sync --frozen
   ```
4. Restart Claude Desktop.

Expected cadence for early period: ~weekly while we iron out issues. Drops off once stable.

---

## Out of scope for this meeting

- Web-app form-factor (deferred until we know if/when this scales beyond ~3 clients)
- Cloud Run deployment (deferred; previous runbook stays in repo for reference)
- macOS Keychain as an alternative to 1Password (no need — Paul has 1Password)
- Multi-tenant per-client config in the same repo (build when we onboard client #2)
- Automated update notification (manual notify-by-message for now)

---

## Wavefront-internal post-deploy record

After the meeting, append to memory:

- Codename: GRIFFON
- Contact: Paul (paul@griffon.example)
- Deploy date: <fill in>
- Repo tag deployed: v0.1.0-griffon
- 1Password vault path: <actual final value>
- Authorized users: paul@griffon.example
- Anything client-specific: <e.g., reauth quirks, network restrictions>
