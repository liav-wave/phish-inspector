# Phish-Triage — Claude Desktop Skill Deploy Runbook

> **This is the canonical deployment path** for current clients (as of 2026-05).
> The legacy Cloud Run / hosted-variant runbook lives at
> `wip/cloud-run/deploy-runbook.md` and is not in active use.

**Form-factor:** project-local stdio MCP server, loaded by Claude Desktop's Code tab when the project directory is the working directory. Skill auto-loads from `.claude/skills/phish-triage/SKILL.md`.

**API keys: dual-path with auto-detection.** `scripts/setup.sh` picks the launcher based on what's available on the client machine:

- `.env` present in project root → `launch-mcp-env.sh` (keys read from `.env` by phish-triage's `load_dotenv()`). Lower friction; intended for first deploy and debugging.
- No `.env`, 1Password CLI reachable → `launch-mcp.sh` (keys retrieved via `op run --env-file=client.env.template -- ...`, never written to disk). Recommended steady state.

For first deploy we ship the `.env` path. Migration to 1Password is a follow-up: delete `.env`, accept vault invite, enable `op`, re-run `setup.sh`.
---

## What gets installed on the client's machine

| Component | Why | First deploy | Future migration |
|---|---|---|---|
| Xcode Command Line Tools | Native compilation for any Python wheels | Required | — |
| `uv` | Pinned-version Python deps from `uv.lock` | Required | — |
| Phish-triage source | The MCP server itself | Tarball (Client may not have git) | — |
| API keys in `.env` | Read by `phish-triage` at startup | Required for first deploy | Removed |
| 1Password CLI (`op`) | API key retrieval at runtime, no disk plaintext | Skipped | Required |
| Wavefront 1Password vault access | Where the API keys live | Skipped | Required (invite client) |

---

## Pre-meeting prep (Wavefront side)

These all need to happen *before* the meeting. The meeting timeline assumes they're done.

### 1. Provision API keys

For client: URLScan.io, AbuseIPDB, Google Safe Browsing. (VirusTotal still skipped per the open ToS issue.) Keep them somewhere we can hand to the client over a secure channel during the meeting (1Password share, Signal, etc.) — for the first deploy they go straight into project's `.env`.

When the client populates `.env` for the first time, ensure the file ends up with mode `0600`. `scripts/setup.sh` runs `chmod 600 .env` automatically when it sees a `.env` in the project root, but if the client created the file before running setup, double-check the perms during the screenshare:

```bash
ls -l .env
# expect: -rw-------
chmod 600 .env  # if not already
```

### 2. (Future) 1Password vault structure

Skipped for first deploy. When we migrate to 1Password, the vault structure is (using GRIFFON as an example):

```
Wavefront-Clients/  (vault)
├─ GRIFFON_URLSCAN_API_KEY               (item, field: credential)
├─ GRIFFON_ABUSEIPDB_API_KEY             (item, field: credential)
└─ GRIFFON_GOOGLE_SAFE_BROWSING_API_KEY  (item, field: credential)
```

`op://` references (already committed in `client.env.template`):
```
op://Wavefront-Clients/GRIFFON_URLSCAN_API_KEY/credential
op://Wavefront-Clients/GRIFFON_ABUSEIPDB_API_KEY/credential
op://Wavefront-Clients/GRIFFON_GOOGLE_SAFE_BROWSING_API_KEY/credential
```

For SABLE/SAPLING/etc., the convention is `<CODENAME>_<KEY_NAME>` per item.

### 3. (Future) Invite Client to the 1Password vault

Skipped for first deploy. When migrating, add client as a guest with read access.

### 4. Source delivery: tarball

Clients often don't have git (no Xcode CLT yet, so `/usr/bin/git` is just an install-prompt stub). Ship a tarball.

Generate from a tagged commit so we have a fixed reference for support:

```bash
cd /Users/liav/projects/phishing-audit
git tag -a v0.1.0-griffon -m "Initial GRIFFON deploy"
git archive --format=tar.gz --prefix=phish-triage/ v0.1.0-griffon \
    -o /tmp/phish-triage-v0.1.0-griffon.tar.gz
```

`git archive` only includes tracked files, so Liav's local untracked `.mcp.json` (gitignored after the migration in step 6) won't ship.

### 5. Land the deploy artifacts on `main`, then re-tag

The artifact files are written and smoke-tested in the working tree but not yet committed. Sequence:

```bash
cd /Users/liav/projects/phishing-audit

# Remove the existing .mcp.json from git tracking — it has Liav's hardcoded
# paths and shouldn't ship to clients. The file stays on disk locally.
git rm --cached .mcp.json

# Stage the new files (note specific paths — never `git add -A`).
git add .gitignore \
        .env.example \
        .mcp.json.example \
        scripts/setup.sh \
        scripts/launch-mcp.sh \
        scripts/launch-mcp-env.sh \
        client.env.template \
        .claude/skills/phish-triage/SKILL.md \
        docs/internal/desktop-skill-deploy.md \
        docs/phish-triage-guide.md

# The skill rename (phish-triage.md → phish-triage/SKILL.md) is already
# staged via `git mv`; verify in `git status`.

git commit -m "<message per repo style>"

# Re-tag now that the artifacts are committed.
git tag -a v0.1.0-griffon -m "Initial GRIFFON deploy"

# Then build the tarball (per step 4).
```

Files in the commit:

- `.gitignore` — adds `.mcp.json` so per-user copies stay local
- `.env.example` — empty `.env` template client copies and fills in
- `.mcp.json.example` — template with `__PROJECT_DIR__` and `__LAUNCHER__` placeholders
- `scripts/setup.sh` — picks launcher based on what's on the machine, generates `.mcp.json`, validates JSON
- `scripts/launch-mcp.sh` — runtime wrapper for the 1Password path
- `scripts/launch-mcp-env.sh` — runtime wrapper for the `.env` path
- `client.env.template` — 1Password secret references (used by `launch-mcp.sh`)
- `.claude/skills/phish-triage/SKILL.md` — skill, renamed from `.claude/skills/phish-triage.md` to the canonical directory layout
- `docs/internal/desktop-skill-deploy.md` — this runbook
- `docs/phish-triage-guide.md` — client-facing user guide (rewritten for the project-local architecture)

---

## Files in the working tree (ready to commit)

All exist in the working tree, smoke-tested. Read directly in the repo:

| Path | Purpose |
|---|---|
| `scripts/setup.sh` | Install-time script. Detects `.env` vs `op` availability, picks the right launcher, generates `.mcp.json` with absolute paths substituted, validates JSON, reports runtime deps. No network, no privilege escalation, no package installs. |
| `scripts/launch-mcp.sh` | Runtime wrapper for the 1Password path: `op run --env-file=client.env.template -- uv run python -m phish_triage`. |
| `scripts/launch-mcp-env.sh` | Runtime wrapper for the `.env` path: `cd $PROJECT_DIR && uv run python -m phish_triage`. phish-triage's `load_dotenv()` finds `.env`. |
| `.mcp.json.example` | Template with `__PROJECT_DIR__` and `__LAUNCHER__` placeholders. |
| `.env.example` | Empty `.env` template (three blank `KEY=` lines). |
| `client.env.template` | 1Password `op://` secret references (used only when `launch-mcp.sh` is selected). |
| `.gitignore` (modified) | Adds `.mcp.json` so per-user copies stay local. |
| `.claude/skills/phish-triage/SKILL.md` | Skill, renamed from old single-file layout via `git mv`. |
| `docs/phish-triage-guide.md` | Client-facing user guide, rewritten for the project-local architecture. |

`docs/internal/desktop-skill-deploy.md` (this file) is also in the to-commit set.

The existing `.mcp.json` (with Liav's hardcoded paths) needs `git rm --cached` as part of the same commit so the tarball doesn't ship Liav's paths to clients. The file stays on disk locally; `setup.sh` refuses to overwrite an existing `.mcp.json`.

---

## Meeting walkthrough

### Phase 0 — Confirm preflight (~2 min)

Re-run the preflight script if it's been more than a day since the last one. Confirms machine state matches what we planned for.

### Phase 1 — Xcode CLT (~10 min, runs in background)

Trigger the install dialog. Click Install. While it downloads, continue with phase 2.

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

# 3. Read it
less ~/Downloads/uv-install.sh

# 4. Run it
sh ~/Downloads/uv-install.sh

# 5. Clean up
rm ~/Downloads/uv-install.sh

# 6. Make uv available in current shell
source ~/.zshrc
```

After install: `uv --version` should print a version. uv binary lives at `~/.local/bin/uv`.

### Phase 3 — (Skipped for first deploy) Enable 1Password CLI

For the first deploy we ship the `.env` path; 1Password CLI setup happens in a follow-up. Skip this phase entirely on the first call.

When migrating later:

1. Open client's 1Password 8 desktop app → Settings → Developer.
2. Toggle on "Connect with 1Password CLI."
3. `op` lands at `/usr/local/bin/op`, pre-authenticated against the desktop session.
4. Verify with `op vault list` showing the `Wavefront-Clients` vault.

### Phase 4 — Get the source onto client's machine (~3 min)

We hand the client a tarball over a secure channel (1Password share, Signal, encrypted email). He extracts:

```bash
mkdir -p ~/wavefront
cd ~/wavefront
tar -xzf ~/Downloads/phish-triage-v0.1.0-griffon.tar.gz
mv phish-triage phish-triage     # tarball already uses --prefix=phish-triage/
cd phish-triage
```

(The tarball is generated via `git archive` from the tagged release; it includes only tracked files. `.mcp.json` is excluded by gitignore, so the client gets the `.example` and runs setup.sh in the next phase to generate his own.)

### Phase 5 — Drop API keys into `.env` (~3 min)

Hand the client the three keys over a secure channel (1Password share, Signal, etc.). He copies them into `.env`:

```bash
cd ~/wavefront/phish-triage
cp .env.example .env
# Edit .env in any editor, paste the three keys
```

Resulting `.env`:
```
URLSCAN_API_KEY=019d...
ABUSEIPDB_API_KEY=a528...
GOOGLE_SAFE_BROWSING_API_KEY=AIzaSy...
```

`.env` is gitignored. 

### Phase 6 — Install pinned Python dependencies (~2 min, longer if CLT just finished)

```bash
cd ~/wavefront/phish-triage
uv sync --frozen
```

`--frozen` ensures uv installs exactly what's in `uv.lock` and doesn't update anything. This is the supply-chain hygiene step — client gets the exact versions we vetted.

### Phase 7 — Configure Claude Desktop (~1 min)

Run the setup script. It picks a launcher based on what's available, generates `.mcp.json` with client's absolute path filled in, validates the JSON, and reports whether `uv` and `op` are reachable.

```bash
cd ~/wavefront/phish-triage
bash scripts/setup.sh
```

Expected output for the `.env` path:
```
setup: wrote /Users/client/wavefront/phish-triage/.mcp.json
       launcher: launch-mcp-env.sh  (.env present in project root)
```

If the client wants to review the script before running (recommended once, especially if his org has security review), `less scripts/setup.sh` — short, no network, no privilege escalation, no package installs.

The skill (`~/wavefront/phish-triage/.claude/skills/phish-triage/SKILL.md`) is already in place from the tarball — nothing more to do.

### Phase 8 — Smoke test (~5 min)

1. Open Claude Desktop.
2. Switch to Code tab in the sidebar.
3. Open the project at `~/wavefront/phish-triage`.
4. Trust prompt appears the first time — client allows.
5. In a fresh chat, ask: "Can you ping the phish-triage tools?" or "Triage this email: [paste a synthetic phishing sample]."
6. Expect: Claude detects the phishing context, the skill triggers, tool calls land.

### Phase 9 — Failure-mode briefing (~5 min)

Walk client through the table below so he knows what to do without us:

| Symptom | Cause | Fix |
|---|---|---|
| "MCP server failed to start" | Wrapper script can't find uv | Re-run `xcode-select --install` (CLT) and re-source `~/.zshrc`. Then Cmd+Q + reopen Claude Desktop. |
| Tool returns `{"error": "not_configured"}` | Key missing or wrong in `.env` | Open `.env`, confirm all three keys present and pasted cleanly (no quotes, no leading whitespace). |
| Tools work but skill doesn't auto-trigger | Wrong working directory in Code tab | Make sure the Code tab is rooted at `~/wavefront/phish-triage`, not somewhere else. |
| `setup.sh` fails with "cannot pick a launcher" | No `.env` and no `op` | Run `cp .env.example .env`, paste keys, then re-run `setup.sh`. |
| Things were working, now broken after macOS update | Apple update sometimes invalidates CLT | `xcode-select --install` again. |

client's escalation path: Slack/email Liav with the symptom + relevant log line from `~/Library/Logs/Claude/main.log`.

---

## Realistic timing (first deploy, `.env` path)

| Phase | Time on a good day | Time if surprises |
|---|---|---|
| 0. Preflight | 2 min | 2 min |
| 1. CLT install | 10 min (background) | 15 min |
| 2. uv install | 3 min | 8 min |
| 3. (1Password — skipped for first deploy) | — | — |
| 4. Tarball extract | 3 min | 5 min |
| 5. `.env` keys | 3 min | 5 min if a key got mangled in transit |
| 6. uv sync | 2 min | 5 min if a wheel needs to compile |
| 7. setup.sh | 1 min | 3 min |
| 8. Smoke test | 5 min | 10 min if a path is wrong |
| 9. Failure modes briefing | 5 min | 5 min |
| **Total** | **~35 min** | **~60 min** |

CLT downloads in parallel with phases 2 and 4, so wall-clock time is dominated by whichever of (CLT, the rest) is longest.

---

## Decisions resolved

1. **Source delivery:** tarball. client has no git. (2026-05-06)
2. **`.mcp.json` strategy:** per-user, gitignored. Generated from `.mcp.json.example` by `scripts/setup.sh`. (2026-05-06)
3. **Auth strategy for first deploy:** `.env`-based, with 1Password as the migration target. setup.sh auto-detects which launcher to wire in based on what's present on the machine. (2026-05-07)
4. **Skill layout:** `.claude/skills/phish-triage/SKILL.md` (canonical directory layout). Single-file `.claude/skills/phish-triage.md` is deprecated and silently ignored by Claude Desktop 1.4758+. (2026-05-07)
5. **Vault path naming (for migration):** per-key items `GRIFFON_<KEY_NAME>` in vault `Wavefront-Clients`, field `credential`.
6. **Repo tag:** `v0.1.0-griffon`.

## Open before the meeting

- Generate the tarball after the commit + tag.
- Decide secure channel for tarball delivery + key handoff to client (1Password share recommended for both).

---

## Updates after first deploy

client has no git, so updates ship as new tarballs:

1. Wavefront-side: tag a new release (`v0.1.1-griffon` or similar) and `git archive` a new tarball.
2. Notify client (Signal/email) with the tarball.
3. He runs:
   ```bash
   cd ~/wavefront
   tar -xzf ~/Downloads/phish-triage-v0.1.1-griffon.tar.gz \
       -C ./phish-triage --strip-components=1
   cd phish-triage
   uv sync --frozen          # picks up any dep changes
   bash scripts/setup.sh     # only re-runs if .mcp.json was deleted; otherwise no-op
   ```
4. Cmd+Q + reopen Claude Desktop.

`.env` and `.mcp.json` are preserved across updates because the tarball doesn't ship them (gitignored on our side).

Expected cadence for the early period: ~weekly while we iron out issues. Drops off once stable.

---

## Out of scope for this meeting

- 1Password migration (separate follow-up after first deploy lands cleanly)
- Web-app form-factor (deferred until we know if/when this scales beyond ~3 clients)
- Cloud Run deployment (deferred; previous runbook stays in repo for reference)
- macOS Keychain as an alternative to 1Password (no need — client has 1Password)
- Multi-tenant per-client config in the same repo (build when we onboard client #2)
- Automated update notification (manual notify-by-message for now)

## Migration to 1Password (follow-up, after first deploy)

When ready, the migration is short:

1. Wavefront-side: invite client to the `Wavefront-Clients` vault as a guest.
2. client accepts the invite in his 1Password app.
3. client enables 1Password CLI: 1Password Settings → Developer → "Connect with 1Password CLI."
4. client: `cd ~/wavefront/phish-triage && rm .env .mcp.json && bash scripts/setup.sh`. Setup.sh sees no `.env` and `op` available, picks `launch-mcp.sh`, regenerates `.mcp.json`.
5. Cmd+Q + reopen Claude Desktop.

After migration, API keys never live on disk on client's machine.

---

## Wavefront-internal post-deploy record

After the meeting, append to memory:

- Codename: GRIFFON
- Contact: client (client@griffon.example)
- Deploy date: <fill in>
- Repo tag deployed: v0.1.0-griffon
- 1Password vault path: <actual final value>
- Authorized users: client@griffon.example
- Anything client-specific: <e.g., reauth quirks, network restrictions>
