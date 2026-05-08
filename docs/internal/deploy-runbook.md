# Phish Triage — Per-Client Deploy Runbook

Internal Wavefront doc. End-to-end procedure for deploying a single-tenant Phish Triage instance for a new client.

This runbook uses **GRIFFON** as the example. For other clients, substitute codenames and contact details.

---

## Pre-deploy checklist

- [ ] GCP project created or selected for the client.
- [ ] Cloud Run, Secret Manager, and Cloud Build APIs enabled in the project.
- [ ] API keys obtained:
  - URLScan.io
  - Google Safe Browsing
  - AbuseIPDB
  - **VirusTotal: skip.** Open ToS issue around commercial use. Do not provision the secret for new client deploys until resolved.
- [ ] Client contact's Google Workspace email confirmed (e.g., `paul@griffon.example`).
- [ ] Client contact has `gcloud` installed locally, or is willing to install it.

---

## Deploy

```bash
export GCP_PROJECT_ID=<client-gcp-project>
gcloud config set project $GCP_PROJECT_ID

# Enable APIs (one-time per project)
gcloud services enable run.googleapis.com secretmanager.googleapis.com cloudbuild.googleapis.com

# Create the three secrets (paste each key when prompted)
echo -n "URLSCAN_KEY"    | gcloud secrets create urlscan-api-key --data-file=-
echo -n "SAFEBROWSE_KEY" | gcloud secrets create google-safe-browsing-api-key --data-file=-
echo -n "ABUSEIPDB_KEY"  | gcloud secrets create abuseipdb-api-key --data-file=-
```

`scripts/deploy.sh` references the VirusTotal secret in `--set-secrets`. **For VT-disabled clients, do not run the script as-is** — use the inline command below instead:

```bash
gcloud builds submit --tag gcr.io/$GCP_PROJECT_ID/phish-triage .

gcloud run deploy phish-triage \
  --image gcr.io/$GCP_PROJECT_ID/phish-triage \
  --region us-central1 \
  --platform managed \
  --no-allow-unauthenticated \
  --memory 512Mi --cpu 1 \
  --min-instances 0 --max-instances 2 \
  --timeout 300 --port 8080 \
  --set-secrets "URLSCAN_API_KEY=urlscan-api-key:latest,GOOGLE_SAFE_BROWSING_API_KEY=google-safe-browsing-api-key:latest,ABUSEIPDB_API_KEY=abuseipdb-api-key:latest"
```

Capture the printed URL. The MCP endpoint Paul needs is `<URL>/mcp`.

---

## Grant client access

```bash
gcloud run services add-iam-policy-binding phish-triage \
  --region=us-central1 \
  --member='user:paul@griffon.example' \
  --role='roles/run.invoker'
```

---

## Hand-off package

Send Paul:

1. **The skill** — current `.claude/skills/phish-triage/` directory (containing `SKILL.md`) from the repo.
2. **The user guide** — `docs/phish-triage-guide.md`.
3. **An MCP config snippet** with the deployed URL pre-filled. Use the example in the user guide as the template — replace `<URL provided by Wavefront>` with `<deployed-url>/mcp`.
4. **A note on auth** — confirm Paul has `gcloud` installed and is signed in as the email you granted access to.

A 15-min screenshare for the first install is worth offering — most snags are gcloud/auth confusion, not the skill itself.

---

## Per-client recordkeeping

No central registry yet. For each deploy, record (in memory or a private gist):

- Codename (e.g., GRIFFON)
- GCP project ID
- Deployed URL
- Deploy date
- Authorized users
- VT enabled: yes / no
- Anything client-specific (restricted enrichments, custom rate limits, etc.)

---

## Known sharp edges

1. **Identity token expires hourly.** `gcloud auth print-identity-token` returns a 1h token. If Cowork doesn't re-evaluate the `$(...)` shell expansion in `headers` on each request, Paul's connection will silently fail after an hour. Workarounds documented in the user guide: restart Cowork, or paste a fresh token manually. Longer-term fix: switch to IAP + load balancer for proper SSO (per the original deployment plan, not yet implemented).

2. **`deploy.sh` hard-codes the VT secret.** Either patch the script per-client, parameterize it, or use the inline gcloud command above. **Do not** create an empty VT secret to satisfy the script — Secret Manager rejects empty payloads, and a dummy non-empty value would route to the real VT API at request time.

3. **Skill drift across clients.** Each client gets a static copy of the skill file. When it changes in the repo, no automatic propagation — re-send manually. A plugin-based distribution removes this; consider promoting once we have a second client live.

---

## Update procedures

**Server update** (new tool, bugfix, etc.):
```bash
export GCP_PROJECT_ID=<client-project>
# Re-run the gcloud builds + gcloud run deploy commands above.
```
Paul does not need to do anything — the URL is unchanged.

**Skill update:** email Paul the new `phish-triage.md`, ask him to drop it into `~/.claude/skills/` and restart Cowork.

**API key rotation:** see `CLAUDE.md` → Incident Response. Same process for routine rotation: add a new secret version, redeploy.

---

## Decommission

When an engagement ends:

```bash
gcloud run services delete phish-triage --region=us-central1
gcloud secrets delete urlscan-api-key
gcloud secrets delete google-safe-browsing-api-key
gcloud secrets delete abuseipdb-api-key
# Optional: delete the project itself
# gcloud projects delete $GCP_PROJECT_ID
```

Tell Paul to:

- Remove `~/.claude/skills/phish-triage/` (directory)
- Remove the `phish-triage` entry from `~/.claude/settings.json`
