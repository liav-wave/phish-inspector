# Cloud Run deployment (legacy / not in active use)

This directory contains the original hosted-variant deployment for Phish Triage:
a single-tenant Cloud Run service running the MCP server in HTTP mode, with API
keys injected from Secret Manager.

**Status as of 2026-05-08: not in use.**

The active deployment path for current clients is the local-stdio form factor
documented in `docs/internal/desktop-skill-deploy.md` — a tarball extracted on
the client's laptop, launched by Claude Desktop as a subprocess. Email content
is processed entirely on the client machine; nothing flows through Wavefront
infrastructure.

These files are kept for reference and possible future use (e.g. clients who
prefer a hosted MCP endpoint over running a local Python process). Before
resurrecting any of this, **read `SECURITY-DEBT.md` in this directory** — there
are known issues that should be fixed before another production deploy.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | Container image for the HTTP-mode server |
| `cloudrun.yaml` | Knative service spec (informational; not used by `deploy.sh`) |
| `docker-compose.yml` | Local Docker test for the HTTP-mode server |
| `deploy.sh` | `gcloud run deploy` wrapper — builds and pushes to Cloud Run |
| `deploy-runbook.md` | Per-client procedure: GCP project, secrets, IAM, updates |
| `SECURITY-DEBT.md` | Known issues to fix before next production deploy |

## How the HTTP transport is wired up

`src/phish_triage/server.py` retains an `http` transport branch (invoked via
`python -m phish_triage http`) used by the Dockerfile in this directory. It is
not exercised by the stdio launchers and is kept dormant.
