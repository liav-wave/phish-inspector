# Cloud Run path — known security debt

Issues identified in the 2026-05-08 security review that apply specifically
to this hosted deployment path. Fix before resurrecting for a production
client. Issues that apply to both deployment paths were fixed in the main
codebase at the same time and are not listed here.

## Critical

### SSRF → GCE metadata service via redirect chain
Severity in this deployment: **critical**. The redirect-follower tool
(`src/phish_triage/tools/redirect_follower.py`) ran behind a host-literal
SSRF check that did not resolve hostnames. A phisher-controlled redirect
chain pointing at a name that resolves to `169.254.169.254` would let the
tool fetch the GCE metadata service and exfiltrate the service-account
identity token in the response body, all from inside the Cloud Run instance.

The validator was hardened in the main codebase (resolves hostnames before
connect, custom transport defeats DNS rebinding). Before resurrecting Cloud
Run, also do:

- Run the service with a dedicated service account that has *only* the
  Secret Manager accessor role for the four phish-triage secrets — the
  default Compute SA is wildly over-provisioned.
- Add a Cloud Run egress policy or VPC connector with egress rules that
  block `169.254.0.0/16` outbound at the network layer, as defense in depth.

## High

### Mutable base image and uv image tags
`Dockerfile` uses `python:3.11-slim` and `ghcr.io/astral-sh/uv:latest`, both
mutable tags. Pin both by digest (`python@sha256:…`, `uv@sha256:…`) and bump
deliberately. A compromised `uv:latest` would run with full privileges
during `RUN uv export`.

### Lockfile hashes discarded at install time
`Dockerfile` does `uv export --frozen --no-hashes > requirements.txt` then
installs the requirements file. The cryptographic hashes from `uv.lock` are
thrown away. Replace with `uv sync --frozen --no-dev --no-install-project`
(or `uv pip sync uv.lock`) so the install verifies against the lockfile
hashes — this is the protection against a registry-side swap of a pinned
version (the LiteLLM scenario).

## Medium

### Cloud Run runs as default Compute service account
`deploy.sh` does not specify `--service-account`. The default Compute SA has
broad project access. Create a dedicated SA with only `roles/secretmanager.secretAccessor`
on the four phish-triage secrets and pass it via `--service-account`.

### `cloudrun.yaml` is templated but never used
`deploy.sh` invokes `gcloud run deploy` with command-line flags and ignores
`cloudrun.yaml`. They will drift. Either delete the YAML or switch the deploy
to `gcloud run services replace cloudrun.yaml`.

### No HTTP body size cap
The MCP HTTP transport accepts arbitrarily large requests up to Cloud Run's
32 MB ceiling. A 30 MB email body to `parse_email_structure` will pressure
memory on a 512 Mi instance. Add an explicit size cap on `raw_email` /
`raw_headers` parameters.

### Container hardening from `docker-compose.yml` does not carry over
`docker-compose.yml` sets `read_only: true`, `no-new-privileges: true`,
tmpfs `/tmp`. None of those are enforced by Cloud Run defaults. At minimum,
use `--execution-environment=gen2` and review whether the app actually needs
filesystem writes anywhere outside `/tmp`.

## Low

### `cloudrun.yaml` lacks digest pinning for the image
`image: IMAGE_URL` is replaced by `deploy.sh` with `gcr.io/$PROJECT/phish-triage`
(no digest). Switch to digest references at deploy time so a Cloud Run
auto-restart can't pick up a different image than what was tested.
