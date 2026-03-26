#!/usr/bin/env python3
"""
vet-package: Pre-install security vetting for Python (PyPI) and Node (npm) packages.

Checks package metadata, age, vulnerabilities, and trust signals BEFORE downloading
or executing any package code. Uses only registry APIs — no code is downloaded or run.

Usage:
    python vet_package.py <package_name>                    # auto-detect ecosystem
    python vet_package.py <package_name> --ecosystem pypi   # force PyPI
    python vet_package.py <package_name> --ecosystem npm    # force npm
    python vet_package.py <package_name>==1.26.0            # specific version (PyPI)
    python vet_package.py <package_name>@1.26.0             # specific version (npm)
    python vet_package.py -r requirements.txt               # audit a requirements file
    python vet_package.py -r package.json                   # audit package.json deps

Exit codes:
    0 = PASS (no issues found)
    1 = WARN (caution advised, review output)
    2 = FAIL (do not install without careful review)
    3 = ERROR (vetting could not complete)

This script does NOT replace runtime vulnerability scanning (pip-audit, npm audit).
It provides a pre-download gate that catches signals those tools cannot.
"""

import argparse
import json
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Optional


# ── Configuration ──────────────────────────────────────────────────────────

MIN_PACKAGE_AGE_DAYS = 7        # Reject versions published less than N days ago
MIN_DOWNLOADS_PYPI = 1000       # Warn if total downloads are below this (monthly)
MIN_DOWNLOADS_NPM = 500         # Warn if weekly downloads are below this
MAX_RESPONSE_TIMEOUT = 15       # Seconds


def _update_min_age(days: int):
    global MIN_PACKAGE_AGE_DAYS
    MIN_PACKAGE_AGE_DAYS = days

# ── Severity levels ────────────────────────────────────────────────────────

PASS = 0
WARN = 1
FAIL = 2
ERROR = 3

SEVERITY_LABELS = {PASS: "PASS", WARN: "WARN", FAIL: "FAIL", ERROR: "ERROR"}
SEVERITY_COLORS = {PASS: "\033[92m", WARN: "\033[93m", FAIL: "\033[91m", ERROR: "\033[91m"}
RESET = "\033[0m"


class Finding:
    def __init__(self, severity: int, check: str, message: str):
        self.severity = severity
        self.check = check
        self.message = message

    def __str__(self):
        color = SEVERITY_COLORS.get(self.severity, "")
        label = SEVERITY_LABELS.get(self.severity, "???")
        return f"  {color}[{label}]{RESET} {self.check}: {self.message}"


def _get_ssl_context() -> ssl.SSLContext:
    """Build an SSL context that works on macOS Python installs missing default certs."""
    ctx = ssl.create_default_context()
    # If the default cert store is empty (common on macOS framework Python when
    # 'Install Certificates.command' hasn't been run), try certifi, then the
    # macOS system roots via Security.framework (loaded by load_default_certs).
    try:
        ctx.load_default_certs()
    except Exception:
        pass
    # If we still have nothing, try certifi
    if not ctx.get_ca_certs():
        try:
            import certifi
            ctx.load_verify_locations(certifi.where())
        except ImportError:
            pass
    # Last resort: try common system CA bundle paths
    if not ctx.get_ca_certs():
        import os
        for ca_path in [
            "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",    # RHEL/CentOS
            "/etc/ssl/cert.pem",                    # macOS/BSD
        ]:
            if os.path.exists(ca_path):
                try:
                    ctx.load_verify_locations(ca_path)
                    break
                except Exception:
                    continue
    return ctx


_ssl_ctx = _get_ssl_context()


def api_get(url: str) -> Optional[dict]:
    """Fetch JSON from a URL. Returns None on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vet-package/1.0"})
        with urllib.request.urlopen(req, timeout=MAX_RESPONSE_TIMEOUT, context=_ssl_ctx) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError) as e:
        return None


# ── Shared helpers ─────────────────────────────────────────────────────────


def query_osv(package: str, version: str, ecosystem: str) -> Optional[list[dict]]:
    """Query OSV for vulnerabilities. Returns list of vuln dicts, or None on error."""
    osv_url = "https://api.osv.dev/v1/query"
    payload = json.dumps({"version": version, "package": {"name": package, "ecosystem": ecosystem}}).encode()
    try:
        req = urllib.request.Request(osv_url, data=payload,
                                     headers={"Content-Type": "application/json", "User-Agent": "vet-package/1.0"})
        with urllib.request.urlopen(req, timeout=MAX_RESPONSE_TIMEOUT, context=_ssl_ctx) as resp:
            osv_data = json.loads(resp.read().decode())
            return osv_data.get("vulns", [])
    except Exception:
        return None


def _get_previous_version(all_versions: list[str], current: str) -> Optional[str]:
    """Return the version immediately before `current` in the ordered list."""
    try:
        idx = all_versions.index(current)
    except ValueError:
        return None
    if idx > 0:
        return all_versions[idx - 1]
    return None


def _is_security_patch(package: str, current_version: str, prev_version: str, ecosystem: str) -> bool:
    """Check if current_version looks like a security patch for prev_version.

    Returns True if the previous version has known vulns and the current does not.
    """
    prev_vulns = query_osv(package, prev_version, ecosystem)
    if not prev_vulns:  # No vulns in previous version (or query failed) — not a security patch
        return False
    curr_vulns = query_osv(package, current_version, ecosystem)
    if curr_vulns is None:  # Query failed — can't determine
        return False
    # Security patch: previous has vulns, current doesn't
    return len(curr_vulns) == 0


# ── PyPI Checks ────────────────────────────────────────────────────────────

def vet_pypi(package: str, version: Optional[str] = None, allow_recent: bool = False) -> list[Finding]:
    findings = []

    # Fetch package metadata from PyPI JSON API (no code executed)
    url = f"https://pypi.org/pypi/{package}/json"
    data = api_get(url)
    if not data:
        findings.append(Finding(ERROR, "registry", f"Could not fetch {package} from PyPI. Check the package name."))
        return findings

    info = data.get("info", {})
    releases = data.get("releases", {})
    all_versions = list(releases.keys())

    # Resolve version
    if version is None:
        version = info.get("version", "")
    if version not in releases:
        findings.append(Finding(ERROR, "version", f"Version {version} not found on PyPI."))
        return findings

    # ── Check 1: Package age ──
    version_files = releases.get(version, [])
    if version_files:
        upload_time_str = version_files[0].get("upload_time_iso_8601") or version_files[0].get("upload_time")
        if upload_time_str:
            try:
                upload_time = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
                age = datetime.now(timezone.utc) - upload_time
                if age.days < MIN_PACKAGE_AGE_DAYS:
                    if allow_recent:
                        findings.append(Finding(WARN, "version-age",
                            f"Version {version} was published {age.days}d {age.seconds//3600}h ago. "
                            f"Age check bypassed via --allow-recent. All other checks still apply."))
                    else:
                        # Check if this is a security patch for the previous version
                        prev_version = _get_previous_version(all_versions, version)
                        if prev_version and _is_security_patch(package, version, prev_version, "PyPI"):
                            findings.append(Finding(WARN, "version-age",
                                f"Version {version} was published {age.days}d {age.seconds//3600}h ago "
                                f"but appears to be a security patch "
                                f"(prior version {prev_version} has known vulnerabilities). "
                                f"Proceed with caution."))
                        else:
                            findings.append(Finding(FAIL, "version-age",
                                f"Version {version} was published {age.days}d {age.seconds//3600}h ago. "
                                f"Minimum age policy: {MIN_PACKAGE_AGE_DAYS} days. "
                                f"This is the #1 signal for supply chain attacks (see: LiteLLM, March 2026)."))
                else:
                    findings.append(Finding(PASS, "version-age", f"Version {version} is {age.days} days old."))
            except (ValueError, TypeError):
                findings.append(Finding(WARN, "version-age", "Could not parse upload timestamp."))

    # ── Check 2: Overall package age ──
    first_version = all_versions[0] if all_versions else None
    if first_version and releases.get(first_version):
        first_files = releases[first_version]
        if first_files:
            first_upload = first_files[0].get("upload_time_iso_8601") or first_files[0].get("upload_time")
            if first_upload:
                try:
                    first_time = datetime.fromisoformat(first_upload.replace("Z", "+00:00"))
                    pkg_age = datetime.now(timezone.utc) - first_time
                    if pkg_age.days < 30:
                        findings.append(Finding(WARN, "package-age",
                            f"Package first published {pkg_age.days} days ago. New packages carry higher risk."))
                except (ValueError, TypeError):
                    pass

    # ── Check 3: GitHub release verification ──
    project_urls = info.get("project_urls") or {}
    home_page = info.get("home_page", "") or ""
    github_url = None
    for url_val in list(project_urls.values()) + [home_page]:
        if url_val and "github.com" in url_val:
            github_url = url_val
            break

    if github_url:
        # Extract owner/repo
        parts = github_url.rstrip("/").split("github.com/")
        if len(parts) == 2:
            repo_path = parts[1].split("/")
            if len(repo_path) >= 2:
                owner, repo = repo_path[0], repo_path[1]
                tags_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/tags"
                tags_data = api_get(tags_url)
                if tags_data and isinstance(tags_data, list):
                    tag_names = [t.get("ref", "").split("/")[-1] for t in tags_data]
                    # Check common tag patterns: v1.26.0, 1.26.0, release-1.26.0
                    version_tags = [f"v{version}", version, f"release-{version}", f"v.{version}"]
                    if any(t in tag_names for t in version_tags):
                        findings.append(Finding(PASS, "github-tag", f"Version {version} has a matching GitHub tag."))
                    else:
                        findings.append(Finding(FAIL, "github-tag",
                            f"Version {version} has NO matching GitHub tag in {owner}/{repo}. "
                            f"The LiteLLM attack published directly to PyPI without a GitHub release. "
                            f"This is a critical red flag."))
                elif tags_data and isinstance(tags_data, dict) and tags_data.get("message"):
                    findings.append(Finding(WARN, "github-tag", f"Could not fetch GitHub tags: {tags_data.get('message')}"))
                else:
                    findings.append(Finding(WARN, "github-tag", "Could not fetch GitHub tags (rate limited or private repo)."))
    else:
        findings.append(Finding(WARN, "github-tag", "No GitHub repository URL found in package metadata."))

    # ── Check 4: OSV vulnerability check ──
    vulns = query_osv(package, version, "PyPI")
    if vulns is None:
        findings.append(Finding(WARN, "vulnerabilities", "Could not query OSV vulnerability database."))
    elif vulns:
        vuln_ids = [v.get("id", "unknown") for v in vulns[:5]]
        findings.append(Finding(FAIL, "vulnerabilities",
            f"Found {len(vulns)} known vulnerability(ies): {', '.join(vuln_ids)}"))
    else:
        findings.append(Finding(PASS, "vulnerabilities", "No known vulnerabilities in OSV database."))

    # ── Check 5: Maintainer / metadata signals ──
    if not info.get("author") and not info.get("author_email") and not info.get("maintainer"):
        findings.append(Finding(WARN, "metadata", "No author or maintainer information in package metadata."))

    if not info.get("summary") and not info.get("description"):
        findings.append(Finding(WARN, "metadata", "No description or summary. Placeholder packages often lack these."))

    # ── Check 6: Install hooks / .pth files (check distribution files) ──
    for file_info in version_files:
        filename = file_info.get("filename", "")
        if filename.endswith(".egg"):
            findings.append(Finding(WARN, "distribution", f"Egg distribution detected ({filename}). Prefer wheels."))

    # ── Check 7: Yanked version ──
    for file_info in version_files:
        if file_info.get("yanked"):
            findings.append(Finding(FAIL, "yanked",
                f"Version {version} has been YANKED from PyPI. Reason: {file_info.get('yanked_reason', 'not specified')}"))
            break

    return findings


# ── npm Checks ─────────────────────────────────────────────────────────────

def vet_npm(package: str, version: Optional[str] = None, allow_recent: bool = False) -> list[Finding]:
    findings = []

    # Fetch package metadata from npm registry (no code executed)
    url = f"https://registry.npmjs.org/{package}"
    data = api_get(url)
    if not data:
        findings.append(Finding(ERROR, "registry", f"Could not fetch {package} from npm. Check the package name."))
        return findings

    versions = data.get("versions", {})
    dist_tags = data.get("dist-tags", {})
    time_info = data.get("time", {})

    # Resolve version
    if version is None:
        version = dist_tags.get("latest", "")
    if version not in versions:
        findings.append(Finding(ERROR, "version", f"Version {version} not found on npm."))
        return findings

    version_data = versions[version]

    # Build a chronologically-ordered version list from time_info
    # (npm time dict includes "created" and "modified" keys — filter those out)
    npm_versions_by_time = sorted(
        [v for v in time_info if v in versions],
        key=lambda v: time_info[v]
    )

    # ── Check 1: Version age ──
    version_time = time_info.get(version)
    if version_time:
        try:
            publish_time = datetime.fromisoformat(version_time.replace("Z", "+00:00"))
            age = datetime.now(timezone.utc) - publish_time
            if age.days < MIN_PACKAGE_AGE_DAYS:
                if allow_recent:
                    findings.append(Finding(WARN, "version-age",
                        f"Version {version} was published {age.days}d {age.seconds//3600}h ago. "
                        f"Age check bypassed via --allow-recent. All other checks still apply."))
                else:
                    prev_version = _get_previous_version(npm_versions_by_time, version)
                    if prev_version and _is_security_patch(package, version, prev_version, "npm"):
                        findings.append(Finding(WARN, "version-age",
                            f"Version {version} was published {age.days}d {age.seconds//3600}h ago "
                            f"but appears to be a security patch "
                            f"(prior version {prev_version} has known vulnerabilities). "
                            f"Proceed with caution."))
                    else:
                        findings.append(Finding(FAIL, "version-age",
                            f"Version {version} was published {age.days}d {age.seconds//3600}h ago. "
                            f"Minimum age policy: {MIN_PACKAGE_AGE_DAYS} days."))
            else:
                findings.append(Finding(PASS, "version-age", f"Version {version} is {age.days} days old."))
        except (ValueError, TypeError):
            findings.append(Finding(WARN, "version-age", "Could not parse publish timestamp."))

    # ── Check 2: Package age ──
    created = time_info.get("created")
    if created:
        try:
            created_time = datetime.fromisoformat(created.replace("Z", "+00:00"))
            pkg_age = datetime.now(timezone.utc) - created_time
            if pkg_age.days < 30:
                findings.append(Finding(WARN, "package-age",
                    f"Package first published {pkg_age.days} days ago. New packages carry higher risk."))
        except (ValueError, TypeError):
            pass

    # ── Check 3: Install scripts ──
    scripts = version_data.get("scripts", {})
    dangerous_hooks = ["preinstall", "postinstall", "install", "preuninstall", "postuninstall"]
    found_hooks = [h for h in dangerous_hooks if h in scripts]
    if found_hooks:
        findings.append(Finding(WARN, "install-scripts",
            f"Package has lifecycle scripts that execute on install: {', '.join(found_hooks)}. "
            f"These run arbitrary code during installation. Common in packages with native binaries, "
            f"but also the primary vector for npm supply chain attacks. Inspect if unfamiliar."))
    else:
        findings.append(Finding(PASS, "install-scripts", "No install lifecycle scripts detected."))

    # ── Check 4: OSV vulnerability check ──
    vulns = query_osv(package, version, "npm")
    if vulns is None:
        findings.append(Finding(WARN, "vulnerabilities", "Could not query OSV vulnerability database."))
    elif vulns:
        vuln_ids = [v.get("id", "unknown") for v in vulns[:5]]
        findings.append(Finding(FAIL, "vulnerabilities",
            f"Found {len(vulns)} known vulnerability(ies): {', '.join(vuln_ids)}"))
    else:
        findings.append(Finding(PASS, "vulnerabilities", "No known vulnerabilities in OSV database."))

    # ── Check 5: GitHub release verification ──
    repo_info = data.get("repository", {})
    repo_url = repo_info.get("url", "") if isinstance(repo_info, dict) else str(repo_info)
    github_url = None
    if "github.com" in repo_url:
        github_url = repo_url.replace("git+", "").replace("git://", "https://").replace(".git", "")

    if github_url:
        parts = github_url.rstrip("/").split("github.com/")
        if len(parts) == 2:
            repo_path = parts[1].split("/")
            if len(repo_path) >= 2:
                owner, repo = repo_path[0], repo_path[1]
                tags_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/tags"
                tags_data = api_get(tags_url)
                if tags_data and isinstance(tags_data, list):
                    tag_names = [t.get("ref", "").split("/")[-1] for t in tags_data]
                    version_tags = [f"v{version}", version]
                    if any(t in tag_names for t in version_tags):
                        findings.append(Finding(PASS, "github-tag", f"Version {version} has a matching GitHub tag."))
                    else:
                        findings.append(Finding(FAIL, "github-tag",
                            f"Version {version} has NO matching GitHub tag in {owner}/{repo}. "
                            f"This may indicate the version was published outside the normal release process."))
                else:
                    findings.append(Finding(WARN, "github-tag", "Could not verify GitHub tags (rate limited or private repo)."))
    else:
        findings.append(Finding(WARN, "github-tag", "No GitHub repository URL found in package metadata."))

    # ── Check 6: Maintainer count ──
    maintainers = data.get("maintainers", [])
    if len(maintainers) == 1:
        findings.append(Finding(WARN, "maintainers",
            f"Only 1 maintainer ({maintainers[0].get('name', 'unknown')}). "
            f"Single-maintainer packages are higher risk for account takeover."))
    elif len(maintainers) == 0:
        findings.append(Finding(WARN, "maintainers", "No maintainer information available."))

    # ── Check 7: Deprecated ──
    if version_data.get("deprecated"):
        findings.append(Finding(FAIL, "deprecated",
            f"Version {version} is DEPRECATED: {version_data.get('deprecated')}"))

    return findings


# ── Requirements file parsing ──────────────────────────────────────────────

def parse_requirements_txt(path: str) -> list[tuple[str, Optional[str], str]]:
    """Parse requirements.txt, return list of (name, version, ecosystem)."""
    packages = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if "==" in line:
                name, ver = line.split("==", 1)
                packages.append((name.strip(), ver.strip(), "pypi"))
            elif ">=" in line:
                name = line.split(">=")[0].strip()
                packages.append((name, None, "pypi"))
            else:
                packages.append((line.split("[")[0].strip(), None, "pypi"))
    return packages


def parse_package_json(path: str) -> list[tuple[str, Optional[str], str]]:
    """Parse package.json, return list of (name, version, ecosystem)."""
    packages = []
    with open(path) as f:
        data = json.load(f)
    for dep_key in ["dependencies", "devDependencies"]:
        deps = data.get(dep_key, {})
        for name, ver_spec in deps.items():
            # Strip ^, ~, >= prefixes to get base version
            ver = ver_spec.lstrip("^~>=<! ")
            if ver and ver[0].isdigit():
                packages.append((name, ver, "npm"))
            else:
                packages.append((name, None, "npm"))
    return packages


# ── Main ───────────────────────────────────────────────────────────────────

def print_report(package: str, version: Optional[str], ecosystem: str, findings: list[Finding]):
    max_severity = max((f.severity for f in findings), default=PASS)
    color = SEVERITY_COLORS.get(max_severity, "")
    label = SEVERITY_LABELS.get(max_severity, "???")

    ver_str = f"=={version}" if version else " (latest)"
    eco_str = ecosystem.upper()

    print(f"\n{'─' * 60}")
    print(f"  {eco_str}  {package}{ver_str}")
    print(f"  Verdict: {color}{label}{RESET}")
    print(f"{'─' * 60}")

    for f in sorted(findings, key=lambda x: -x.severity):
        print(f)
    print()

    return max_severity


def detect_ecosystem(package: str) -> str:
    """Guess ecosystem from package name patterns."""
    if package.startswith("@") or "/" in package:
        return "npm"
    # Try PyPI first
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vet-package/1.0"}, method="HEAD")
        with urllib.request.urlopen(req, timeout=5, context=_ssl_ctx):
            return "pypi"
    except Exception:
        pass
    # Try npm
    url = f"https://registry.npmjs.org/{package}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vet-package/1.0"}, method="HEAD")
        with urllib.request.urlopen(req, timeout=5, context=_ssl_ctx):
            return "npm"
    except Exception:
        pass
    return "pypi"  # default


def main():
    parser = argparse.ArgumentParser(
        description="Vet packages for security signals BEFORE installing.",
        epilog="This tool queries registry APIs only. No package code is downloaded or executed."
    )
    parser.add_argument("packages", nargs="*", help="Package(s) to vet (e.g., 'mcp==1.26.0', 'express@4.18.2')")
    parser.add_argument("--ecosystem", "-e", choices=["pypi", "npm"], help="Force ecosystem (auto-detected if omitted)")
    parser.add_argument("-r", "--requirements", help="Path to requirements.txt or package.json")
    parser.add_argument("--min-age", type=int, default=MIN_PACKAGE_AGE_DAYS,
                        help=f"Minimum version age in days (default: {MIN_PACKAGE_AGE_DAYS})")
    parser.add_argument("--allow-recent", action="store_true",
                        help="Bypass the version age check (still runs all other checks). "
                             "Use when you need to install a known-good recent release urgently.")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.min_age != MIN_PACKAGE_AGE_DAYS:
        # Update module-level config
        _update_min_age(args.min_age)

    packages_to_vet = []

    # Parse requirements file
    if args.requirements:
        path = args.requirements
        if path.endswith(".json"):
            packages_to_vet = parse_package_json(path)
        else:
            packages_to_vet = parse_requirements_txt(path)
    
    # Parse CLI arguments
    for pkg_str in (args.packages or []):
        if "==" in pkg_str:
            name, ver = pkg_str.split("==", 1)
            eco = args.ecosystem or detect_ecosystem(name)
            packages_to_vet.append((name, ver, eco))
        elif "@" in pkg_str and not pkg_str.startswith("@"):
            name, ver = pkg_str.rsplit("@", 1)
            packages_to_vet.append((name, ver, args.ecosystem or "npm"))
        else:
            eco = args.ecosystem or detect_ecosystem(pkg_str)
            packages_to_vet.append((pkg_str, None, eco))

    if not packages_to_vet:
        parser.print_help()
        sys.exit(0)

    # Run vetting
    allow_recent = args.allow_recent
    worst_severity = PASS
    for name, version, ecosystem in packages_to_vet:
        if ecosystem == "pypi":
            findings = vet_pypi(name, version, allow_recent=allow_recent)
        else:
            findings = vet_npm(name, version, allow_recent=allow_recent)

        severity = print_report(name, version, ecosystem, findings)
        worst_severity = max(worst_severity, severity)

    # Summary
    total = len(packages_to_vet)
    print(f"{'═' * 60}")
    color = SEVERITY_COLORS.get(worst_severity, "")
    label = SEVERITY_LABELS.get(worst_severity, "???")
    print(f"  Vetted {total} package(s). Overall: {color}{label}{RESET}")

    if worst_severity >= FAIL:
        print(f"\n  {SEVERITY_COLORS[FAIL]}⛔ One or more packages FAILED vetting.{RESET}")
        print(f"  Do NOT install without careful manual review.")
    elif worst_severity >= WARN:
        print(f"\n  {SEVERITY_COLORS[WARN]}⚠  Warnings detected. Review before installing.{RESET}")
    else:
        print(f"\n  {SEVERITY_COLORS[PASS]}✓  All packages passed vetting.{RESET}")

    print(f"{'═' * 60}\n")
    sys.exit(worst_severity)


if __name__ == "__main__":
    main()
