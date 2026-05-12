"""Shared input validation for tools — SSRF-safe IP and URL checks."""

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlparse


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP (in any notation) is private/loopback/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return False


def validate_url(url: str) -> str | None:
    """Cheap synchronous URL validation: scheme + literal-IP-private check.

    Does NOT resolve DNS. For use sites that actually fetch the URL, follow up
    with `validate_url_with_dns()` to defeat the trivial SSRF where an
    attacker-controlled domain resolves to a private/internal address.
    """
    if not url.startswith(("http://", "https://")):
        return "URL must start with http:// or https://"
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if is_private_ip(hostname):
            return "Refusing to scan private/loopback address"
        if hostname.lower() in ("localhost", "localhost.localdomain"):
            return "Refusing to scan localhost"
    except Exception:
        return "Invalid URL"
    return None


def _resolve_hostname(hostname: str) -> list[str]:
    """Return all IP strings the hostname resolves to (A and AAAA).

    Module-level so tests can patch it without monkey-patching socket.
    Empty list means the hostname did not resolve.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


async def validate_url_with_dns(url: str) -> str | None:
    """Run `validate_url`, then resolve the hostname and reject if any
    returned address is private/loopback/reserved/link-local.

    Mitigates the dominant SSRF vector: an attacker-registered domain whose
    A record points at GCE metadata (169.254.169.254), the host LAN, or
    similar internal infrastructure.

    Does NOT mitigate DNS rebinding (TTL=0 with answer changing across the
    validate-time and connect-time resolutions). The connect-time resolution
    inside httpx is independent. Mitigate rebinding at the network layer:
    VPC egress rules on Cloud Run, or host firewall on laptops where the
    deployment surface warrants it. See `wip/cloud-run/SECURITY-DEBT.md`.
    """
    sync_error = validate_url(url)
    if sync_error:
        return sync_error

    hostname = (urlparse(url).hostname or "").strip()
    if not hostname:
        return "URL has no hostname"

    # If the hostname is already a literal IP, validate_url has already
    # covered the private-range check.
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    addrs = await asyncio.to_thread(_resolve_hostname, hostname)
    if not addrs:
        return f"Could not resolve hostname: {hostname}"
    for addr in addrs:
        if is_private_ip(addr):
            return (
                f"Refusing to connect: {hostname} resolves to {addr} "
                f"(private/loopback/reserved)"
            )
    return None


def validate_ip(ip_str: str) -> str | None:
    """Validate IP for external lookups. Returns error message or None if valid."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Invalid IP address format"
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        return "Refusing to check private/loopback/reserved IP"
    return None


# Conservative DNS-name pattern: ASCII letters, digits, hyphens, dots, and
# underscores only (DKIM selectors use underscores per RFC 6376; underscores
# are also tolerated in some real-world subdomains). Maximum 253 chars per
# RFC 1035. Used to keep adversary-controlled strings from a phishing email
# from being concatenated into a WHOIS socket payload or DNS query name with
# unexpected bytes (CR/LF, spaces, NULs, etc.).
_DOMAIN_LABEL_RE = re.compile(r'^[A-Za-z0-9._-]{1,253}$')

# A single non-empty label between dots may not start or end with a hyphen
# and must contain at least one alphanumeric. Per-label cap is 63 chars
# (RFC 1035). Used for the stricter `validate_domain_strict` variant.
_STRICT_LABEL_RE = re.compile(r'^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$')


def validate_domain_name(name: str) -> str | None:
    """Conservative syntactic check for DNS names and DKIM selectors.

    Returns an error string if the name contains characters outside the
    allowed set, is empty, or exceeds RFC 1035 length. Use at boundaries
    where the input came from email headers and will be passed to dnspython
    or python-whois, both of which accept bytes that should never reach a
    network protocol.

    This is the loose form: it accepts DKIM selectors like `s1` (no dot) and
    rejects only the unambiguous junk. For lookups that *must* be a real
    multi-label domain (WHOIS, VT/GSB indicator checks), use
    `validate_domain_strict` instead.
    """
    if not name or not isinstance(name, str):
        return "Empty or non-string domain"
    if not _DOMAIN_LABEL_RE.match(name):
        return "Invalid characters in domain/selector"
    return None


def validate_domain_strict(name: str) -> str | None:
    """Stricter domain check for callers that must pass a real multi-label
    domain to a provider API (WHOIS, VirusTotal, Google Safe Browsing).

    On top of `validate_domain_name`'s character/length filter, this rejects:
      - leading or trailing dot
      - consecutive dots
      - single-label names (no dot)
      - labels that start or end with a hyphen
      - labels longer than 63 chars

    Pure IP literals are also rejected here — callers wanting IP-or-domain
    should dispatch on type first.
    """
    base = validate_domain_name(name)
    if base:
        return base
    if name.startswith(".") or name.endswith("."):
        return "Domain must not start or end with a dot"
    if ".." in name:
        return "Domain must not contain consecutive dots"
    labels = name.split(".")
    if len(labels) < 2:
        return "Domain must have at least two labels"
    for label in labels:
        if not _STRICT_LABEL_RE.match(label):
            return f"Invalid domain label: {label!r}"
    # Reject all-numeric final label (looks like an IP, not a domain).
    if labels[-1].isdigit():
        return "Domain TLD must not be all-numeric"
    return None
