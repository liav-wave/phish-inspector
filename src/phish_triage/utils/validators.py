"""Shared input validation for tools — SSRF-safe IP and URL checks."""

import ipaddress
from urllib.parse import urlparse


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP (in any notation) is private/loopback/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return False


def validate_url(url: str) -> str | None:
    """Validate URL for external scanning. Returns error message or None if valid."""
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


def validate_ip(ip_str: str) -> str | None:
    """Validate IP for external lookups. Returns error message or None if valid."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Invalid IP address format"
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        return "Refusing to check private/loopback/reserved IP"
    return None
