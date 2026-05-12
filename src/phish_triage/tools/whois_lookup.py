"""WHOIS domain registration lookup using python-whois."""

import asyncio
from datetime import datetime, timezone

from phish_triage.utils.errors import sanitize_error
from phish_triage.utils.sanitize import clean_untrusted_string
from phish_triage.utils.validators import validate_domain_strict
from whois import whois


def _to_datetime(val) -> datetime | None:
    """Coerce various date formats to a single datetime."""
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            from dateutil import parser as dateutil_parser
            return dateutil_parser.parse(val)
        except (ValueError, TypeError):
            return None
    return None


def _days_since(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


async def whois_lookup(domain: str) -> dict:
    """Get domain registration information to assess age and legitimacy.

    Args:
        domain: Domain to query.

    Returns:
        Structured WHOIS data including registrar, dates, age, and privacy status.
    """
    try:
        domain_error = validate_domain_strict(domain)
        if domain_error:
            return {"error": "invalid_input", "detail": domain_error, "domain": domain}

        w = await asyncio.wait_for(asyncio.to_thread(whois, domain), timeout=15.0)

        creation_date = _to_datetime(w.creation_date)
        expiration_date = _to_datetime(w.expiration_date)
        updated_date = _to_datetime(w.updated_date)

        # Detect privacy protection
        registrant = w.get("org", "") or w.get("name", "") or ""
        privacy_keywords = ["privacy", "proxy", "redacted", "withheld", "not disclosed", "data protected"]
        privacy_protected = any(kw in str(registrant).lower() for kw in privacy_keywords)

        name_servers = w.name_servers or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        name_servers = [ns.lower().rstrip(".") for ns in name_servers]

        domain_age = _days_since(creation_date)

        # Dates and the privacy bool are server-computed and trusted. The
        # provider strings (registrar, country, name servers) are influenced
        # by the registrant — attacker-controlled when the domain is theirs.
        return {
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": expiration_date.isoformat() if expiration_date else None,
            "updated_date": updated_date.isoformat() if updated_date else None,
            "domain_age_days": domain_age,
            "privacy_protected": privacy_protected,
            "untrusted_input": {"domain": domain},
            "untrusted_api_response": {
                "registrar": clean_untrusted_string(w.registrar, max_len=200),
                "registrant_country": clean_untrusted_string(w.get("country"), max_len=100),
                "name_servers": sorted({clean_untrusted_string(ns, max_len=255) for ns in name_servers}),
            },
        }
    except asyncio.TimeoutError:
        return {
            "error": "timeout",
            "detail": "WHOIS lookup timed out after 15s.",
            "untrusted_input": {"domain": domain},
        }
    except Exception as e:
        return {
            "error": "WHOIS lookup failed",
            "detail": sanitize_error(e),
            "untrusted_input": {"domain": domain},
        }
