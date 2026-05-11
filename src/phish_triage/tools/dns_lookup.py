"""DNS record lookup for mail authentication and domain legitimacy checks."""

import asyncio

import dns.resolver
import dns.exception

from phish_triage.utils.errors import sanitize_error
from phish_triage.utils.validators import validate_domain_name


TIMEOUT = 5.0  # seconds per query


def _query(domain: str, rdtype: str) -> list[str]:
    """Query DNS with timeout, returning list of string results.

    NOTE: This is a blocking call — always invoke via asyncio.to_thread().
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        answers = resolver.resolve(domain, rdtype)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return []
    except Exception:
        return []


async def _aquery(domain: str, rdtype: str) -> list[str]:
    """Async wrapper around blocking DNS query."""
    return await asyncio.to_thread(_query, domain, rdtype)


async def dns_lookup(domain: str, record_types: list[str] | None = None, dkim_selector: str | None = None) -> dict:
    """Query DNS records for a domain to check mail auth configuration and legitimacy.

    Args:
        domain: Domain to query.
        record_types: Record types to query. Default: ["MX", "TXT", "A", "NS"].
        dkim_selector: DKIM selector from email headers. If provided, queries the DKIM DNS record.

    Returns:
        Structured DNS data including MX, SPF, DMARC, DKIM, and nameserver information.
    """
    try:
        domain_error = validate_domain_name(domain)
        if domain_error:
            return {
                "error": "invalid_input",
                "detail": domain_error,
                "untrusted_input": {"domain": domain},
            }
        if dkim_selector is not None:
            selector_error = validate_domain_name(dkim_selector)
            if selector_error:
                return {
                    "error": "invalid_input",
                    "detail": f"DKIM selector: {selector_error}",
                    "untrusted_input": {"domain": domain, "dkim_selector": dkim_selector},
                }

        if record_types is None:
            record_types = ["MX", "TXT", "A", "NS"]

        # DNS response data — comes from authoritative servers, which for a
        # phisher-owned domain are attacker-controlled. Wrap accordingly.
        api: dict = {}

        # MX records
        if "MX" in record_types:
            mx_raw = await _aquery(domain, "MX")
            mx_records = []
            for r in mx_raw:
                parts = r.split()
                if len(parts) >= 2:
                    mx_records.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
            api["mx_records"] = mx_records

        # TXT records (includes SPF)
        spf_record = None
        if "TXT" in record_types:
            txt_raw = await _aquery(domain, "TXT")
            txt_records = [r.strip('"') for r in txt_raw]
            for txt in txt_records:
                if txt.lower().startswith("v=spf1"):
                    spf_record = txt
                    break
            api["spf_record"] = spf_record

        # DMARC (always query _dmarc.{domain})
        dmarc_raw = await _aquery(f"_dmarc.{domain}", "TXT")
        dmarc_record = None
        for r in dmarc_raw:
            cleaned = r.strip('"')
            if cleaned.lower().startswith("v=dmarc1"):
                dmarc_record = cleaned
                break
        api["dmarc_record"] = dmarc_record

        # DKIM (requires selector)
        if dkim_selector:
            dkim_domain = f"{dkim_selector}._domainkey.{domain}"
            dkim_raw = await _aquery(dkim_domain, "TXT")
            api["dkim_record"] = dkim_raw[0].strip('"') if dkim_raw else None
            api["dkim_query"] = dkim_domain
        else:
            api["dkim_record"] = None
            api["dkim_note"] = "DKIM verification requires a selector from the email headers. Pass dkim_selector if available."

        # A records
        if "A" in record_types:
            api["a_records"] = await _aquery(domain, "A")

        # NS records
        if "NS" in record_types:
            ns_raw = await _aquery(domain, "NS")
            api["ns_records"] = [r.rstrip(".") for r in ns_raw]

        # Summary flag (server-computed, trusted)
        has_mx = bool(api.get("mx_records"))
        has_spf = spf_record is not None
        has_dmarc = dmarc_record is not None

        return {
            "has_mail_config": has_mx and (has_spf or has_dmarc),
            "untrusted_input": {"domain": domain, "dkim_selector": dkim_selector},
            "untrusted_api_response": api,
        }
    except Exception as e:
        return {
            "error": "DNS lookup failed",
            "detail": sanitize_error(e),
            "untrusted_input": {"domain": domain},
        }
