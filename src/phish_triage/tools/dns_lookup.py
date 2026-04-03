"""DNS record lookup for mail authentication and domain legitimacy checks."""

import asyncio

import dns.resolver
import dns.exception

from phish_triage.utils.errors import sanitize_error


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
        if record_types is None:
            record_types = ["MX", "TXT", "A", "NS"]

        result: dict = {"domain": domain}

        # MX records
        if "MX" in record_types:
            mx_raw = await _aquery(domain, "MX")
            mx_records = []
            for r in mx_raw:
                parts = r.split()
                if len(parts) >= 2:
                    mx_records.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
            result["mx_records"] = mx_records

        # TXT records (includes SPF)
        spf_record = None
        if "TXT" in record_types:
            txt_raw = await _aquery(domain, "TXT")
            txt_records = [r.strip('"') for r in txt_raw]
            for txt in txt_records:
                if txt.lower().startswith("v=spf1"):
                    spf_record = txt
                    break
            result["spf_record"] = spf_record

        # DMARC (always query _dmarc.{domain})
        dmarc_raw = await _aquery(f"_dmarc.{domain}", "TXT")
        dmarc_record = None
        for r in dmarc_raw:
            cleaned = r.strip('"')
            if cleaned.lower().startswith("v=dmarc1"):
                dmarc_record = cleaned
                break
        result["dmarc_record"] = dmarc_record

        # DKIM (requires selector)
        if dkim_selector:
            dkim_domain = f"{dkim_selector}._domainkey.{domain}"
            dkim_raw = await _aquery(dkim_domain, "TXT")
            result["dkim_record"] = dkim_raw[0].strip('"') if dkim_raw else None
            result["dkim_query"] = dkim_domain
        else:
            result["dkim_record"] = None
            result["dkim_note"] = "DKIM verification requires a selector from the email headers. Pass dkim_selector if available."

        # A records
        if "A" in record_types:
            result["a_records"] = await _aquery(domain, "A")

        # NS records
        if "NS" in record_types:
            ns_raw = await _aquery(domain, "NS")
            result["ns_records"] = [r.rstrip(".") for r in ns_raw]

        # Summary flag
        has_mx = bool(result.get("mx_records"))
        has_spf = spf_record is not None
        has_dmarc = dmarc_record is not None
        result["has_mail_config"] = has_mx and (has_spf or has_dmarc)

        return result
    except Exception as e:
        return {"error": "DNS lookup failed", "detail": sanitize_error(e), "domain": domain}
