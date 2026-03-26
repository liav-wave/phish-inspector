"""Tests for DNS lookup tool."""

from unittest.mock import patch, MagicMock

import pytest
import dns.resolver
import dns.exception

from phish_triage.tools.dns_lookup import dns_lookup, _query


class FakeRdata:
    def __init__(self, value):
        self._value = value
    def __str__(self):
        return self._value


class FakeAnswer:
    def __init__(self, values):
        self._values = [FakeRdata(v) for v in values]
    def __iter__(self):
        return iter(self._values)


def _mock_resolve(results_map):
    """Create a mock resolver that returns predefined results."""
    def resolver(domain, rdtype):
        key = f"{domain}/{rdtype}"
        if key in results_map:
            return FakeAnswer(results_map[key])
        raise dns.resolver.NoAnswer()
    return resolver


async def test_dns_lookup_with_mail_config():
    results = {
        "example.com/MX": ["10 mail.example.com."],
        "example.com/TXT": ['"v=spf1 include:_spf.google.com ~all"'],
        "_dmarc.example.com/TXT": ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'],
        "example.com/A": ["93.184.216.34"],
        "example.com/NS": ["ns1.example.com.", "ns2.example.com."],
    }
    with patch("phish_triage.tools.dns_lookup._query") as mock_q:
        def side_effect(domain, rdtype):
            key = f"{domain}/{rdtype}"
            if key in results:
                return [r.strip('"') for r in results[key]]
            return []
        mock_q.side_effect = side_effect

        result = await dns_lookup("example.com")

    assert result["has_mail_config"] is True
    assert result["mx_records"][0]["host"] == "mail.example.com"
    assert "v=spf1" in result["spf_record"]
    assert "v=DMARC1" in result["dmarc_record"]


async def test_dns_lookup_no_mail_config():
    with patch("phish_triage.tools.dns_lookup._query", return_value=[]):
        result = await dns_lookup("no-mail.example.com")

    assert result["has_mail_config"] is False
    assert result["mx_records"] == []
    assert result["spf_record"] is None
    assert result["dmarc_record"] is None


async def test_dns_lookup_with_dkim_selector():
    results = {}
    def side_effect(domain, rdtype):
        if domain == "selector1._domainkey.example.com" and rdtype == "TXT":
            return ['"v=DKIM1; k=rsa; p=MIGfMA0G..."']
        return []

    with patch("phish_triage.tools.dns_lookup._query", side_effect=side_effect):
        result = await dns_lookup("example.com", dkim_selector="selector1")

    assert result["dkim_record"] is not None
    assert "v=DKIM1" in result["dkim_record"]
    assert result["dkim_query"] == "selector1._domainkey.example.com"


async def test_dns_lookup_no_dkim_selector():
    with patch("phish_triage.tools.dns_lookup._query", return_value=[]):
        result = await dns_lookup("example.com")

    assert result["dkim_record"] is None
    assert "dkim_note" in result


async def test_dns_nxdomain_handling():
    """NXDOMAIN should return empty results, not errors."""
    def raise_nxdomain(domain, rdtype):
        raise dns.resolver.NXDOMAIN()

    with patch("dns.resolver.Resolver.resolve", side_effect=raise_nxdomain):
        records = _query("nonexistent.example.com", "A")

    assert records == []


async def test_dns_timeout_handling():
    """Timeouts should return empty results, not errors."""
    def raise_timeout(domain, rdtype):
        raise dns.exception.Timeout()

    with patch("dns.resolver.Resolver.resolve", side_effect=raise_timeout):
        records = _query("slow.example.com", "A")

    assert records == []
