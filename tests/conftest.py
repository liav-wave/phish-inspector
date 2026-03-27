"""Shared fixtures for tests."""

import os
from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def phishing_email_1() -> str:
    return (FIXTURES_DIR / "phishing_email_1.eml").read_text()


@pytest.fixture
def phishing_email_2() -> str:
    return (FIXTURES_DIR / "phishing_email_2.eml").read_text()


@pytest.fixture
def legitimate_email() -> str:
    return (FIXTURES_DIR / "legitimate_email.eml").read_text()


@pytest.fixture
def spearphish_bec() -> str:
    return (FIXTURES_DIR / "spearphish_bec_wire_transfer.eml").read_text()


@pytest.fixture
def spearphish_oauth() -> str:
    return (FIXTURES_DIR / "spearphish_oauth_credential_harvest.eml").read_text()


@pytest.fixture
def spearphish_helpdesk() -> str:
    return (FIXTURES_DIR / "spearphish_it_helpdesk.eml").read_text()


@pytest.fixture
def spearphish_vendor() -> str:
    return (FIXTURES_DIR / "spearphish_vendor_impersonation.eml").read_text()
