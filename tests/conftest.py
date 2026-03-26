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
