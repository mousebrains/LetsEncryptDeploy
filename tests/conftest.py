"""Shared fixtures for deploy hook tests."""

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_env():
    """Snapshot and restore os.environ around every test."""
    old_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(old_env)


@pytest.fixture
def cert_dir(tmp_path):
    """Create a fake letsencrypt live directory with dummy cert and key."""
    hostname = "test.example.com"
    live_dir = tmp_path / "live" / hostname
    live_dir.mkdir(parents=True)
    (live_dir / "fullchain.pem").write_text("FAKE CERT DATA\n")
    (live_dir / "privkey.pem").write_text("FAKE KEY DATA\n")
    return live_dir


@pytest.fixture
def env_vars(cert_dir):
    """Set RENEWED_DOMAINS and RENEWED_LINEAGE env vars for testing."""
    hostname = cert_dir.name
    os.environ["RENEWED_DOMAINS"] = hostname
    os.environ["RENEWED_LINEAGE"] = str(cert_dir)
    return hostname


@pytest.fixture
def config_file(tmp_path):
    """Create a JSON config file with test credentials."""
    cfg = tmp_path / "test-config.json"
    cfg.write_text('{"admin_user": "admin", "admin_password": "testpass123"}')
    return cfg


@pytest.fixture
def clean_env():
    """Ensure RENEWED_* env vars are not set."""
    os.environ.pop("RENEWED_DOMAINS", None)
    os.environ.pop("RENEWED_LINEAGE", None)
