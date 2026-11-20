import base64

import pytest

from icloud_mcp import auth
from icloud_mcp.config import config


def test_env_fallback(monkeypatch):
    monkeypatch.setattr(auth, "_request_headers", lambda: {})
    assert auth.get_credentials() == ("tester@icloud.com", "aaaa-bbbb-cccc-dddd")


def test_headers_win_over_env(monkeypatch):
    monkeypatch.setattr(config, "ACCEPT_REQUEST_CREDENTIALS", True)
    monkeypatch.setattr(
        auth,
        "_request_headers",
        lambda: {"x-apple-email": "h@icloud.com", "x-apple-app-specific-password": "pppp qqqq"},
    )
    assert auth.get_credentials() == ("h@icloud.com", "ppppqqqq")


def test_basic_auth(monkeypatch):
    monkeypatch.setattr(config, "ACCEPT_REQUEST_CREDENTIALS", True)
    token = base64.b64encode(b"b@icloud.com:secret-pass").decode()
    monkeypatch.setattr(auth, "_request_headers", lambda: {"authorization": f"Basic {token}"})
    assert auth.get_credentials() == ("b@icloud.com", "secret-pass")


def test_missing_credentials(monkeypatch):
    monkeypatch.setattr(auth, "_request_headers", lambda: {})
    monkeypatch.setattr(config, "FALLBACK_EMAIL", None)
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", None)
    with pytest.raises(auth.AuthenticationError):
        auth.get_credentials()


def test_request_credentials_ignored_by_default(monkeypatch):
    """Single-user fork: caller-supplied Apple credentials are ignored unless opted in."""
    monkeypatch.setattr(config, "ACCEPT_REQUEST_CREDENTIALS", False)
    monkeypatch.setattr(config, "ENV_CREDENTIALS_ACTIVE", True)
    monkeypatch.setattr(config, "FALLBACK_EMAIL", "owner@icloud.com")
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", "owner-pass")
    token = base64.b64encode(b"other@icloud.com:other-pass").decode()
    monkeypatch.setattr(
        auth,
        "_request_headers",
        lambda: {
            "x-apple-email": "other@icloud.com",
            "x-apple-app-specific-password": "other-pass",
            "authorization": f"Basic {token}",
        },
    )
    assert auth.get_credentials() == ("owner@icloud.com", "owner-pass")
