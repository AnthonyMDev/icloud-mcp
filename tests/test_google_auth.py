"""Google OAuth: the email allow-list, fail-closed startup, and HTTP auth policy."""

import asyncio

import pytest
from fastmcp.server.auth import AccessToken, TokenVerifier

from icloud_mcp import server
from icloud_mcp.config import config
from icloud_mcp.google_auth import EmailAllowlistVerifier, build_google_auth


class FakeVerifier(TokenVerifier):
    """Stands in for GoogleTokenVerifier: returns preset claims, or None for a bad token."""

    def __init__(self, claims):
        super().__init__(required_scopes=["openid"])
        self.claims = claims

    async def verify_token(self, token):
        if self.claims is None:
            return None
        return AccessToken(token=token, client_id="sub", scopes=["openid"], claims=self.claims)


def verify(claims, allowed=frozenset({"owner@gmail.com"})):
    return asyncio.run(EmailAllowlistVerifier(FakeVerifier(claims), allowed).verify_token("t"))


def test_allowed_verified_email_passes():
    assert verify({"email": "owner@gmail.com", "email_verified": True}) is not None


def test_email_match_is_case_insensitive():
    assert verify({"email": "Owner@Gmail.com", "email_verified": True}) is not None


def test_other_google_account_rejected():
    assert verify({"email": "stranger@gmail.com", "email_verified": True}) is None


def test_lookalike_addresses_rejected():
    for email in ["owner@gmail.com.evil.com", "xowner@gmail.com", "owner@gmail.co", "owner@gmail.com "]:
        result = verify({"email": email, "email_verified": True})
        # Trailing whitespace is normalised; everything else must fail.
        assert (result is not None) == (email.strip() == "owner@gmail.com"), email


def test_unverified_email_rejected():
    assert verify({"email": "owner@gmail.com", "email_verified": False}) is None
    assert verify({"email": "owner@gmail.com"}) is None


def test_missing_email_rejected():
    assert verify({"email_verified": True}) is None
    assert verify({"email": None, "email_verified": True}) is None


def test_invalid_upstream_token_rejected():
    assert verify(None) is None


def test_empty_allowlist_refused():
    with pytest.raises(ValueError):
        EmailAllowlistVerifier(FakeVerifier({}), frozenset())


GOOD = dict(
    client_id="123.apps.googleusercontent.com",
    client_secret="GOCSPX-test-secret-value",
    public_url="https://home-server.example.ts.net",
    allowed_emails=frozenset({"owner@gmail.com"}),
    allowed_client_redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
    jwt_signing_key="a-long-test-signing-key-for-jwts",
)


def test_provider_installs_allowlist(tmp_path, monkeypatch):
    monkeypatch.setenv("FASTMCP_HOME", str(tmp_path))
    provider = build_google_auth(**GOOD)
    assert isinstance(provider._token_validator, EmailAllowlistVerifier)
    assert provider._token_validator.allowed_emails == {"owner@gmail.com"}


@pytest.mark.parametrize("missing", ["client_id", "client_secret", "public_url"])
def test_provider_requires_settings(missing):
    with pytest.raises(ValueError, match="missing required settings"):
        build_google_auth(**{**GOOD, missing: None})


def test_provider_requires_allowlist():
    with pytest.raises(ValueError, match="MCP_ALLOWED_EMAILS"):
        build_google_auth(**{**GOOD, "allowed_emails": frozenset()})


def test_provider_requires_https():
    with pytest.raises(ValueError, match="https"):
        build_google_auth(**{**GOOD, "public_url": "http://home-server.example.ts.net"})


def test_http_refuses_to_start_without_auth(monkeypatch):
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", None)
    monkeypatch.setattr(config, "MCP_AUTH_TOKEN", None)
    monkeypatch.setattr(config, "ALLOW_UNAUTHENTICATED", False)
    with pytest.raises(SystemExit, match="Refusing to serve HTTP without authentication"):
        server._http_credential_policy()


def test_google_and_static_token_are_exclusive(monkeypatch):
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "x")
    monkeypatch.setattr(config, "MCP_AUTH_TOKEN", "y")
    with pytest.raises(SystemExit, match="not both"):
        server._http_credential_policy()


def test_default_bind_host_is_loopback():
    import os
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items() if k != "MCP_SERVER_HOST"}
    out = subprocess.run(
        [sys.executable, "-c", "from icloud_mcp.config import config; print(config.MCP_SERVER_HOST)"],
        env=env, capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == "127.0.0.1"
