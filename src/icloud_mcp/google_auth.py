"""Google OAuth for the HTTP transport, restricted to an allow-list of email addresses.

claude.ai custom connectors authenticate with OAuth, not static headers. FastMCP's
GoogleProvider runs the OAuth flow, but on its own it accepts *any* Google account.
This module wraps the provider's token verifier so a request is accepted only when
Google reports a verified email that is on ``MCP_ALLOWED_EMAILS``.

Every MCP request re-validates the upstream Google token through the verifier
(see OAuthProxy.load_access_token), so the allow-list is enforced per request,
not just at login.
"""

from __future__ import annotations

import logging

from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.providers.google import GoogleProvider

logger = logging.getLogger(__name__)


class EmailAllowlistVerifier(TokenVerifier):
    """Delegate to another verifier, then require a verified, allow-listed email."""

    def __init__(self, inner: TokenVerifier, allowed_emails: frozenset[str]):
        if not allowed_emails:
            raise ValueError("EmailAllowlistVerifier needs at least one allowed email")
        super().__init__(required_scopes=inner.required_scopes)
        self.inner = inner
        self.allowed_emails = frozenset(e.strip().lower() for e in allowed_emails)

    async def verify_token(self, token: str) -> AccessToken | None:
        result = await self.inner.verify_token(token)
        if result is None:
            return None
        claims = result.claims or {}
        email = claims.get("email")
        verified = claims.get("email_verified")
        if not isinstance(email, str) or not email.strip():
            logger.warning("Rejected Google token without an email claim")
            return None
        if verified not in (True, "true", "True"):
            logger.warning("Rejected Google token with unverified email")
            return None
        if email.strip().lower() not in self.allowed_emails:
            # Log the domain only; the full address of a stranger is not ours to keep.
            logger.warning("Rejected Google account not on MCP_ALLOWED_EMAILS (domain %s)",
                           email.rsplit("@", 1)[-1])
            return None
        return result


def build_google_auth(
    *,
    client_id: str | None,
    client_secret: str | None,
    public_url: str | None,
    allowed_emails: frozenset[str],
    allowed_client_redirect_uris: list[str] | None,
    jwt_signing_key: str | None = None,
) -> GoogleProvider:
    """Create a GoogleProvider whose token verifier enforces the email allow-list.

    Fails closed: raises if any required setting is missing or the provider's
    internals have changed so the allow-list cannot be installed.
    """
    missing = [
        name
        for name, value in (
            ("MCP_GOOGLE_CLIENT_ID", client_id),
            ("MCP_GOOGLE_CLIENT_SECRET", client_secret),
            ("MCP_PUBLIC_URL", public_url),
        )
        if not value
    ]
    if not allowed_emails:
        missing.append("MCP_ALLOWED_EMAILS")
    if missing:
        raise ValueError(f"Google auth is missing required settings: {', '.join(missing)}")
    if not public_url.startswith("https://"):
        raise ValueError("MCP_PUBLIC_URL must be an https:// URL")

    provider = GoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=public_url.rstrip("/"),
        required_scopes=["openid", "email"],
        allowed_client_redirect_uris=allowed_client_redirect_uris,
        jwt_signing_key=jwt_signing_key,
    )

    inner = getattr(provider, "_token_validator", None)
    if not isinstance(inner, TokenVerifier):
        raise RuntimeError(
            "FastMCP's GoogleProvider no longer exposes _token_validator; refusing to start "
            "without the email allow-list. Re-check google_auth.py against the FastMCP version."
        )
    provider._token_validator = EmailAllowlistVerifier(inner, allowed_emails)
    return provider
