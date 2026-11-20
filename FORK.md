# Fork notes

A single-user, calendar-only deployment of [mike-tih/icloud-mcp](https://github.com/mike-tih/icloud-mcp),
reachable as a claude.ai custom connector through Tailscale Funnel.

## Changes from upstream

- **Google OAuth with an email allow-list** (`src/icloud_mcp/google_auth.py`). claude.ai connectors
  authenticate with OAuth, not static headers. FastMCP's `GoogleProvider` accepts any Google
  account, so its token verifier is wrapped to require a verified email on `MCP_ALLOWED_EMAILS`.
  The upstream token is re-verified on every MCP request. Startup fails closed if the allow-list
  can't be installed.
- **OAuth client redirect URIs are restricted** to claude.ai's connector callback by default
  (`MCP_ALLOWED_CLIENT_REDIRECT_URIS`).
- **Binds to `127.0.0.1` by default.** Expose it through Funnel, not on every interface.
- **HTTP refuses to start without authentication** unless `ICLOUD_MCP_ALLOW_UNAUTHENTICATED=true`.
- **Caller-supplied iCloud credentials are ignored** (`X-Apple-*` headers, Basic auth) unless
  `ICLOUD_MCP_ACCEPT_REQUEST_CREDENTIALS=true`. Only the server's own account is served.
- **Dependencies are locked** (`uv.lock`) and the Python version is pinned (`.python-version`).

## Configuration

| Variable | Value |
|---|---|
| `ICLOUD_ENABLED_CATEGORIES` | `calendar` |
| `ICLOUD_EMAIL` / `ICLOUD_APP_SPECIFIC_PASSWORD` | the account and a dedicated app-specific password |
| `MCP_GOOGLE_CLIENT_ID` / `MCP_GOOGLE_CLIENT_SECRET` | Google Cloud OAuth client (Web application) |
| `MCP_PUBLIC_URL` | `https://<machine>.<tailnet>.ts.net` |
| `MCP_ALLOWED_EMAILS` | the owner's Google address(es), comma-separated |
| `EMAIL_SEND_ALLOWLIST` | the owner's addresses, so calendar invitations can't reach strangers |

Google OAuth client redirect URI: `https://<machine>.<tailnet>.ts.net/auth/callback`.

## Syncing upstream

```bash
git fetch upstream && git merge upstream/main && uv lock && uv run pytest
```

After any FastMCP upgrade, `tests/test_google_auth.py` must pass. It checks that the allow-list is installed.
