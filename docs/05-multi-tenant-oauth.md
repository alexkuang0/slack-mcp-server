### 5. Multi-tenant OAuth with Dynamic Client Registration

This document describes how to deploy the Slack MCP Server in **multi-tenant OAuth mode**: a single shared deployment where each end-user authenticates against your Slack OAuth app and the server stores per-user Slack credentials encrypted at rest. MCP clients (Claude Desktop, mcp-inspector, Cursor, ...) discover the authorization server, register themselves dynamically (RFC 7591), and get a per-user MCP token they can use against `/mcp`.

## Overview

| Mode | When to use it | Doc |
| --- | --- | --- |
| Single-user (legacy) | One person, one workspace, run locally with `xoxc`/`xoxd`/`xoxp`/`xoxb` | [01-authentication-setup.md](01-authentication-setup.md) |
| Multi-tenant OAuth | Multiple users on a team, SaaS, shared remote deployment | this document |

In multi-tenant mode the server runs as a full [MCP-spec OAuth Authorization Server](https://modelcontextprotocol.io/specification/draft/basic/authorization) with:

- RFC 8414 authorization-server metadata (`/.well-known/oauth-authorization-server`)
- RFC 9728 protected-resource metadata (`/.well-known/oauth-protected-resource`)
- RFC 7591 Dynamic Client Registration (`/register`)
- RFC 7636 PKCE (S256 only)
- RFC 8707 audience-restricted tokens (the `resource` parameter)
- RFC 7009 token revocation (`/revoke`)
- Bearer-token-protected `/mcp` endpoint

The server bridges its own OAuth flow to Slack's `oauth.v2.access` so that **the MCP client never sees the user's Slack token**. It only sees the server-issued opaque MCP token; the Slack `xoxp`/`xoxb` is stored AES-GCM-encrypted in SQLite.

The server boots in multi-tenant OAuth mode automatically when **none** of the legacy `SLACK_MCP_XOXP_TOKEN` / `SLACK_MCP_XOXB_TOKEN` / `SLACK_MCP_XOXC_TOKEN` + `SLACK_MCP_XOXD_TOKEN` env vars are set. Setting any of those switches the server back to single-user mode and the OAuth endpoints below are not registered.

## Prerequisites

### A public HTTPS-reachable host with a domain you control

The MCP OAuth spec mandates HTTPS for issuer URLs. The `docker-compose.oauth.yml` bundle uses [Caddy](https://caddyserver.com/) for automatic Let's Encrypt provisioning, but you can substitute any reverse proxy that terminates TLS in front of port `13080`.

### A Slack OAuth app

1. Visit [api.slack.com/apps](https://api.slack.com/apps) and click **Create New App** -> **From scratch**.
2. Pick a name and a development workspace. (You can distribute the app later if you want it to work across workspaces.)
3. In the left sidebar, go to **OAuth & Permissions**.
4. Under **Redirect URLs**, click **Add New Redirect URL** and enter `<ISSUER>/oauth/slack/callback`, where `<ISSUER>` is your public HTTPS URL (for example `https://mcp.example.com/oauth/slack/callback`). Slack requires HTTPS. Click **Save URLs**.
5. Under **Scopes -> User Token Scopes**, add the scopes the MCP tools need:
    - `channels:history` — read messages in public channels
    - `channels:read` — read public channel metadata
    - `groups:history` — read messages in private channels
    - `groups:read` — read private channel metadata
    - `im:history` — read direct messages
    - `im:read` — read DM metadata
    - `im:write` — start DMs on the user's behalf
    - `mpim:history` — read group DMs
    - `mpim:read` — read group DM metadata
    - `mpim:write` — start group DMs
    - `users:read` — read workspace membership (drives the users cache)
    - `chat:write` — post messages on the user's behalf (only needed if you enable `conversations_add_message`)
    - `search:read` — search workspace content (drives `conversations_search_messages`)
    - `usergroups:read` — list user groups
    - `usergroups:write` — create/manage user groups
6. Optionally, under **Scopes -> Bot Token Scopes**, add bot scopes if you want the deployment to also receive a bot token (needed for some Enterprise Grid setups).
7. Click **Install to Workspace** at the top of the page (you only need to install once for development; production users will install via the OAuth flow).
8. Back on **Basic Information**, copy the **Client ID** and **Client Secret**. You'll set these as `SLACK_MCP_OAUTH_CLIENT_ID` and `SLACK_MCP_OAUTH_CLIENT_SECRET`.

### A 32-byte master key for AES-GCM at-rest encryption

The server refuses to boot in OAuth mode without one. Generate it with:

```bash
head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '='
```

Store the result in `SLACK_MCP_OAUTH_MASTER_KEY`. **If you lose this key, all stored Slack tokens become unrecoverable** and every user has to re-authorize.

## Quick start with docker-compose

```bash
cp .env.oauth.example .env.oauth
# Edit .env.oauth and set: ISSUER, DOMAIN, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, MASTER_KEY
docker-compose -f docker-compose.oauth.yml up -d

# Verify the AS metadata endpoint
curl https://mcp.example.com/.well-known/oauth-authorization-server
```

You should get a JSON document listing the issuer, authorization/token/registration endpoints, supported PKCE methods (`S256`), and so on. If you don't, check `docker-compose -f docker-compose.oauth.yml logs caddy mcp-server`.

The compose stack:

- runs the MCP server on the internal `oauth-tier` network (no port exposed to the host)
- mounts a named `oauth_data` volume to `/data` for the SQLite database
- runs Caddy as the public HTTPS terminator on `:80` and `:443`, auto-provisioning a cert for `$SLACK_MCP_DOMAIN`
- proxies all paths to `mcp-server:13080`

## Connecting Claude Desktop

1. In Claude Desktop, open **Settings -> Connectors -> Add Custom Connector**.
2. Set the URL to `https://mcp.example.com/mcp` (your `<ISSUER>/mcp`).
3. Claude will:
   - fetch `/.well-known/oauth-protected-resource` to discover the AS,
   - fetch `/.well-known/oauth-authorization-server` to discover endpoints,
   - register itself dynamically via `POST /register` (RFC 7591),
   - open a browser to `/authorize` and start the auth-code + PKCE flow,
   - bounce the user through Slack's OAuth screen,
   - exchange the resulting code at `/token`,
   - and call `/mcp` with the resulting Bearer token.
4. After the OAuth dance completes, the MCP tools should be listed and available.

The token is bound to the resource indicator `<ISSUER>/mcp` per RFC 8707; tokens issued for a different resource will be rejected.

## Connecting other MCP clients

### mcp-inspector

```bash
npx @modelcontextprotocol/inspector https://mcp.example.com/mcp
```

The inspector implements DCR + PKCE; it will trigger the same browser-based Slack OAuth flow as Claude Desktop.

### Cursor

Cursor's MCP integration follows the same protocol. Add a custom MCP server with URL `https://mcp.example.com/mcp`; the editor will run DCR and PKCE automatically.

## Operations

### Backup the SQLite database

```bash
docker run --rm \
  -v slack-mcp-server_oauth_data:/data \
  alpine tar -czf - /data > backup.tar.gz
```

Restore by extracting back into the same named volume on a fresh stack. The DB contains encrypted Slack tokens; the master key is **not** stored alongside, so a backup without the key is useless to an attacker.

### Rotate the master key

**SECURITY WARNING: rotating the master key invalidates every stored Slack token. All users will be forced to re-authorize.** There is no online migration path because the old ciphertext is unreadable without the old key.

To rotate:

1. Generate a new key (see Prerequisites above).
2. Update `SLACK_MCP_OAUTH_MASTER_KEY` in `.env.oauth`.
3. Wipe the OAuth tokens and codes:
   ```bash
   docker-compose -f docker-compose.oauth.yml exec mcp-server \
     sqlite3 /data/oauth.db 'DELETE FROM oauth_tokens; DELETE FROM oauth_codes;'
   ```
4. `docker-compose -f docker-compose.oauth.yml restart mcp-server`.
5. Notify users that they need to re-authorize on their next request.

Keep the old key on hand until you have confirmed all clients have re-authorized; reverting requires both DB and key from the same generation.

### Revoke a single user's session

Two paths:

- **Client-side (preferred, RFC 7009)**: the user's MCP client can hit `/revoke` with their token:
  ```bash
  curl -X POST https://mcp.example.com/revoke -d "token=<their_mcp_token>"
  ```
- **Admin-side**: drop the row directly. The user will hit `401` on their next `/mcp` call and the client will trigger a fresh OAuth flow.
  ```bash
  docker-compose -f docker-compose.oauth.yml exec mcp-server \
    sqlite3 /data/oauth.db "DELETE FROM oauth_tokens WHERE slack_user_id='U01234567';"
  ```

### Metrics

Set `SLACK_MCP_OAUTH_METRICS=true` in `.env.oauth` and restart. The server exposes process and request counters under `/metrics` (expvar). The endpoint is **unauthenticated** — do not expose it on the public internet. If you need it, add a Caddy rule that restricts `/metrics` to your VPC CIDR, or scrape it via the internal Docker network instead of through Caddy.

## Endpoints reference

| Path | Method | Auth | Spec | Description |
| --- | --- | --- | --- | --- |
| `/healthz` | GET | none | (custom) | Liveness probe. Returns 200 + version JSON. |
| `/.well-known/oauth-protected-resource` | GET | none | RFC 9728 | Tells MCP clients which AS to trust for `/mcp`. |
| `/.well-known/oauth-authorization-server` | GET | none | RFC 8414 | Lists `/authorize`, `/token`, `/register`, `/revoke`, supported PKCE/algs. |
| `/register` | POST | none | RFC 7591 | Dynamic Client Registration. Returns `client_id`. |
| `/authorize` | GET | browser session | RFC 6749 + RFC 7636 + RFC 8707 | Auth-code endpoint. Validates `resource`, kicks off Slack OAuth, redirects back with a code. |
| `/oauth/slack/callback` | GET | (Slack-driven) | (internal) | Slack returns here after the user consents. The server exchanges the Slack code, encrypts the resulting `xoxp` token, mints an MCP code, and 302s back to the original `redirect_uri`. |
| `/token` | POST | client_id (+ PKCE verifier) | RFC 6749 | Auth-code and refresh-token grants. Issues MCP access tokens. |
| `/revoke` | POST | client_id | RFC 7009 | Revokes an MCP token. Always returns 200 per the spec. |
| `/mcp` | POST | Bearer | (MCP) | Streamable HTTP MCP transport. Bearer must be a valid MCP access token whose audience matches `<ISSUER>/mcp`. |

## Troubleshooting

- **`400 invalid_target` from `/authorize`** — the MCP client's `resource` parameter doesn't match `<ISSUER>/mcp`. Make sure `SLACK_MCP_OAUTH_ISSUER` exactly matches the public HTTPS URL the client is configured with (no trailing slash, correct host, correct scheme). The resource parameter is RFC 8707 audience binding; the server rejects mismatches to prevent token confusion.
- **`400 invalid_grant` on `/token`** — either the PKCE `code_verifier` doesn't match the original `code_challenge`, or the auth code has expired (TTL is 60 seconds). Re-run the authorize flow.
- **`401` on `/mcp`** — the access token is expired, has been revoked, or was issued for a different resource. Most clients will detect this and re-run the OAuth flow automatically.
- **Slack returns `redirect_uri did not match any configured URIs`** — `SLACK_MCP_OAUTH_REDIRECT_URI` must **exactly** match the value configured in your Slack app's OAuth settings (scheme, host, path). Pasting from a different env (e.g. dev vs prod) is the usual cause.
- **`SLACK_MCP_OAUTH_MASTER_KEY is required in OAuth mode`** at startup — the server detected that no legacy token env vars are set (so it picked OAuth mode) but no master key is provided. Either set the master key or set a legacy token env var to fall back to single-user mode.
- **Caddy can't get a TLS cert** — make sure the `$SLACK_MCP_DOMAIN` resolves to the host running the stack and that ports `:80` and `:443` are open to the public internet so the ACME HTTP-01 challenge can succeed.

See also: [01-authentication-setup.md](01-authentication-setup.md) for single-user mode, [02-installation.md](02-installation.md) for non-Docker installs, [03-configuration-and-usage.md](03-configuration-and-usage.md) for the full env-var reference.
