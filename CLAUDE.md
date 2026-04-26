# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & test commands

All workflows go through the Makefile (Go 1.24.4, module `github.com/korotovsky/slack-mcp-server`).

- `make build` — clean, tidy, format, then build `./build/slack-mcp-server` from `cmd/slack-mcp-server`. Injects version/commit/build-time via `-ldflags` into `pkg/version`.
- `make build-all-platforms` — cross-compile for `darwin/linux/windows × amd64/arm64`.
- `make test` — runs **only unit tests**: `go test -count=1 -v -run=".*Unit.*" ./...`
- `make test-integration` — runs **only integration tests**: `go test -count=1 -v -run=".*Integration.*" ./...`
- `make format` / `make tidy` / `make deps` / `make clean`

### Test naming convention is load-bearing

The Make targets filter by name regex, so test functions **must** be named `TestUnit*` or `TestIntegration*` to run via `make test` / `make test-integration`. A plain `TestFoo` will be skipped by both targets but will run with a bare `go test ./...`. Some existing tests (e.g. `TestSlackErrorStringUnmarshal`, `TestCallWithRetry_*`, cache tests in `pkg/provider`) do not follow the convention and only run via direct `go test`.

### Running a single test

```bash
go test -v -run TestUnitParseFlexibleDate ./pkg/handler/...
```

### Integration tests require live credentials

`pkg/handler/*_test.go` `TestIntegration*` boot a real MCP server, expose it through ngrok, and drive it with OpenAI. They require these env vars (set in the GH Actions workflow `.github/workflows/integration-tests.yaml`):
- `SLACK_MCP_OPENAI_API` — OpenAI API key
- `SLACK_MCP_XOXP_TOKEN` — real Slack user OAuth token
- `NGROK_AUTH_TOKEN`

Helpers live in `pkg/test/util/` (`mcp.go`, `ngrok.go`).

## Run locally

```bash
# stdio (default) — for MCP clients like Claude Desktop
./build/slack-mcp-server

# SSE on :13080 (override with SLACK_MCP_HOST/SLACK_MCP_PORT)
./build/slack-mcp-server -t sse

# Streamable HTTP on /mcp
./build/slack-mcp-server -t http
```

Authentication: set **one** of `SLACK_MCP_XOXP_TOKEN` (user OAuth), `SLACK_MCP_XOXB_TOKEN` (bot — limited), or both `SLACK_MCP_XOXC_TOKEN` + `SLACK_MCP_XOXD_TOKEN` (browser session). The string `"demo"` puts the server in offline mode (skips cache warm-up). See README for the full env var matrix.

Docker: `docker-compose.yml` (prebuilt image), `docker-compose.dev.yml` (live build with `dlv` on `:40000`).

## Architecture

### Entry point and transports — `cmd/slack-mcp-server/main.go`

Reads `-t/--transport` (`stdio` | `sse` | `http`) and `-e/--enabled-tools`, builds a `*zap.Logger` (JSON in containers, console with colors on a TTY), constructs `provider.ApiProvider`, then `server.NewMCPServer`. For `stdio` it blocks until `provider.IsReady()` so the LLM never sees an empty cache; for `sse`/`http` it starts serving immediately and warms caches in the background via `newUsersWatcher` / `newChannelsWatcher`.

### Tool registration & gating — `pkg/server/server.go`

`NewMCPServer` is the single source of truth for which MCP tools and resources are exposed. Every tool goes through `shouldAddTool(name, enabledTools, envVar)`:

- Read-only tools (`conversations_history`, `conversations_replies`, `channels_list`, `users_search`, `usergroups_list`, …) — `envVar == ""`, registered by default.
- **Write/destructive tools** are gated by a dedicated env var **or** by being explicitly listed in `SLACK_MCP_ENABLED_TOOLS`:
  - `conversations_add_message` ↔ `SLACK_MCP_ADD_MESSAGE_TOOL` (also accepts `!`-prefixed channel-ID denylists; mixing allow/deny errors at startup via `validateToolConfig`)
  - `reactions_add` / `reactions_remove` ↔ `SLACK_MCP_REACTION_TOOL`
  - `attachment_get_data` ↔ `SLACK_MCP_ATTACHMENT_TOOL`
  - `conversations_mark` ↔ `SLACK_MCP_MARK_TOOL`
- **Bot-token-incompatible tools** are skipped when `provider.IsBotToken()` is true — `conversations_search_messages` (bot tokens can't call `search.messages`) and `conversations_unreads` (no unread tracking).

Every tool handler is wrapped by three middleware layers:
1. `auth.BuildMiddleware` — bearer-token check for SSE/HTTP (no-op on stdio); reads `SLACK_MCP_API_KEY` (or deprecated `SLACK_MCP_SSE_API_KEY`).
2. `buildLoggerMiddleware` — request/duration logging.
3. `buildErrorRecoveryMiddleware` — converts handler errors into `mcp.NewToolResultError` with `isError=true` instead of letting them surface as JSON-RPC `-32603` protocol errors that crash MCP clients. **Do not bypass this** when adding new handlers; return errors normally.

When adding a new tool: add the constant to `ToolXxx`/`ValidToolNames`, register it in `NewMCPServer`, and (if write-capable) wire it through `shouldAddTool` with a new env var.

### Slack client layer — `pkg/provider/`

`MCPSlackClient` (in `api.go`) wraps **two** Slack clients behind one `SlackAPI` interface:

- `slack.Client` from `slack-go/slack` — the standard public API.
- `edge.Client` from `pkg/provider/edge/` — an internal Slack endpoint reverse-engineered for browser-session (`xoxc/xoxd`) tokens. Provides `client.boot`, `client.counts`, edge user search, channel listings on Enterprise Grid, etc. **This package is a partial copy of `rusq/slackdump/v3`** (see `pkg/provider/README.md`); avoid drift and keep upstream attribution if you change it.

Token mode is detected at construction time and exposed via `IsBotToken()`, `isOAuth`, `isEnterprise`. Tool dispatch and behavior (e.g. unread tracking, search) branches on these.

`edgeFailed` is a one-shot circuit breaker — once an edge call fails, subsequent code paths skip straight to the standard API instead of looping. There are tests for this in `api_edge_fallback_test.go`.

### Caches and readiness

`ApiProvider` keeps users and channels in `atomic.Pointer` snapshots so reads never copy or block. Caches persist to disk:

- Default location: `os.UserCacheDir() + "/slack-mcp-server/"` (overridable via `SLACK_MCP_USERS_CACHE` / `SLACK_MCP_CHANNELS_CACHE`).
- File names are **prefixed with `TeamID_`** (`getCachePathWithTeamID`) so multiple workspaces don't contaminate each other.
- TTL via `SLACK_MCP_CACHE_TTL` (`1h` default; `0` = never expire).
- Forced refreshes are throttled by `SLACK_MCP_MIN_REFRESH_INTERVAL` (30s default) returning `ErrRefreshRateLimited`.
- `IsReady()` returns false until both caches are populated; `stdio` mode blocks on this, SSE/HTTP modes return `ErrUsersNotReady` / `ErrChannelsNotReady` from handlers if hit early.

### HTTP transport — `pkg/transport/transport.go`

Wraps the outgoing HTTP client with:
- Custom `User-Agent` (`SLACK_MCP_USER_AGENT`) and Slack `d` cookie injection.
- Optional uTLS Chrome JA3 fingerprint when `SLACK_MCP_CUSTOM_TLS=true` (helps bypass Enterprise Slack TLS fingerprinting).
- Proxy (`SLACK_MCP_PROXY`), custom CA (`SLACK_MCP_SERVER_CA`), HTTPToolkit MitM CA (`SLACK_MCP_SERVER_CA_TOOLKIT`), insecure trust (`SLACK_MCP_SERVER_CA_INSECURE`).
- GovSlack mode (`SLACK_MCP_GOVSLACK=true`) reroutes API calls to `slack-gov.com`.

### Handlers — `pkg/handler/`

- `conversations.go` (~2300 lines) — history, replies, search, add_message, reactions, file fetch, unreads, mark, plus the `slack://<workspace>/users` directory resource and helpers like `parseFlexibleDate`, `buildDateFilters`, `limitByExpression`, `isChannelAllowedForConfig`. New conversation-shaped tools usually belong here.
- `channels.go` — `channels_list` tool and `slack://<workspace>/channels` resource.
- `usergroups.go` — list / me / create / update / users_update.
- `slack_error_test.go` defines the canonical pattern for tolerant Slack error JSON unmarshaling (Slack's `error` field is sometimes a string, sometimes an object).

### Output format

Most list/search responses are CSV via `gocarina/gocsv` (the LLM-friendly format the README documents). Single messages can be JSON. The `cursor` value in conversation responses is **the value of the last row's `Cursor` column** — handlers reuse the row to encode pagination.

## Conventions

- Logging: always `zap` with structured fields. Use `zap.String("context", "console")` for startup/lifecycle logs and `zap.String("context", "http")` for request-scoped logs (the existing convention).
- Errors that should reach the LLM: return them from the handler — middleware will wrap into `isError` results. Do not call `mcp.NewToolResultError` directly unless you also need to short-circuit middleware.
- Test names: `TestUnit*` / `TestIntegration*` if you want them picked up by `make test` / `make test-integration`.
- Build artifacts: never commit `./build/`, `./npm/*/bin/`, or generated `.npmrc` files (covered by `make clean`).
- Don't change `manifest-dxt.json` or files under `npm/` casually — they drive the DXT extension and npm publishing pipeline (`make build-dxt`, `make npm-publish`).

## Useful docs

- `docs/01-authentication-setup.md` — extracting `xoxc`/`xoxd` from a browser; OAuth app setup.
- `docs/02-installation.md` — install via npm, DXT, Docker.
- `docs/03-configuration-and-usage.md` — wiring into Claude Desktop / clients.
- `SECURITY.md` — disclosure policy.
