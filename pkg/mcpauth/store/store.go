// Package store defines the persistence contract for the mcpauth package.
//
// It is intentionally storage-agnostic: the SQLite implementation in this
// package is the default, but the interface allows alternative back-ends
// (e.g. Postgres, in-memory for tests) without touching the OAuth handlers.
package store

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors. Callers compare with errors.Is.
var (
	ErrClientNotFound      = errors.New("mcpauth/store: client not found")
	ErrCodeNotFound        = errors.New("mcpauth/store: authorization code not found")
	ErrCodeAlreadyConsumed = errors.New("mcpauth/store: authorization code already consumed")
	ErrTokenNotFound       = errors.New("mcpauth/store: token not found")
	ErrSlackAppNotFound    = errors.New("mcpauth/store: slack app not found")
)

// OAuthClient is a client registered via RFC 7591 Dynamic Client Registration.
type OAuthClient struct {
	ClientID         string
	ClientName       string
	RedirectURIs     []string
	ClientSecretHash []byte // nil for public clients (DCR default)
	CreatedAt        time.Time
}

// AuthzCode is a short-lived (60s) authorization code that maps a PKCE
// challenge + Slack OAuth result to the eventual MCP token exchange.
type AuthzCode struct {
	CodeHash             string // SHA-256 hex of the raw code
	ClientID             string
	RedirectURI          string
	CodeChallenge        string
	CodeChallengeMethod  string // "S256"
	Resource             string // RFC 8707 audience
	SlackTeamID          string
	SlackUserID          string
	SlackAccessTokenEnc  []byte
	SlackRefreshTokenEnc []byte
	SlackScope           string
	ExpiresAt            time.Time
	Consumed             bool
}

// Token is an MCP-issued access token (opaque "mcp_at_..." string) with
// the Slack credentials it represents stored encrypted at rest.
type Token struct {
	TokenHash            string // SHA-256 hex of the raw access token
	ClientID             string
	SlackTeamID          string
	SlackUserID          string
	SlackAccessTokenEnc  []byte
	SlackRefreshTokenEnc []byte
	SlackScope           string
	ExpiresAt            time.Time
	RefreshTokenHash     string // empty if no refresh issued
}

// SlackApp is a Slack OAuth app's client credentials. TeamID is "default"
// for single-app deployments; per-team rows enable multi-tenant install.
type SlackApp struct {
	TeamID          string
	ClientID        string
	ClientSecretEnc []byte
}

// Storage is the persistence contract used by the mcpauth package.
type Storage interface {
	// OAuth clients (RFC 7591 DCR registry).
	CreateClient(ctx context.Context, c OAuthClient) error
	GetClient(ctx context.Context, clientID string) (*OAuthClient, error)
	DeleteClient(ctx context.Context, clientID string) error

	// Authorization codes (60s TTL, single-use).
	CreateAuthzCode(ctx context.Context, code AuthzCode) error
	// ConsumeAuthzCode atomically marks the code as consumed and returns
	// the row. Returns ErrCodeNotFound if missing, ErrCodeAlreadyConsumed
	// if a previous call already consumed it.
	ConsumeAuthzCode(ctx context.Context, codeHash string) (*AuthzCode, error)
	// GCExpiredAuthzCodes deletes codes whose expires_at is in the past
	// and returns the number of rows removed.
	GCExpiredAuthzCodes(ctx context.Context) (int, error)

	// MCP access tokens.
	CreateToken(ctx context.Context, t Token) error
	// LookupToken returns ErrTokenNotFound if the token does not exist OR
	// has expired. Expiry is enforced server-side so callers cannot ride
	// stale state through clock skew.
	LookupToken(ctx context.Context, tokenHash string) (*Token, error)
	RevokeToken(ctx context.Context, tokenHash string) error
	// LookupByRefresh resolves a refresh-token hash to its parent access
	// token row. Used by the refresh_token grant.
	LookupByRefresh(ctx context.Context, refreshHash string) (*Token, error)

	// RotateRefresh atomically deletes the old token (by raw refresh hash)
	// and inserts the new one. Returns ErrTokenNotFound if the old hash is
	// absent (defends against replay). Both rows must share the same
	// client_id; the caller is responsible for that contract.
	RotateRefresh(ctx context.Context, oldRefreshHash string, newToken Token) error

	// UpdateSlackTokens replaces the encrypted Slack access/refresh tokens
	// (and scope/expiry) on an existing MCP token row identified by
	// tokenHash. Returns ErrTokenNotFound if the row does not exist.
	UpdateSlackTokens(ctx context.Context, tokenHash string, accessEnc, refreshEnc []byte, scope string, expiresAt time.Time) error

	// Slack app credentials.
	UpsertSlackApp(ctx context.Context, app SlackApp) error
	GetSlackApp(ctx context.Context, teamID string) (*SlackApp, error)
}
