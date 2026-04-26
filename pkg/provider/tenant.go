package provider

import (
	"context"

	"github.com/rusq/slackdump/v3/auth"
)

// TenantContext identifies a single Slack user/team scope for a request.
// In legacy single-tenant mode, the factory returns the same singleton regardless of tenant —
// callers can pass the zero value.
type TenantContext struct {
	TeamID       string
	UserID       string
	SlackToken   string        // xoxp/xoxb/xoxc; required in OAuth mode
	AuthProvider auth.Provider // can be nil; legacy path constructs its own
}

type tenantCtxKey struct{}

// WithTenant returns a new context that carries the given TenantContext.
// Multi-tenant transports (Phase 5+) attach this to each request after
// authenticating; handlers retrieve it via TenantFromContext / ProviderFromContext.
func WithTenant(ctx context.Context, t TenantContext) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, t)
}

// TenantFromContext extracts the TenantContext attached by WithTenant.
// Returns the zero value and ok=false in legacy single-tenant mode where no
// tenant has been attached.
func TenantFromContext(ctx context.Context) (TenantContext, bool) {
	t, ok := ctx.Value(tenantCtxKey{}).(TenantContext)
	return t, ok
}
