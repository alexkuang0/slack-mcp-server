// Package server implements the MCP-spec OAuth Authorization Server endpoints
// in front of Slack: well-known metadata (RFC 8414, RFC 9728), Dynamic Client
// Registration (RFC 7591), the authorize/callback/token flow with PKCE
// (RFC 7636) and audience binding (RFC 8707), and a bearer-token middleware
// that resolves opaque MCP tokens to a per-tenant context.
//
// The handlers are intentionally framework-free: net/http only, so they can
// be mounted onto any *http.ServeMux next to the streamable-HTTP /mcp handler.
package server

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth/store"
	"github.com/korotovsky/slack-mcp-server/pkg/provider"
	"go.uber.org/zap"
)

// Default TTLs. Operators can override via the Server struct fields.
const (
	defaultAccessTTL    = 1 * time.Hour
	defaultAuthzCodeTTL = 60 * time.Second
	defaultRefreshTTL   = 30 * 24 * time.Hour
	pendingAuthzTTL     = 10 * time.Minute
	gcSweepInterval     = 1 * time.Minute
)

// Server is the central OAuth AS handler set. It is constructed once at
// startup and mounted onto an *http.ServeMux via Mount.
//
// All exported fields are read-only after Mount; the goroutine started by
// Mount only reads them.
type Server struct {
	Logger     *zap.Logger
	Store      store.Storage
	Crypto     *mcpauth.Crypto
	SlackOAuth *mcpauth.SlackOAuthConfig
	Factory    provider.Factory

	// Issuer is the canonical https URL of THIS server (e.g.
	// https://mcp.example.com). It is the base for the resource URI
	// (Issuer + "/mcp") and AS metadata document URIs.
	Issuer string

	// AccessTTL controls how long minted MCP access tokens live. Default 1h.
	AccessTTL time.Duration
	// AuthzCodeTTL controls how long authorization codes live. Default 60s.
	AuthzCodeTTL time.Duration
	// RefreshTTL controls refresh-token lifetime. Used in Phase 6.
	RefreshTTL time.Duration

	// NowFn is overridden in tests for deterministic expiry. Defaults to
	// time.Now.
	NowFn func() time.Time

	// gc lifecycle.
	gcOnce  sync.Once
	stopCh  chan struct{}
	stopped sync.Once
}

// Mount registers all OAuth AS endpoints and the bearer-protected /mcp handler
// on mux. The MCP streamable-HTTP handler must be passed in so we can wrap it
// with the bearer middleware. Mount also starts a background goroutine that
// periodically GCs expired authorization codes.
func (s *Server) Mount(mux *http.ServeMux, mcpHandler http.Handler) {
	s.applyDefaults()

	mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth/slack/callback", s.handleSlackCallback)
	mux.HandleFunc("/token", s.handleToken)
	mux.Handle("/mcp", s.bearerMiddleware(mcpHandler))

	s.startGCOnce()
}

// Close stops the GC goroutine started by Mount. Safe to call multiple times.
func (s *Server) Close() {
	s.stopped.Do(func() {
		if s.stopCh != nil {
			close(s.stopCh)
		}
	})
}

func (s *Server) applyDefaults() {
	if s.Logger == nil {
		s.Logger = zap.NewNop()
	}
	if s.AccessTTL <= 0 {
		s.AccessTTL = defaultAccessTTL
	}
	if s.AuthzCodeTTL <= 0 {
		s.AuthzCodeTTL = defaultAuthzCodeTTL
	}
	if s.RefreshTTL <= 0 {
		s.RefreshTTL = defaultRefreshTTL
	}
	if s.NowFn == nil {
		s.NowFn = time.Now
	}
	s.Issuer = strings.TrimRight(s.Issuer, "/")
	if s.stopCh == nil {
		s.stopCh = make(chan struct{})
	}
}

func (s *Server) now() time.Time { return s.NowFn() }

func (s *Server) resourceURI() string { return s.Issuer + "/mcp" }

func (s *Server) startGCOnce() {
	s.gcOnce.Do(func() {
		go s.gcLoop()
	})
}

func (s *Server) gcLoop() {
	t := time.NewTicker(gcSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.runGC()
		}
	}
}

func (s *Server) runGC() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if n, err := s.Store.GCExpiredAuthzCodes(ctx); err != nil {
		s.Logger.Warn("mcpauth: gc authz codes failed",
			zap.String("context", "http"),
			zap.Error(err),
		)
	} else if n > 0 {
		s.Logger.Debug("mcpauth: gc authz codes",
			zap.String("context", "http"),
			zap.Int("removed", n),
		)
	}
}
