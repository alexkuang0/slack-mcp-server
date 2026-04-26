package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	"github.com/korotovsky/slack-mcp-server/pkg/provider"
	"go.uber.org/zap"
)

// bearerMiddleware wraps the streamable-HTTP /mcp handler so every request
// arrives with a valid Bearer token AND a TenantContext attached to the
// request context. Unauthorized requests get 401 + RFC 9728 WWW-Authenticate.
func (s *Server) bearerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := trimBearer(r.Header.Get("Authorization"))
		if raw == "" {
			s.unauthorized(w, "missing_token", "Bearer token required")
			return
		}
		tok, err := s.Store.LookupToken(r.Context(), mcpauth.HashToken(raw))
		if err != nil {
			s.Logger.Debug("mcpauth/mw: token lookup failed",
				zap.String("context", "http"),
				zap.Error(err),
			)
			s.unauthorized(w, "invalid_token", "token is invalid or expired")
			return
		}

		slackTok, err := s.Crypto.Decrypt(tok.SlackAccessTokenEnc)
		if err != nil {
			s.Logger.Error("mcpauth/mw: decrypt slack token",
				zap.String("context", "http"),
				zap.Error(err),
			)
			s.unauthorized(w, "server_error", "internal error decrypting upstream token")
			return
		}

		tenant := provider.TenantContext{
			TeamID:     tok.SlackTeamID,
			UserID:     tok.SlackUserID,
			SlackToken: string(slackTok),
		}
		ctx := provider.WithTenant(r.Context(), tenant)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// refreshSlackTokenForToken refreshes the upstream Slack access token tied
// to the MCP token row identified by tokenHash. Wires:
//
//  1. Look up the MCP token row.
//  2. Decrypt the stored Slack refresh token.
//  3. Call SlackOAuth.RefreshToken.
//  4. Encrypt the new access/refresh tokens.
//  5. Persist via Storage.UpdateSlackTokens.
//
// Phase 6 deliberately does NOT auto-trigger this from request handlers;
// integrating it deeply with pkg/provider is out of scope. The endpoint exists
// so a future phase can plumb it in. The slack_unauthorized_total counter is
// incremented when the upstream Slack call returns invalid_auth so operators
// can alert on tenant-token rot.
func (s *Server) refreshSlackTokenForToken(ctx context.Context, tokenHash string) error {
	tok, err := s.Store.LookupToken(ctx, tokenHash)
	if err != nil {
		return err
	}
	if len(tok.SlackRefreshTokenEnc) == 0 {
		return mcpauth.ErrSlackRefreshUnsupported
	}

	refreshRaw, err := s.Crypto.Decrypt(tok.SlackRefreshTokenEnc)
	if err != nil {
		return fmt.Errorf("decrypt refresh token: %w", err)
	}

	grant, err := s.SlackOAuth.RefreshToken(ctx, string(refreshRaw))
	if err != nil {
		if errors.Is(err, mcpauth.ErrSlackAuthFailed) {
			mcpauth.IncMetric(mcpauth.MetricSlackUnauthorizedTotal)
		}
		return err
	}

	accessEnc, err := s.Crypto.Encrypt([]byte(grant.AccessToken))
	if err != nil {
		return fmt.Errorf("encrypt access token: %w", err)
	}
	var refreshEnc []byte
	if grant.RefreshToken != "" {
		refreshEnc, err = s.Crypto.Encrypt([]byte(grant.RefreshToken))
		if err != nil {
			return fmt.Errorf("encrypt refresh token: %w", err)
		}
	} else {
		// Carry forward the prior refresh token if Slack didn't issue a new
		// one; not all configurations rotate.
		refreshEnc = tok.SlackRefreshTokenEnc
	}

	scope := grant.Scope
	if scope == "" {
		scope = tok.SlackScope
	}

	return s.Store.UpdateSlackTokens(ctx, tokenHash, accessEnc, refreshEnc, scope, grant.ExpiresAt)
}

// unauthorized writes a 401 with an RFC 9728-style WWW-Authenticate header
// pointing the client at the protected-resource metadata document, plus a
// small JSON body with the OAuth error code.
func (s *Server) unauthorized(w http.ResponseWriter, code, desc string) {
	resourceMeta := s.Issuer + "/.well-known/oauth-protected-resource"
	val := fmt.Sprintf(`Bearer realm=%q, resource_metadata=%q, error=%q`,
		s.Issuer, resourceMeta, code)
	w.Header().Set("WWW-Authenticate", val)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	_ = json.NewEncoder(w).Encode(body)
}
