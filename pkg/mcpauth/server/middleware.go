package server

import (
	"encoding/json"
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
