package server

import (
	"errors"
	"net/http"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth/store"
	"go.uber.org/zap"
)

// handleRevoke implements RFC 7009 OAuth 2.0 Token Revocation.
//
// Per spec we always return 200, even when the token is unknown, malformed,
// or already revoked. This prevents an attacker from probing the AS to
// enumerate valid tokens.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTokenError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		// RFC 7009: invalid_request is the only legitimate non-200 response.
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "could not parse body")
		return
	}

	tokenRaw := r.Form.Get("token")
	hint := r.Form.Get("token_type_hint")

	// Always increment the counter — this is a "request was made" signal,
	// not an "outcome" signal.
	mcpauth.IncMetric(mcpauth.MetricTokensRevokedTotal)

	if tokenRaw == "" {
		// RFC 7009: still 200 for missing token to avoid enumeration.
		s.writeRevokeOK(w)
		return
	}

	hash := mcpauth.HashToken(tokenRaw)

	// Resolve the access-token row. We need to delete by access-token hash
	// (RevokeToken does that) so for a refresh-token revocation we look up
	// via LookupByRefresh first to find the parent row's TokenHash.
	var accessHash string
	if hint == "refresh_token" {
		if t, err := s.Store.LookupByRefresh(r.Context(), hash); err == nil {
			accessHash = t.TokenHash
		} else if t, err := s.Store.LookupToken(r.Context(), hash); err == nil {
			accessHash = t.TokenHash
		}
	} else {
		if t, err := s.Store.LookupToken(r.Context(), hash); err == nil {
			accessHash = t.TokenHash
		} else if t, err := s.Store.LookupByRefresh(r.Context(), hash); err == nil {
			accessHash = t.TokenHash
		}
	}

	if accessHash == "" {
		// Unknown / already-revoked token: still 200.
		s.writeRevokeOK(w)
		return
	}

	if err := s.Store.RevokeToken(r.Context(), accessHash); err != nil && !errors.Is(err, store.ErrTokenNotFound) {
		s.Logger.Warn("mcpauth/revoke: delete failed",
			zap.String("context", "http"),
			zap.Error(err),
		)
		// Still 200 per RFC 7009 — internal failure shouldn't leak token
		// existence; we logged the issue server-side.
	}
	s.writeRevokeOK(w)
}

func (s *Server) writeRevokeOK(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}
