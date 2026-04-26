package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth/store"
	"go.uber.org/zap"
)

// tokenResponse is the OAuth 2.1 token endpoint response shape we emit.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// handleToken implements POST /token for grant_type=authorization_code (Phase
// 5). The refresh_token grant lands in Phase 6 — we surface a clear error for
// it here rather than silently returning invalid_grant.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTokenError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "could not parse body")
		return
	}

	grantType := r.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		// Reserved for Phase 6. Avoid leaking that we know about it via
		// invalid_grant; "unsupported_grant_type" is the correct OAuth code.
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type",
			"refresh_token grant is not yet implemented")
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type",
			"unsupported grant_type")
	}
}

func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	form := r.Form
	rawCode := form.Get("code")
	redirectURI := form.Get("redirect_uri")
	clientID := form.Get("client_id")
	codeVerifier := form.Get("code_verifier")
	resource := form.Get("resource")

	if rawCode == "" || redirectURI == "" || clientID == "" || codeVerifier == "" || resource == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request",
			"code, redirect_uri, client_id, code_verifier, resource are all required")
		return
	}

	authz, err := s.Store.ConsumeAuthzCode(r.Context(), mcpauth.HashToken(rawCode))
	if err != nil {
		s.Logger.Warn("mcpauth/token: code consume failed",
			zap.String("context", "http"),
			zap.Error(err),
		)
		// Whether missing, already-consumed, or anything else, the OAuth
		// answer is the same: invalid_grant.
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "code is invalid or already used")
		return
	}

	if authz.ExpiresAt.Before(s.now()) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "code expired")
		return
	}
	if authz.ClientID != clientID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}
	if authz.RedirectURI != redirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if authz.Resource != resource {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "resource mismatch")
		return
	}
	if !mcpauth.ValidatePKCE(authz.CodeChallenge, codeVerifier) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verifier mismatch")
		return
	}

	rawAccess, accessHash, err := mcpauth.NewOpaqueToken(mcpauth.MCPTokenPrefix)
	if err != nil {
		s.Logger.Error("mcpauth/token: gen access token",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	tok := store.Token{
		TokenHash:            accessHash,
		ClientID:             clientID,
		SlackTeamID:          authz.SlackTeamID,
		SlackUserID:          authz.SlackUserID,
		SlackAccessTokenEnc:  authz.SlackAccessTokenEnc,
		SlackRefreshTokenEnc: authz.SlackRefreshTokenEnc,
		SlackScope:           authz.SlackScope,
		ExpiresAt:            s.now().Add(s.AccessTTL),
	}
	if err := s.Store.CreateToken(r.Context(), tok); err != nil {
		s.Logger.Error("mcpauth/token: persist token",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	resp := tokenResponse{
		AccessToken: rawAccess,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.AccessTTL.Seconds()),
		Scope:       authz.SlackScope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	_ = json.NewEncoder(w).Encode(body)
}

// trimBearer strips a "Bearer " prefix from an Authorization header value.
// Exposed via package-internal helper to keep the middleware compact.
func trimBearer(s string) string {
	const p = "Bearer "
	if strings.HasPrefix(s, p) {
		return strings.TrimPrefix(s, p)
	}
	return ""
}
