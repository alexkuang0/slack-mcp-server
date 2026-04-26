package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth/store"
	"go.uber.org/zap"
)

// tokenResponse is the OAuth 2.1 token endpoint response shape we emit.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// handleToken implements POST /token for both the authorization_code and
// refresh_token grants per OAuth 2.1.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTokenError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "could not parse body")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	grantType := r.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type",
			"unsupported grant_type")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
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
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	authz, err := s.Store.ConsumeAuthzCode(r.Context(), mcpauth.HashToken(rawCode))
	if err != nil {
		s.Logger.Warn("mcpauth/token: code consume failed",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "code is invalid or already used")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	if authz.ExpiresAt.Before(s.now()) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "code expired")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}
	if authz.ClientID != clientID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}
	if authz.RedirectURI != redirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}
	if authz.Resource != resource {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "resource mismatch")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}
	if !mcpauth.ValidatePKCE(authz.CodeChallenge, codeVerifier) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verifier mismatch")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	rawAccess, accessHash, err := mcpauth.NewOpaqueToken(mcpauth.MCPTokenPrefix)
	if err != nil {
		s.Logger.Error("mcpauth/token: gen access token",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	rawRefresh, refreshHash, err := mcpauth.NewOpaqueToken(mcpauth.MCPRefreshPrefix)
	if err != nil {
		s.Logger.Error("mcpauth/token: gen refresh token",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
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
		RefreshTokenHash:     refreshHash,
	}
	if err := s.Store.CreateToken(r.Context(), tok); err != nil {
		s.Logger.Error("mcpauth/token: persist token",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	resp := tokenResponse{
		AccessToken:  rawAccess,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.AccessTTL.Seconds()),
		RefreshToken: rawRefresh,
		Scope:        authz.SlackScope,
	}

	writeTokenJSON(w, resp)
	mcpauth.IncMetric(mcpauth.MetricTokensIssuedTotal)
}

// handleRefreshTokenGrant rotates an MCP refresh token per OAuth 2.1: the old
// refresh token is consumed (deleted) and a new (access, refresh) pair is
// issued, all in a single SQL transaction so a replay attempt sees the row
// already gone.
func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	form := r.Form
	refreshRaw := form.Get("refresh_token")
	clientID := form.Get("client_id")

	if refreshRaw == "" || clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request",
			"refresh_token and client_id are required")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	oldHash := mcpauth.HashToken(refreshRaw)
	prev, err := s.Store.LookupByRefresh(r.Context(), oldHash)
	if err != nil {
		s.Logger.Warn("mcpauth/token: refresh lookup failed",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"refresh_token is invalid or expired")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}
	if prev.ClientID != clientID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	rawAccess, accessHash, err := mcpauth.NewOpaqueToken(mcpauth.MCPTokenPrefix)
	if err != nil {
		s.Logger.Error("mcpauth/token: gen access token",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}
	rawRefresh, refreshHash, err := mcpauth.NewOpaqueToken(mcpauth.MCPRefreshPrefix)
	if err != nil {
		s.Logger.Error("mcpauth/token: gen refresh token",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	newTok := store.Token{
		TokenHash:            accessHash,
		ClientID:             prev.ClientID,
		SlackTeamID:          prev.SlackTeamID,
		SlackUserID:          prev.SlackUserID,
		SlackAccessTokenEnc:  prev.SlackAccessTokenEnc,
		SlackRefreshTokenEnc: prev.SlackRefreshTokenEnc,
		SlackScope:           prev.SlackScope,
		ExpiresAt:            s.now().Add(s.AccessTTL),
		RefreshTokenHash:     refreshHash,
	}

	if err := s.Store.RotateRefresh(r.Context(), oldHash, newTok); err != nil {
		// ErrTokenNotFound here means the row was already rotated by a concurrent
		// (or replayed) request between LookupByRefresh and RotateRefresh.
		if errors.Is(err, store.ErrTokenNotFound) {
			writeTokenError(w, http.StatusBadRequest, "invalid_grant",
				"refresh_token is invalid or already used")
			mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
			return
		}
		s.Logger.Error("mcpauth/token: rotate refresh",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "")
		mcpauth.IncMetric(mcpauth.MetricTokenGrantFailuresTotal)
		return
	}

	resp := tokenResponse{
		AccessToken:  rawAccess,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.AccessTTL.Seconds()),
		RefreshToken: rawRefresh,
		Scope:        prev.SlackScope,
	}
	writeTokenJSON(w, resp)
	mcpauth.IncMetric(mcpauth.MetricTokensRefreshedTotal)
}

func writeTokenJSON(w http.ResponseWriter, resp tokenResponse) {
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
