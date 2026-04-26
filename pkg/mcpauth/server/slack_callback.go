package server

import (
	"net/http"
	"net/url"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth/store"
	"go.uber.org/zap"
)

// handleSlackCallback receives Slack's redirect after user authorization. It
// decrypts the pending state, exchanges the upstream code for a Slack token,
// stores the AuthzCode, and 302-redirects back to the MCP client.
func (s *Server) handleSlackCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	state := q.Get("state")
	pending, err := s.decodePendingAuthz(state)
	if err != nil {
		// Without a trusted redirect_uri we cannot redirect; respond directly.
		s.Logger.Warn("mcpauth/callback: invalid state",
			zap.String("context", "http"),
			zap.Error(err),
		)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// If Slack itself returned an error (user denied, etc.), surface it to the
	// MCP client with their state preserved.
	if slackErr := q.Get("error"); slackErr != "" {
		redirectClientError(w, r, pending.RedirectURI, pending.ClientState,
			slackErr, q.Get("error_description"))
		return
	}

	code := q.Get("code")
	if code == "" {
		redirectClientError(w, r, pending.RedirectURI, pending.ClientState,
			"server_error", "missing code from Slack")
		return
	}

	grant, err := s.SlackOAuth.ExchangeCode(r.Context(), code)
	if err != nil {
		s.Logger.Error("mcpauth/callback: slack exchange",
			zap.String("context", "http"),
			zap.Error(err),
		)
		redirectClientError(w, r, pending.RedirectURI, pending.ClientState,
			"server_error", "slack token exchange failed")
		return
	}

	accessEnc, err := s.Crypto.Encrypt([]byte(grant.AccessToken))
	if err != nil {
		s.Logger.Error("mcpauth/callback: encrypt access token",
			zap.String("context", "http"),
			zap.Error(err),
		)
		redirectClientError(w, r, pending.RedirectURI, pending.ClientState,
			"server_error", "encryption failed")
		return
	}
	var refreshEnc []byte
	if grant.RefreshToken != "" {
		refreshEnc, err = s.Crypto.Encrypt([]byte(grant.RefreshToken))
		if err != nil {
			s.Logger.Error("mcpauth/callback: encrypt refresh token",
				zap.String("context", "http"),
				zap.Error(err),
			)
			redirectClientError(w, r, pending.RedirectURI, pending.ClientState,
				"server_error", "encryption failed")
			return
		}
	}

	rawCode, codeHash, err := mcpauth.NewOpaqueToken(mcpauth.MCPCodePrefix)
	if err != nil {
		redirectClientError(w, r, pending.RedirectURI, pending.ClientState,
			"server_error", "code generation failed")
		return
	}

	authz := store.AuthzCode{
		CodeHash:             codeHash,
		ClientID:             pending.ClientID,
		RedirectURI:          pending.RedirectURI,
		CodeChallenge:        pending.CodeChallenge,
		CodeChallengeMethod:  pending.CodeChallengeMethod,
		Resource:             pending.Resource,
		SlackTeamID:          grant.TeamID,
		SlackUserID:          grant.UserID,
		SlackAccessTokenEnc:  accessEnc,
		SlackRefreshTokenEnc: refreshEnc,
		SlackScope:           grant.Scope,
		ExpiresAt:            s.now().Add(s.AuthzCodeTTL),
	}
	if err := s.Store.CreateAuthzCode(r.Context(), authz); err != nil {
		s.Logger.Error("mcpauth/callback: persist authz code",
			zap.String("context", "http"),
			zap.Error(err),
		)
		redirectClientError(w, r, pending.RedirectURI, pending.ClientState,
			"server_error", "persistence failed")
		return
	}

	// Build redirect to the MCP client with the raw authz code.
	u, err := url.Parse(pending.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	cq := u.Query()
	cq.Set("code", rawCode)
	if pending.ClientState != "" {
		cq.Set("state", pending.ClientState)
	}
	u.RawQuery = cq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
