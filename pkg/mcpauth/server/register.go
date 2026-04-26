package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth/store"
	"go.uber.org/zap"
)

// registerRequest is the RFC 7591 DCR request body subset we accept. We
// deliberately ignore unknown fields — clients sending extra hints (e.g.
// software_id, contacts) shouldn't be rejected on that alone.
type registerRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// registerResponse is the response shape we emit on successful registration.
type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// handleRegister implements RFC 7591 Dynamic Client Registration. Open
// (unauthenticated) — that is the point of DCR for MCP.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeRegisterError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON body")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeRegisterError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			writeRegisterError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	clientID, err := newClientID()
	if err != nil {
		s.Logger.Error("mcpauth/register: gen client id",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeRegisterError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	now := s.now().UTC()
	if err := s.Store.CreateClient(r.Context(), store.OAuthClient{
		ClientID:     clientID,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    now,
	}); err != nil {
		s.Logger.Error("mcpauth/register: persist client",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeRegisterError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(registerResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        now.Unix(),
		RedirectURIs:            req.RedirectURIs,
		ClientName:              req.ClientName,
		TokenEndpointAuthMethod: "none",
	})
	mcpauth.IncMetric(mcpauth.MetricDCRRegistrationsTotal)
}

// validateRedirectURI accepts only https or http://localhost (or 127.0.0.1)
// per current MCP guidance for public clients.
func validateRedirectURI(raw string) error {
	if raw == "" {
		return errors.New("empty redirect URI")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return errors.New("redirect URI must use https or http://localhost")
}

// newClientID returns "mcp_client_" + 16 random bytes (base64url, no padding).
func newClientID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "mcp_client_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// writeRegisterError emits an RFC 7591-flavored error JSON body.
func writeRegisterError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	_ = json.NewEncoder(w).Encode(body)
}
