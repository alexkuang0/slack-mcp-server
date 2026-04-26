package server

import (
	"encoding/json"
	"net/http"
)

// scopesSupported is the static list of MCP scopes this AS advertises. We do
// not actually gate any tool by these today; the client uses them only to
// satisfy spec discovery.
var scopesSupported = []string{"mcp"}

// handleProtectedResourceMetadata serves RFC 9728 metadata. The MCP client
// hits this first to discover which AS to use.
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := map[string]any{
		"resource":                 s.resourceURI(),
		"authorization_servers":    []string{s.Issuer},
		"scopes_supported":         scopesSupported,
		"bearer_methods_supported": []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(body)
}

// handleAuthorizationServerMetadata serves RFC 8414 AS metadata.
func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := map[string]any{
		"issuer":                                s.Issuer,
		"authorization_endpoint":                s.Issuer + "/authorize",
		"token_endpoint":                        s.Issuer + "/token",
		"registration_endpoint":                 s.Issuer + "/register",
		"revocation_endpoint":                   s.Issuer + "/revoke",
		"code_challenge_methods_supported":      []string{"S256"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"response_types_supported":              []string{"code"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      scopesSupported,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(body)
}
