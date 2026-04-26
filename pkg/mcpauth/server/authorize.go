package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	"go.uber.org/zap"
)

// pendingAuthz is the opaque state we hand to Slack as the OAuth `state`
// parameter. It encodes the entire MCP authorize request so the callback can
// rebuild it without a DB row. The blob is AES-GCM encrypted with the
// server's master key, so its contents are invisible and unforgeable to
// anyone outside the process.
type pendingAuthz struct {
	ClientID            string `json:"c"`
	RedirectURI         string `json:"r"`
	CodeChallenge       string `json:"cc"`
	CodeChallengeMethod string `json:"ccm"`
	Resource            string `json:"res"`
	Scope               string `json:"sc,omitempty"`
	ClientState         string `json:"st,omitempty"`
	ExpiresAtUnix       int64  `json:"e"`
}

// handleAuthorize implements GET /authorize. It validates the request, encodes
// a pendingAuthz blob, and 302-redirects the user to Slack.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Counter increments on entry regardless of outcome — useful for spotting
	// flood patterns even when most requests get rejected.
	mcpauth.IncMetric(mcpauth.MetricAuthorizeRequestsTotal)

	q := r.URL.Query()

	if got := q.Get("response_type"); got != "code" {
		writeAuthzError(w, http.StatusBadRequest, "unsupported_response_type",
			"only response_type=code is supported")
		return
	}

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	resource := q.Get("resource")
	scope := q.Get("scope")
	clientState := q.Get("state")

	if clientID == "" {
		writeAuthzError(w, http.StatusBadRequest, "invalid_request", "missing client_id")
		return
	}
	if redirectURI == "" {
		writeAuthzError(w, http.StatusBadRequest, "invalid_request", "missing redirect_uri")
		return
	}
	if codeChallenge == "" {
		writeAuthzError(w, http.StatusBadRequest, "invalid_request", "missing code_challenge")
		return
	}
	if codeChallengeMethod != "S256" {
		writeAuthzError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
		return
	}
	if resource == "" || resource != s.resourceURI() {
		writeAuthzError(w, http.StatusBadRequest, "invalid_target",
			fmt.Sprintf("resource must equal %q", s.resourceURI()))
		return
	}

	client, err := s.Store.GetClient(r.Context(), clientID)
	if err != nil {
		s.Logger.Warn("mcpauth/authorize: unknown client",
			zap.String("context", "http"),
			zap.String("client_id", clientID),
			zap.Error(err),
		)
		writeAuthzError(w, http.StatusBadRequest, "unauthorized_client", "unknown client_id")
		return
	}
	if !redirectURIRegistered(client.RedirectURIs, redirectURI) {
		writeAuthzError(w, http.StatusBadRequest, "invalid_redirect_uri",
			"redirect_uri does not match a registered URI")
		return
	}

	pending := pendingAuthz{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Resource:            resource,
		Scope:               scope,
		ClientState:         clientState,
		ExpiresAtUnix:       s.now().Add(pendingAuthzTTL).Unix(),
	}
	state, err := s.encodePendingAuthz(pending)
	if err != nil {
		s.Logger.Error("mcpauth/authorize: encode state",
			zap.String("context", "http"),
			zap.Error(err),
		)
		writeAuthzError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	slackURL := s.SlackOAuth.AuthorizeURL(state)
	http.Redirect(w, r, slackURL, http.StatusFound)
}

// redirectURIRegistered does an exact match against the client's registered
// list. Per the MCP spec we do NOT relax this to "starts with" matching.
func redirectURIRegistered(registered []string, candidate string) bool {
	for _, u := range registered {
		if u == candidate {
			return true
		}
	}
	return false
}

func (s *Server) encodePendingAuthz(p pendingAuthz) (string, error) {
	js, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	enc, err := s.Crypto.Encrypt(js)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(enc), nil
}

func (s *Server) decodePendingAuthz(state string) (*pendingAuthz, error) {
	if state == "" {
		return nil, errors.New("empty state")
	}
	blob, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	pt, err := s.Crypto.Decrypt(blob)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	var p pendingAuthz
	if err := json.Unmarshal(pt, &p); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if time.Unix(p.ExpiresAtUnix, 0).Before(s.now()) {
		return nil, errors.New("pending authz expired")
	}
	return &p, nil
}

// writeAuthzError emits a JSON error body for /authorize. We do not redirect
// errors back to the client's redirect_uri before validating that redirect_uri
// itself: per OAuth 2.1, callers cannot rely on us to redirect bad inputs.
func writeAuthzError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	_ = json.NewEncoder(w).Encode(body)
}

// redirectClientError redirects to the client's redirect_uri with OAuth-style
// error query params. Used by the Slack callback when a downstream step fails
// after we've validated the client (so we have a trusted redirect_uri).
func redirectClientError(w http.ResponseWriter, r *http.Request, redirectURI, clientState, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if clientState != "" {
		q.Set("state", clientState)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
