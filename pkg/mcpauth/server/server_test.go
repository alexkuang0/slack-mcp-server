package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth/store"
	"github.com/korotovsky/slack-mcp-server/pkg/provider"
	"go.uber.org/zap"
)

// ----- test harness -----------------------------------------------------------

// newFakeSlack returns an httptest.Server that mimics oauth.v2.access and
// auth.test enough for the server tests. The server hands out a known token
// shape so tests can assert downstream encryption/storage.
func newFakeSlackForServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth.v2.access", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Parse to make sure the form arrives correctly; ignore values.
		_, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"app_id":       "A1",
			"access_token": "xoxb-bot",
			"token_type":   "bot",
			"scope":        "chat:write",
			"bot_user_id":  "UBOT",
			"team":         map[string]string{"id": "TWORKSPACE"},
			"authed_user": map[string]any{
				"id":           "UALICE",
				"scope":        "channels:history,users:read",
				"access_token": "xoxp-alice",
				"token_type":   "user",
			},
		})
	})
	mux.HandleFunc("/api/auth.test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"url":     "https://team.slack.com/",
			"team_id": "TWORKSPACE",
			"user_id": "UALICE",
			"app_id":  "A1",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// stubMCPHandler echoes the tenant pulled from context — so tests can assert
// the bearer middleware attached the correct TenantContext.
type stubMCPHandler struct{}

func (h *stubMCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, ok := provider.TenantFromContext(r.Context())
	if !ok {
		http.Error(w, "no tenant", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"team_id":   t.TeamID,
		"user_id":   t.UserID,
		"slack_tok": t.SlackToken,
	})
}

type harness struct {
	srv         *Server
	httpSrv     *httptest.Server
	store       *store.SQLiteStore
	slackStub   *httptest.Server
	now         time.Time
	advanceTime func(d time.Duration)
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	storage, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	crypto, err := mcpauth.NewCrypto(masterKey)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	slackStub := newFakeSlackForServer(t)

	cur := time.Now()
	h := &harness{
		store:     storage,
		slackStub: slackStub,
		now:       cur,
	}
	h.advanceTime = func(d time.Duration) { h.now = h.now.Add(d) }

	// Issuer is filled in once we know httpSrv's URL.
	srv := &Server{
		Logger: zap.NewNop(),
		Store:  storage,
		Crypto: crypto,
		SlackOAuth: &mcpauth.SlackOAuthConfig{
			ClientID:     "slack-app-id",
			ClientSecret: "slack-app-secret",
			RedirectURI:  "", // filled below
			UserScopes:   []string{"channels:history"},
			BotScopes:    []string{"chat:write"},
			APIBase:      slackStub.URL,
			HTTPClient:   slackStub.Client(),
		},
		AccessTTL:    1 * time.Hour,
		AuthzCodeTTL: 60 * time.Second,
		RefreshTTL:   30 * 24 * time.Hour,
		NowFn:        func() time.Time { return h.now },
	}

	mux := http.NewServeMux()
	srv.Mount(mux, &stubMCPHandler{})

	httpSrv := httptest.NewServer(mux)
	t.Cleanup(httpSrv.Close)
	t.Cleanup(srv.Close)

	srv.Issuer = httpSrv.URL
	srv.SlackOAuth.RedirectURI = httpSrv.URL + "/oauth/slack/callback"

	h.srv = srv
	h.httpSrv = httpSrv
	return h
}

// registerTestClient performs DCR and returns the new client_id.
func (h *harness) registerTestClient(t *testing.T, redirectURIs []string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"client_name":   "test client",
		"redirect_uris": redirectURIs,
	})
	resp, err := http.Post(h.httpSrv.URL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("register status %d: %s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cid, _ := out["client_id"].(string)
	if cid == "" {
		t.Fatalf("no client_id in response: %v", out)
	}
	return cid
}

// pkce builds a verifier+S256 challenge.
func pkce(t *testing.T) (verifier, challenge string) {
	t.Helper()
	v := make([]byte, 32)
	if _, err := rand.Read(v); err != nil {
		t.Fatalf("rand: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(v)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

// noRedirectClient returns an *http.Client that does NOT follow redirects, so
// tests can inspect the 302 Location header directly.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// driveAuthCodeFlow runs the full happy-path: register → authorize → callback
// → token, returning the final access_token + the verifier used.
func (h *harness) driveAuthCodeFlow(t *testing.T, clientRedirect string) (clientID, verifier, accessToken string) {
	t.Helper()

	clientID = h.registerTestClient(t, []string{clientRedirect})
	verifier, challenge := pkce(t)

	// /authorize → expect 302 to slackStub.
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", clientRedirect)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", h.srv.resourceURI())
	q.Set("state", "client-state-123")

	authzURL := h.httpSrv.URL + "/authorize?" + q.Encode()
	c := noRedirectClient()

	resp, err := c.Get(authzURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	slackURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse slack url: %v", err)
	}
	if !strings.HasPrefix(loc, h.slackStub.URL) {
		t.Fatalf("expected redirect to slack stub, got %s", loc)
	}
	stateBlob := slackURL.Query().Get("state")
	if stateBlob == "" {
		t.Fatalf("missing state in slack redirect")
	}

	// Simulate Slack redirecting back to /oauth/slack/callback.
	cbURL := h.httpSrv.URL + "/oauth/slack/callback?" + url.Values{
		"code":  []string{"slack-grant-code"},
		"state": []string{stateBlob},
	}.Encode()
	resp, err = c.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback status %d: %s", resp.StatusCode, raw)
	}
	cbLoc := resp.Header.Get("Location")
	if !strings.HasPrefix(cbLoc, clientRedirect) {
		t.Fatalf("expected redirect to client (%s), got %s", clientRedirect, cbLoc)
	}
	cbParsed, err := url.Parse(cbLoc)
	if err != nil {
		t.Fatalf("parse cb redirect: %v", err)
	}
	rawCode := cbParsed.Query().Get("code")
	if rawCode == "" {
		t.Fatalf("missing code in client redirect: %s", cbLoc)
	}
	if got := cbParsed.Query().Get("state"); got != "client-state-123" {
		t.Fatalf("client state not preserved: %q", got)
	}

	// /token exchange.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", rawCode)
	form.Set("redirect_uri", clientRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	form.Set("resource", h.srv.resourceURI())

	tokResp, err := http.Post(h.httpSrv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("token status %d: %s", tokResp.StatusCode, raw)
	}
	var tr tokenResponse
	if err := json.NewDecoder(tokResp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode token resp: %v", err)
	}
	if !strings.HasPrefix(tr.AccessToken, mcpauth.MCPTokenPrefix) {
		t.Fatalf("access_token missing prefix: %q", tr.AccessToken)
	}
	if tr.TokenType != "Bearer" {
		t.Fatalf("token_type: %q", tr.TokenType)
	}
	if tr.ExpiresIn != int64(time.Hour.Seconds()) {
		t.Fatalf("expires_in: %d", tr.ExpiresIn)
	}
	return clientID, verifier, tr.AccessToken
}

// ----- tests -----------------------------------------------------------------

func TestUnitASMetadataDocs(t *testing.T) {
	h := newHarness(t)

	// /.well-known/oauth-protected-resource
	resp, err := http.Get(h.httpSrv.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var pr map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pr["resource"] != h.srv.resourceURI() {
		t.Errorf("resource: %v", pr["resource"])
	}
	if servers, ok := pr["authorization_servers"].([]any); !ok || len(servers) != 1 || servers[0] != h.srv.Issuer {
		t.Errorf("authorization_servers: %v", pr["authorization_servers"])
	}

	// /.well-known/oauth-authorization-server
	resp2, err := http.Get(h.httpSrv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp2.Body.Close()
	var as map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&as); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{
		"issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint",
		"code_challenge_methods_supported", "grant_types_supported",
		"response_types_supported", "token_endpoint_auth_methods_supported",
	} {
		if _, ok := as[k]; !ok {
			t.Errorf("missing AS metadata field: %s", k)
		}
	}
	if as["issuer"] != h.srv.Issuer {
		t.Errorf("issuer: %v", as["issuer"])
	}
}

func TestUnitDCRRegistersClient(t *testing.T) {
	h := newHarness(t)

	cid := h.registerTestClient(t, []string{"https://example.com/cb"})
	if !strings.HasPrefix(cid, "mcp_client_") {
		t.Errorf("client_id should start with mcp_client_, got %q", cid)
	}

	got, err := h.store.GetClient(context.Background(), cid)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.ClientID != cid {
		t.Errorf("client_id mismatch: %q vs %q", got.ClientID, cid)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://example.com/cb" {
		t.Errorf("redirect_uris: %v", got.RedirectURIs)
	}
}

func TestUnitDCRRejectsBadRedirect(t *testing.T) {
	h := newHarness(t)
	body, _ := json.Marshal(map[string]any{
		"client_name":   "evil",
		"redirect_uris": []string{"http://evil.com/cb"},
	})
	resp, err := http.Post(h.httpSrv.URL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "invalid_redirect_uri" {
		t.Errorf("error: %v", out["error"])
	}
}

func TestUnitDCRAcceptsLocalhost(t *testing.T) {
	h := newHarness(t)
	cid := h.registerTestClient(t, []string{"http://localhost:6274/cb", "http://127.0.0.1:6274/cb"})
	if cid == "" {
		t.Fatal("expected client_id")
	}
}

func TestUnitDCRRejectsEmptyRedirects(t *testing.T) {
	h := newHarness(t)
	body, _ := json.Marshal(map[string]any{"client_name": "x"})
	resp, err := http.Post(h.httpSrv.URL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestUnitAuthorizeRequiresPKCE(t *testing.T) {
	h := newHarness(t)
	cid := h.registerTestClient(t, []string{"https://app/cb"})

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cid)
	q.Set("redirect_uri", "https://app/cb")
	q.Set("resource", h.srv.resourceURI())
	// missing code_challenge and code_challenge_method.

	resp, err := noRedirectClient().Get(h.httpSrv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestUnitAuthorizeRequiresResource(t *testing.T) {
	h := newHarness(t)
	cid := h.registerTestClient(t, []string{"https://app/cb"})
	_, ch := pkce(t)
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cid)
	q.Set("redirect_uri", "https://app/cb")
	q.Set("code_challenge", ch)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", "https://wrong/mcp")

	resp, err := noRedirectClient().Get(h.httpSrv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "invalid_target" {
		t.Errorf("error: %v", out["error"])
	}
}

func TestUnitAuthorizeRedirectsToSlack(t *testing.T) {
	h := newHarness(t)
	cid := h.registerTestClient(t, []string{"https://app/cb"})
	_, ch := pkce(t)
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cid)
	q.Set("redirect_uri", "https://app/cb")
	q.Set("code_challenge", ch)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", h.srv.resourceURI())
	q.Set("state", "abc")

	resp, err := noRedirectClient().Get(h.httpSrv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, h.slackStub.URL) {
		t.Errorf("location not slack stub: %s", loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("state") == "" {
		t.Errorf("missing state in slack URL: %s", loc)
	}
}

func TestUnitAuthorizeUnknownClient(t *testing.T) {
	h := newHarness(t)
	_, ch := pkce(t)
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "mcp_client_unknown")
	q.Set("redirect_uri", "https://app/cb")
	q.Set("code_challenge", ch)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", h.srv.resourceURI())

	resp, err := noRedirectClient().Get(h.httpSrv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestUnitFullAuthCodeFlowEndToEnd(t *testing.T) {
	h := newHarness(t)
	clientRedirect := "https://app.example.com/cb"

	_, _, access := h.driveAuthCodeFlow(t, clientRedirect)

	// Use the bearer to call /mcp; stub handler echoes the tenant.
	req, err := http.NewRequest(http.MethodGet, h.httpSrv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("/mcp status %d: %s", resp.StatusCode, raw)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["team_id"] != "TWORKSPACE" {
		t.Errorf("tenant team_id: %q", got["team_id"])
	}
	if got["user_id"] != "UALICE" {
		t.Errorf("tenant user_id: %q", got["user_id"])
	}
	if got["slack_tok"] != "xoxp-alice" {
		t.Errorf("tenant slack_tok: %q", got["slack_tok"])
	}

	// Wrong token → 401 with WWW-Authenticate.
	badReq, _ := http.NewRequest(http.MethodGet, h.httpSrv.URL+"/mcp", nil)
	badReq.Header.Set("Authorization", "Bearer mcp_at_garbage")
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatalf("do bad: %v", err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", badResp.StatusCode)
	}
	wa := badResp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wa, "Bearer") || !strings.Contains(wa, "resource_metadata") {
		t.Errorf("WWW-Authenticate: %q", wa)
	}
}

func TestUnitTokenDoubleRedeemFails(t *testing.T) {
	h := newHarness(t)
	clientRedirect := "https://app.example.com/cb"

	// Drive the flow once via the helper to exhaust the code.
	cid, verifier, _ := h.driveAuthCodeFlow(t, clientRedirect)

	// Mint a fresh authz code by walking through authorize+callback again
	// since driveAuthCodeFlow consumed the first one. Then attempt to
	// redeem it twice.
	_, ch := pkce(t)
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cid)
	q.Set("redirect_uri", clientRedirect)
	q.Set("code_challenge", ch)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", h.srv.resourceURI())

	c := noRedirectClient()
	resp, _ := c.Get(h.httpSrv.URL + "/authorize?" + q.Encode())
	resp.Body.Close()
	state := mustQueryParam(t, resp.Header.Get("Location"), "state")

	cbResp, _ := c.Get(h.httpSrv.URL + "/oauth/slack/callback?" + url.Values{
		"code":  []string{"slack-code-2"},
		"state": []string{state},
	}.Encode())
	cbResp.Body.Close()
	rawCode := mustQueryParam(t, cbResp.Header.Get("Location"), "code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", rawCode)
	form.Set("redirect_uri", clientRedirect)
	form.Set("client_id", cid)
	// First attempt uses the right verifier for THIS authorize (challenge=ch).
	// We need the verifier matching `ch`. We still have it from pkce(t):
	// the helper returned verifier first, but we discarded it; redo the flow.
	_ = verifier // unused — the pkce above is for the second flow.

	// Redo: capture verifier+challenge inline to keep this simple.
	v2, ch2 := pkce(t)
	q2 := url.Values{}
	q2.Set("response_type", "code")
	q2.Set("client_id", cid)
	q2.Set("redirect_uri", clientRedirect)
	q2.Set("code_challenge", ch2)
	q2.Set("code_challenge_method", "S256")
	q2.Set("resource", h.srv.resourceURI())
	resp2, _ := c.Get(h.httpSrv.URL + "/authorize?" + q2.Encode())
	resp2.Body.Close()
	state2 := mustQueryParam(t, resp2.Header.Get("Location"), "state")
	cbResp2, _ := c.Get(h.httpSrv.URL + "/oauth/slack/callback?" + url.Values{
		"code":  []string{"slack-code-3"},
		"state": []string{state2},
	}.Encode())
	cbResp2.Body.Close()
	rawCode2 := mustQueryParam(t, cbResp2.Header.Get("Location"), "code")

	form = url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", rawCode2)
	form.Set("redirect_uri", clientRedirect)
	form.Set("client_id", cid)
	form.Set("code_verifier", v2)
	form.Set("resource", h.srv.resourceURI())

	first, err := http.Post(h.httpSrv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("first token: %v", err)
	}
	if first.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(first.Body)
		first.Body.Close()
		t.Fatalf("first token: status %d body %s", first.StatusCode, raw)
	}
	first.Body.Close()

	second, err := http.Post(h.httpSrv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("second token: %v", err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on double redeem, got %d", second.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(second.Body).Decode(&out)
	if out["error"] != "invalid_grant" {
		t.Errorf("error: %v", out["error"])
	}
}

func TestUnitTokenPKCEMismatchFails(t *testing.T) {
	h := newHarness(t)
	clientRedirect := "https://app.example.com/cb"

	cid := h.registerTestClient(t, []string{clientRedirect})
	_, ch := pkce(t)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cid)
	q.Set("redirect_uri", clientRedirect)
	q.Set("code_challenge", ch)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", h.srv.resourceURI())

	c := noRedirectClient()
	resp, _ := c.Get(h.httpSrv.URL + "/authorize?" + q.Encode())
	resp.Body.Close()
	state := mustQueryParam(t, resp.Header.Get("Location"), "state")

	cbResp, _ := c.Get(h.httpSrv.URL + "/oauth/slack/callback?" + url.Values{
		"code":  []string{"slack-code"},
		"state": []string{state},
	}.Encode())
	cbResp.Body.Close()
	rawCode := mustQueryParam(t, cbResp.Header.Get("Location"), "code")

	// Use a wrong verifier.
	wrongVerifier, _ := pkce(t)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", rawCode)
	form.Set("redirect_uri", clientRedirect)
	form.Set("client_id", cid)
	form.Set("code_verifier", wrongVerifier)
	form.Set("resource", h.srv.resourceURI())

	resp2, err := http.Post(h.httpSrv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp2.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&out)
	if out["error"] != "invalid_grant" {
		t.Errorf("error: %v", out["error"])
	}
}

func TestUnitTokenExpiredCodeFails(t *testing.T) {
	h := newHarness(t)
	clientRedirect := "https://app.example.com/cb"

	cid := h.registerTestClient(t, []string{clientRedirect})
	v, ch := pkce(t)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cid)
	q.Set("redirect_uri", clientRedirect)
	q.Set("code_challenge", ch)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", h.srv.resourceURI())

	c := noRedirectClient()
	resp, _ := c.Get(h.httpSrv.URL + "/authorize?" + q.Encode())
	resp.Body.Close()
	state := mustQueryParam(t, resp.Header.Get("Location"), "state")

	cbResp, _ := c.Get(h.httpSrv.URL + "/oauth/slack/callback?" + url.Values{
		"code":  []string{"slack-code"},
		"state": []string{state},
	}.Encode())
	cbResp.Body.Close()
	rawCode := mustQueryParam(t, cbResp.Header.Get("Location"), "code")

	// Advance time past AuthzCodeTTL (60s default).
	h.advanceTime(2 * time.Minute)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", rawCode)
	form.Set("redirect_uri", clientRedirect)
	form.Set("client_id", cid)
	form.Set("code_verifier", v)
	form.Set("resource", h.srv.resourceURI())

	resp2, err := http.Post(h.httpSrv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp2.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&out)
	if out["error"] != "invalid_grant" {
		t.Errorf("error: %v", out["error"])
	}
}

func TestUnitBearerMiddlewareTokenExpired(t *testing.T) {
	h := newHarness(t)
	clientRedirect := "https://app.example.com/cb"

	_, _, access := h.driveAuthCodeFlow(t, clientRedirect)

	// Advance past AccessTTL (1h default in harness).
	h.advanceTime(2 * time.Hour)

	// SQLite's LookupToken filters using time.Now() (real wall clock), not
	// our NowFn — so the SQLite store handles expiry with real time. We need
	// to assert behavior using real-clock expiry; reuse the store-level
	// expiry by manually expiring the token in the DB.
	tokHash := mcpauth.HashToken(access)
	if _, err := h.store.ExpireTokenForTest(context.Background(), tokHash); err != nil {
		t.Fatalf("expire token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, h.httpSrv.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestUnitBearerMiddlewareMissingToken(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.httpSrv.URL + "/mcp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wa, "Bearer") {
		t.Errorf("WWW-Authenticate: %q", wa)
	}
}

func TestUnitTokenWrongMethod(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.httpSrv.URL + "/token")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// mustQueryParam parses a URL string and returns the named query param,
// failing the test if the URL is malformed or the param is missing.
func mustQueryParam(t *testing.T, raw, name string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	v := u.Query().Get(name)
	if v == "" {
		t.Fatalf("query param %q missing in %q", name, raw)
	}
	return v
}

// silence "declared and not used" under some build tags.
var _ = fmt.Sprintf
