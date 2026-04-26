package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeSlack mounts httptest handlers for Slack's oauth.v2.access and auth.test
// endpoints. Tests configure the JSON each handler returns.
type fakeSlack struct {
	t          *testing.T
	srv        *httptest.Server
	oauthResp  any
	authResp   any
	oauthCode  int
	authCode   int
	lastForm   url.Values
	lastBearer string
}

func newFakeSlack(t *testing.T) *fakeSlack {
	t.Helper()
	f := &fakeSlack{t: t, oauthCode: 200, authCode: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth.v2.access", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("oauth.v2.access: parse form: %v", err)
		}
		f.lastForm = form
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.oauthCode)
		_ = json.NewEncoder(w).Encode(f.oauthResp)
	})
	mux.HandleFunc("/api/auth.test", func(w http.ResponseWriter, r *http.Request) {
		f.lastBearer = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.authCode)
		_ = json.NewEncoder(w).Encode(f.authResp)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSlack) cfg() *SlackOAuthConfig {
	return &SlackOAuthConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://app.example.com/callback",
		UserScopes:   []string{"channels:history", "users:read"},
		BotScopes:    []string{"chat:write"},
		APIBase:      f.srv.URL,
		HTTPClient:   f.srv.Client(),
	}
}

func TestUnitSlackOAuthAuthorizeURL(t *testing.T) {
	c := &SlackOAuthConfig{
		ClientID:     "ABC123",
		ClientSecret: "shh",
		RedirectURI:  "https://app.example.com/cb?x=1",
		UserScopes:   []string{"channels:history", "users:read"},
		BotScopes:    []string{"chat:write"},
		APIBase:      "https://slack.example",
	}
	got := c.AuthorizeURL("state with spaces & ampersand")

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if u.Scheme != "https" || u.Host != "slack.example" || u.Path != "/oauth/v2/authorize" {
		t.Fatalf("wrong base: %s", got)
	}
	q := u.Query()
	if q.Get("client_id") != "ABC123" {
		t.Errorf("client_id: %q", q.Get("client_id"))
	}
	if q.Get("user_scope") != "channels:history,users:read" {
		t.Errorf("user_scope: %q", q.Get("user_scope"))
	}
	if q.Get("scope") != "chat:write" {
		t.Errorf("scope: %q", q.Get("scope"))
	}
	if q.Get("redirect_uri") != "https://app.example.com/cb?x=1" {
		t.Errorf("redirect_uri: %q", q.Get("redirect_uri"))
	}
	if q.Get("state") != "state with spaces & ampersand" {
		t.Errorf("state: %q", q.Get("state"))
	}

	// Default base when APIBase is empty.
	c.APIBase = ""
	got2 := c.AuthorizeURL("s")
	if !strings.HasPrefix(got2, "https://slack.com/oauth/v2/authorize?") {
		t.Errorf("default base: %s", got2)
	}
}

func TestUnitSlackOAuthExchangeCodeUserToken(t *testing.T) {
	f := newFakeSlack(t)
	f.oauthResp = map[string]any{
		"ok":           true,
		"app_id":       "A1",
		"access_token": "xoxb-bot",
		"token_type":   "bot",
		"scope":        "chat:write",
		"bot_user_id":  "UBOT",
		"team":         map[string]string{"id": "Twrong", "name": "team"},
		"authed_user": map[string]any{
			"id":           "U1",
			"scope":        "channels:history,users:read",
			"access_token": "xoxp-user",
			"token_type":   "user",
		},
	}
	f.authResp = map[string]any{
		"ok":      true,
		"url":     "https://example.slack.com/",
		"team_id": "T1",
		"user_id": "U1",
		"app_id":  "A1",
	}

	g, err := f.cfg().ExchangeCode(context.Background(), "the-code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if !strings.HasPrefix(g.AccessToken, "xoxp-") {
		t.Errorf("expected xoxp token, got %q", g.AccessToken)
	}
	if g.Scope != "channels:history,users:read" {
		t.Errorf("scope: %q", g.Scope)
	}
	if g.UserID != "U1" {
		t.Errorf("user_id: %q", g.UserID)
	}
	// auth.test team_id wins over oauth.v2.access team.id.
	if g.TeamID != "T1" {
		t.Errorf("team_id: %q (expected auth.test value to win)", g.TeamID)
	}
	if g.URL != "https://example.slack.com/" {
		t.Errorf("url: %q", g.URL)
	}
	if g.AppID != "A1" {
		t.Errorf("app_id: %q", g.AppID)
	}

	// Verify the form sent to oauth.v2.access.
	if f.lastForm.Get("client_id") != "client-id" ||
		f.lastForm.Get("client_secret") != "client-secret" ||
		f.lastForm.Get("code") != "the-code" ||
		f.lastForm.Get("redirect_uri") != "https://app.example.com/callback" {
		t.Errorf("oauth.v2.access form: %v", f.lastForm)
	}

	// auth.test must be called with the chosen (xoxp) token.
	if f.lastBearer != "xoxp-user" {
		t.Errorf("auth.test bearer: %q", f.lastBearer)
	}
}

func TestUnitSlackOAuthExchangeCodeBotOnly(t *testing.T) {
	f := newFakeSlack(t)
	f.oauthResp = map[string]any{
		"ok":           true,
		"app_id":       "A2",
		"access_token": "xoxb-only",
		"token_type":   "bot",
		"scope":        "chat:write,channels:read",
		"bot_user_id":  "UBOTID",
		"team":         map[string]string{"id": "T2"},
	}
	f.authResp = map[string]any{
		"ok":      true,
		"url":     "https://team2.slack.com/",
		"team_id": "T2",
		"user_id": "UBOTID",
	}

	g, err := f.cfg().ExchangeCode(context.Background(), "code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if !strings.HasPrefix(g.AccessToken, "xoxb-") {
		t.Errorf("expected xoxb token, got %q", g.AccessToken)
	}
	if g.BotUserID != "UBOTID" {
		t.Errorf("bot_user_id: %q", g.BotUserID)
	}
	if g.Scope != "chat:write,channels:read" {
		t.Errorf("scope: %q", g.Scope)
	}
	if g.TeamID != "T2" {
		t.Errorf("team_id: %q", g.TeamID)
	}
	if f.lastBearer != "xoxb-only" {
		t.Errorf("auth.test bearer: %q", f.lastBearer)
	}
}

func TestUnitSlackOAuthExchangeCodeFailed(t *testing.T) {
	f := newFakeSlack(t)
	f.oauthResp = map[string]any{
		"ok":    false,
		"error": "invalid_code",
	}

	_, err := f.cfg().ExchangeCode(context.Background(), "bad")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrSlackAuthFailed) {
		t.Errorf("expected ErrSlackAuthFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_code") {
		t.Errorf("error should include slack code: %v", err)
	}
}

func TestUnitSlackOAuthExchangeCodeAuthTestRejection(t *testing.T) {
	f := newFakeSlack(t)
	f.oauthResp = map[string]any{
		"ok":           true,
		"access_token": "xoxb-bad",
		"token_type":   "bot",
		"team":         map[string]string{"id": "T3"},
	}
	f.authResp = map[string]any{
		"ok":    false,
		"error": "invalid_auth",
	}

	_, err := f.cfg().ExchangeCode(context.Background(), "code")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrSlackAuthFailed) {
		t.Errorf("expected ErrSlackAuthFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_auth") {
		t.Errorf("error should include auth.test code: %v", err)
	}
}

func TestUnitSlackOAuthExchangeCodeNetworkError(t *testing.T) {
	f := newFakeSlack(t)
	cfg := f.cfg()
	// Close the fake server before issuing the request — Do() must fail.
	f.srv.Close()

	_, err := cfg.ExchangeCode(context.Background(), "code")
	if err == nil {
		t.Fatal("expected network error")
	}
	if !errors.Is(err, ErrSlackUnreachable) {
		t.Errorf("expected ErrSlackUnreachable, got %v", err)
	}
}

func TestUnitSlackOAuthRefreshTokenSuccess(t *testing.T) {
	f := newFakeSlack(t)
	f.oauthResp = map[string]any{
		"ok":            true,
		"app_id":        "A1",
		"access_token":  "xoxb-new",
		"token_type":    "bot",
		"scope":         "chat:write",
		"refresh_token": "xoxe.refresh-2",
		"expires_in":    3600,
		"team":          map[string]string{"id": "T1"},
	}

	g, err := f.cfg().RefreshToken(context.Background(), "xoxe.refresh-1")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if g.AccessToken != "xoxb-new" {
		t.Errorf("access_token: %q", g.AccessToken)
	}
	if g.RefreshToken != "xoxe.refresh-2" {
		t.Errorf("rotated refresh_token: %q", g.RefreshToken)
	}
	if g.ExpiresAt.IsZero() {
		t.Error("expected non-zero ExpiresAt")
	}

	if got := f.lastForm.Get("grant_type"); got != "refresh_token" {
		t.Errorf("grant_type: %q", got)
	}
	if got := f.lastForm.Get("refresh_token"); got != "xoxe.refresh-1" {
		t.Errorf("refresh_token form: %q", got)
	}
	if got := f.lastForm.Get("client_id"); got != "client-id" {
		t.Errorf("client_id form: %q", got)
	}
	if got := f.lastForm.Get("client_secret"); got != "client-secret" {
		t.Errorf("client_secret form: %q", got)
	}
}

func TestUnitSlackOAuthRefreshTokenInvalid(t *testing.T) {
	f := newFakeSlack(t)
	f.oauthResp = map[string]any{
		"ok":    false,
		"error": "invalid_refresh_token",
	}

	_, err := f.cfg().RefreshToken(context.Background(), "xoxe.bad")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrSlackAuthFailed) {
		t.Errorf("expected ErrSlackAuthFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_refresh_token") {
		t.Errorf("error should include slack code: %v", err)
	}

	// Empty refresh token => ErrSlackRefreshUnsupported, no HTTP call.
	_, err = f.cfg().RefreshToken(context.Background(), "")
	if !errors.Is(err, ErrSlackRefreshUnsupported) {
		t.Errorf("expected ErrSlackRefreshUnsupported for empty refresh, got %v", err)
	}
}

func TestUnitSlackOAuthExchangeCodeWorkspaceURL(t *testing.T) {
	f := newFakeSlack(t)
	f.oauthResp = map[string]any{
		"ok":           true,
		"access_token": "xoxb-gov",
		"token_type":   "bot",
		"team":         map[string]string{"id": "Tgov"},
	}
	f.authResp = map[string]any{
		"ok":      true,
		"url":     "https://gov-customer.slack-gov.com/",
		"team_id": "Tgov",
		"user_id": "Ugov",
	}

	g, err := f.cfg().ExchangeCode(context.Background(), "code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if g.URL != "https://gov-customer.slack-gov.com/" {
		t.Errorf("workspace URL: %q", g.URL)
	}
	if g.TeamID != "Tgov" {
		t.Errorf("team_id: %q", g.TeamID)
	}
}
