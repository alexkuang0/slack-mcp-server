package mcpauth

// This file implements the upstream Slack OAuth bridge as pure package
// functions: build the authorize URL, exchange a callback code for a Slack
// token via oauth.v2.access, validate it via auth.test, and refresh it.
//
// There are deliberately NO HTTP handlers here — Phase 5 mounts these into
// endpoints. There is also NO mcp-go integration: this package issues the
// network calls to Slack and exposes a clean data shape (SlackTokenGrant)
// that Phase 5 will persist via the store package.
//
// The package depends only on stdlib so it has zero coupling to slack-go,
// matching the design constraint in the Phase 3 spec.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultAPIBase is Slack's public API host. GovSlack and tests can override
// this via SlackOAuthConfig.APIBase. We never read env vars in this package —
// the caller (cmd/) is responsible for plumbing through SLACK_MCP_GOVSLACK.
const defaultAPIBase = "https://slack.com"

// Sentinel errors. Callers compare with errors.Is.
var (
	// ErrSlackAuthFailed indicates Slack rejected the credentials. Returned
	// when oauth.v2.access or auth.test responds with ok=false, when refresh
	// fails with invalid_refresh_token, etc. Wraps the upstream error code
	// when available.
	ErrSlackAuthFailed = errors.New("slack: auth failed")

	// ErrSlackUnreachable indicates a network or HTTP-level failure talking
	// to Slack (DNS, connection refused, non-2xx status, malformed JSON).
	// Distinct from ErrSlackAuthFailed so callers can decide whether to
	// retry vs surface to the user.
	ErrSlackUnreachable = errors.New("slack: unreachable")

	// ErrSlackRefreshUnsupported indicates the original grant did not include
	// a refresh_token, so RefreshToken cannot be called for it. Most user
	// OAuth (xoxp) apps don't issue refresh tokens unless token rotation is
	// explicitly enabled in the Slack app config.
	ErrSlackRefreshUnsupported = errors.New("slack: refresh not supported by this grant")
)

// SlackOAuthConfig configures the upstream Slack OAuth flow.
//
// In a single-app deployment, one instance of this is created at startup;
// in a per-team deployment (future), one is created per (team_id) using
// store.GetSlackApp() to fetch credentials.
type SlackOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string // must be HTTPS per Slack requirements

	// UserScopes is the user (xoxp) scope list; corresponds to Slack's
	// `user_scope` query param. Leaving empty means we won't request a
	// user token.
	UserScopes []string

	// BotScopes is the bot (xoxb) scope list; corresponds to Slack's
	// `scope` query param. Leaving empty means we won't request a bot
	// token.
	BotScopes []string

	// APIBase overrides Slack's API host. Defaults to https://slack.com.
	// Used by tests (httptest.Server.URL) and by callers wiring up
	// SLACK_MCP_GOVSLACK=true (which routes to slack-gov.com).
	APIBase string

	// HTTPClient overrides the HTTP client. Defaults to http.DefaultClient.
	// Tests inject httptest.Server.Client so the test cert is trusted.
	HTTPClient *http.Client
}

// SlackTokenGrant is the result of a successful OAuth code exchange and
// auth.test validation. It is the canonical shape that Phase 5 will encrypt
// and persist into the AuthzCode / Token rows defined in pkg/mcpauth/store.
type SlackTokenGrant struct {
	TeamID       string
	UserID       string
	AccessToken  string // xoxp-... (preferred when present) or xoxb-...
	RefreshToken string // empty if Slack didn't issue one
	Scope        string
	ExpiresAt    time.Time // zero value if non-expiring
	BotUserID    string    // present if the grant includes a bot token
	AppID        string    // for audit
	URL          string    // workspace URL from auth.test
}

// AuthorizeURL returns the URL the user's browser should be redirected to
// in order to start the Slack OAuth flow.
//
// The state value is opaque to Slack and is round-tripped back to the
// callback; the caller is responsible for storing it server-side and
// validating on callback (RFC 6749 §10.12 CSRF protection).
func (c *SlackOAuthConfig) AuthorizeURL(state string) string {
	base := c.apiBase()

	v := url.Values{}
	v.Set("client_id", c.ClientID)
	if len(c.BotScopes) > 0 {
		v.Set("scope", strings.Join(c.BotScopes, ","))
	}
	if len(c.UserScopes) > 0 {
		v.Set("user_scope", strings.Join(c.UserScopes, ","))
	}
	if c.RedirectURI != "" {
		v.Set("redirect_uri", c.RedirectURI)
	}
	if state != "" {
		v.Set("state", state)
	}
	return base + "/oauth/v2/authorize?" + v.Encode()
}

// slackOAuthAccessResp is the JSON shape returned by oauth.v2.access for both
// the authorization_code and refresh_token grant types. Slack documents these
// fields at https://api.slack.com/methods/oauth.v2.access.
type slackOAuthAccessResp struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Warn    string `json:"warning,omitempty"`
	AppID   string `json:"app_id,omitempty"`
	Scope   string `json:"scope,omitempty"`
	Token   string `json:"access_token,omitempty"`
	Type    string `json:"token_type,omitempty"`
	BotID   string `json:"bot_user_id,omitempty"`
	Expiry  int64  `json:"expires_in,omitempty"`
	Refresh string `json:"refresh_token,omitempty"`
	Team    *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"team,omitempty"`
	Enterprise *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"enterprise,omitempty"`
	AuthedUser *struct {
		ID           string `json:"id"`
		Scope        string `json:"scope,omitempty"`
		AccessToken  string `json:"access_token,omitempty"`
		TokenType    string `json:"token_type,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
		ExpiresIn    int64  `json:"expires_in,omitempty"`
	} `json:"authed_user,omitempty"`
}

// slackAuthTestResp is the JSON shape returned by auth.test.
// https://api.slack.com/methods/auth.test
type slackAuthTestResp struct {
	OK           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	URL          string `json:"url,omitempty"`
	Team         string `json:"team,omitempty"`
	User         string `json:"user,omitempty"`
	TeamID       string `json:"team_id,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	BotID        string `json:"bot_id,omitempty"`
	EnterpriseID string `json:"enterprise_id,omitempty"`
	AppID        string `json:"app_id,omitempty"`
}

// ExchangeCode posts the authorization code to oauth.v2.access, picks the
// best access token (xoxp preferred over xoxb), then validates the token via
// auth.test. The auth.test result is canonical for TeamID/UserID/URL — for
// Enterprise Grid in particular, oauth.v2.access reports the workspace's
// team_id while auth.test reports the enterprise_id, and we want the latter
// for routing.
//
// Returns ErrSlackAuthFailed if Slack rejects the code (or the resulting
// token), ErrSlackUnreachable on network or HTTP-status errors.
func (c *SlackOAuthConfig) ExchangeCode(ctx context.Context, code string) (*SlackTokenGrant, error) {
	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("code", code)
	if c.RedirectURI != "" {
		form.Set("redirect_uri", c.RedirectURI)
	}

	resp, err := c.postOAuthAccess(ctx, form)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%w: %s", ErrSlackAuthFailed, resp.Error)
	}

	grant := grantFromAccessResp(resp)
	if grant.AccessToken == "" {
		return nil, fmt.Errorf("%w: oauth.v2.access returned no access_token", ErrSlackAuthFailed)
	}

	// Canonicalize via auth.test. This overrides team/user/url from
	// oauth.v2.access — auth.test is authoritative, especially for
	// Enterprise Grid where oauth.v2.access reports the workspace
	// team_id but auth.test exposes the enterprise_id.
	test, err := c.callAuthTest(ctx, grant.AccessToken)
	if err != nil {
		return nil, err
	}
	if !test.OK {
		return nil, fmt.Errorf("%w: auth.test: %s", ErrSlackAuthFailed, test.Error)
	}

	if test.TeamID != "" {
		grant.TeamID = test.TeamID
	}
	if test.UserID != "" {
		grant.UserID = test.UserID
	}
	if test.URL != "" {
		grant.URL = test.URL
	}
	if test.AppID != "" && grant.AppID == "" {
		grant.AppID = test.AppID
	}
	// auth.test returns bot_id (B...), not bot_user_id (U...). Don't
	// overwrite the user-id form we got from oauth.v2.access; the
	// caller cares about the user id form.

	return grant, nil
}

// RefreshToken refreshes a Slack token using the refresh_token grant.
//
// Slack's documented behavior: when token rotation is enabled, oauth.v2.access
// with grant_type=refresh_token returns a new access_token + new refresh_token
// + expires_in. We require all three; an old grant without a refresh_token
// must be re-authorized via the full authorize/callback flow.
//
// Returns ErrSlackRefreshUnsupported if refreshToken is empty,
// ErrSlackAuthFailed on invalid_refresh_token / Slack ok=false,
// ErrSlackUnreachable on network errors.
func (c *SlackOAuthConfig) RefreshToken(ctx context.Context, refreshToken string) (*SlackTokenGrant, error) {
	if refreshToken == "" {
		return nil, ErrSlackRefreshUnsupported
	}

	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	resp, err := c.postOAuthAccess(ctx, form)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%w: %s", ErrSlackAuthFailed, resp.Error)
	}

	grant := grantFromAccessResp(resp)
	if grant.AccessToken == "" {
		return nil, fmt.Errorf("%w: refresh returned no access_token", ErrSlackAuthFailed)
	}
	return grant, nil
}

// grantFromAccessResp extracts a SlackTokenGrant from an oauth.v2.access
// response. The xoxp user token (authed_user.access_token) takes precedence
// over the xoxb bot token because it carries the richer scope set our tools
// rely on. If only a bot token is present, we still surface bot_user_id.
func grantFromAccessResp(r *slackOAuthAccessResp) *SlackTokenGrant {
	g := &SlackTokenGrant{
		AppID: r.AppID,
	}
	if r.Team != nil {
		g.TeamID = r.Team.ID
	}

	// Prefer the user token when present.
	if r.AuthedUser != nil && r.AuthedUser.AccessToken != "" {
		g.AccessToken = r.AuthedUser.AccessToken
		g.Scope = r.AuthedUser.Scope
		g.UserID = r.AuthedUser.ID
		g.RefreshToken = r.AuthedUser.RefreshToken
		if r.AuthedUser.ExpiresIn > 0 {
			g.ExpiresAt = time.Now().Add(time.Duration(r.AuthedUser.ExpiresIn) * time.Second)
		}
		// Bot user id and bot-side refresh token may still be useful
		// for audit even when we returned the user token.
		g.BotUserID = r.BotID
	} else {
		g.AccessToken = r.Token
		g.Scope = r.Scope
		g.RefreshToken = r.Refresh
		g.BotUserID = r.BotID
		if r.AuthedUser != nil {
			g.UserID = r.AuthedUser.ID
		}
		if r.Expiry > 0 {
			g.ExpiresAt = time.Now().Add(time.Duration(r.Expiry) * time.Second)
		}
	}
	return g
}

// postOAuthAccess submits a form-encoded POST to oauth.v2.access and parses
// the JSON response. It does NOT inspect resp.OK — callers handle that so
// they can wrap the error with their own context (initial vs refresh).
func (c *SlackOAuthConfig) postOAuthAccess(ctx context.Context, form url.Values) (*slackOAuthAccessResp, error) {
	endpoint := c.apiBase() + "/api/oauth.v2.access"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrSlackUnreachable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpResp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSlackUnreachable, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrSlackUnreachable, err)
	}
	if httpResp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w: status %d", ErrSlackUnreachable, httpResp.StatusCode)
	}

	var out slackOAuthAccessResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%w: decode response: %v", ErrSlackUnreachable, err)
	}
	return &out, nil
}

// callAuthTest invokes auth.test with the given access token in the
// Authorization header. Slack accepts the token via either form body or
// Authorization: Bearer; the latter is cleaner.
func (c *SlackOAuthConfig) callAuthTest(ctx context.Context, accessToken string) (*slackAuthTestResp, error) {
	endpoint := c.apiBase() + "/api/auth.test"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(""))
	if err != nil {
		return nil, fmt.Errorf("%w: build auth.test request: %v", ErrSlackUnreachable, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpResp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSlackUnreachable, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read auth.test body: %v", ErrSlackUnreachable, err)
	}
	if httpResp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w: auth.test status %d", ErrSlackUnreachable, httpResp.StatusCode)
	}

	var out slackAuthTestResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%w: decode auth.test: %v", ErrSlackUnreachable, err)
	}
	return &out, nil
}

func (c *SlackOAuthConfig) apiBase() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return defaultAPIBase
}

func (c *SlackOAuthConfig) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}
