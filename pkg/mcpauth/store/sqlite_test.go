package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) (*SQLiteStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.db")
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	s, err := OpenSQLite(context.Background(), dsn)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dsn
}

func mustCreateClient(t *testing.T, s *SQLiteStore, id string) {
	t.Helper()
	err := s.CreateClient(context.Background(), OAuthClient{
		ClientID:     id,
		ClientName:   "test " + id,
		RedirectURIs: []string{"https://app.example/cb"},
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
}

func TestUnitSQLiteMigrationsIdempotent(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "mig.db")

	s1, err := OpenSQLite(context.Background(), dsn)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := OpenSQLite(context.Background(), dsn)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer s2.Close()

	var n int
	if err := s2.db.QueryRowContext(context.Background(),
		`SELECT COUNT(1) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 migration row, got %d", n)
	}
}

func TestUnitSQLiteClientCRUD(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	mustCreateClient(t, s, "client-1")

	got, err := s.GetClient(ctx, "client-1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.ClientID != "client-1" || got.ClientName != "test client-1" {
		t.Fatalf("unexpected client: %+v", got)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app.example/cb" {
		t.Fatalf("unexpected redirect_uris: %+v", got.RedirectURIs)
	}

	if err := s.DeleteClient(ctx, "client-1"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if _, err := s.GetClient(ctx, "client-1"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("expected ErrClientNotFound, got %v", err)
	}
	if err := s.DeleteClient(ctx, "client-1"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("expected ErrClientNotFound on second delete, got %v", err)
	}
}

func TestUnitSQLiteAuthzCodeConsume(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	mustCreateClient(t, s, "client-2")

	code := AuthzCode{
		CodeHash:             "hash-abc",
		ClientID:             "client-2",
		RedirectURI:          "https://app.example/cb",
		CodeChallenge:        "challenge",
		CodeChallengeMethod:  "S256",
		Resource:             "https://mcp.example",
		SlackTeamID:          "T1",
		SlackUserID:          "U1",
		SlackAccessTokenEnc:  []byte{0x01, 0x02},
		SlackRefreshTokenEnc: []byte{0x03},
		SlackScope:           "channels:read",
		ExpiresAt:            time.Now().Add(60 * time.Second).UTC(),
	}
	if err := s.CreateAuthzCode(ctx, code); err != nil {
		t.Fatalf("CreateAuthzCode: %v", err)
	}

	got, err := s.ConsumeAuthzCode(ctx, "hash-abc")
	if err != nil {
		t.Fatalf("first ConsumeAuthzCode: %v", err)
	}
	if got.ClientID != "client-2" || got.SlackTeamID != "T1" || got.SlackUserID != "U1" {
		t.Fatalf("unexpected code returned: %+v", got)
	}
	if !got.Consumed {
		t.Fatalf("expected returned code marked consumed")
	}

	if _, err := s.ConsumeAuthzCode(ctx, "hash-abc"); !errors.Is(err, ErrCodeAlreadyConsumed) {
		t.Fatalf("expected ErrCodeAlreadyConsumed, got %v", err)
	}
	if _, err := s.ConsumeAuthzCode(ctx, "missing"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestUnitSQLiteAuthzCodeGC(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	mustCreateClient(t, s, "client-3")

	now := time.Now().UTC()
	codes := []AuthzCode{
		{
			CodeHash: "expired-1", ClientID: "client-3",
			RedirectURI: "https://app.example/cb",
			CodeChallenge: "c", CodeChallengeMethod: "S256",
			Resource: "https://mcp.example", SlackTeamID: "T", SlackUserID: "U",
			SlackAccessTokenEnc: []byte{0x01}, SlackScope: "x",
			ExpiresAt: now.Add(-time.Minute),
		},
		{
			CodeHash: "expired-2", ClientID: "client-3",
			RedirectURI: "https://app.example/cb",
			CodeChallenge: "c", CodeChallengeMethod: "S256",
			Resource: "https://mcp.example", SlackTeamID: "T", SlackUserID: "U",
			SlackAccessTokenEnc: []byte{0x01}, SlackScope: "x",
			ExpiresAt: now.Add(-2 * time.Minute),
		},
		{
			CodeHash: "fresh-1", ClientID: "client-3",
			RedirectURI: "https://app.example/cb",
			CodeChallenge: "c", CodeChallengeMethod: "S256",
			Resource: "https://mcp.example", SlackTeamID: "T", SlackUserID: "U",
			SlackAccessTokenEnc: []byte{0x01}, SlackScope: "x",
			ExpiresAt: now.Add(time.Minute),
		},
	}
	for _, c := range codes {
		if err := s.CreateAuthzCode(ctx, c); err != nil {
			t.Fatalf("CreateAuthzCode(%s): %v", c.CodeHash, err)
		}
	}

	n, err := s.GCExpiredAuthzCodes(ctx)
	if err != nil {
		t.Fatalf("GCExpiredAuthzCodes: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 deletions, got %d", n)
	}
	// The future code should still consume successfully.
	if _, err := s.ConsumeAuthzCode(ctx, "fresh-1"); err != nil {
		t.Fatalf("consume fresh code: %v", err)
	}
	if _, err := s.ConsumeAuthzCode(ctx, "expired-1"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("expected expired code gone, got %v", err)
	}
}

func TestUnitSQLiteTokenLookup(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	mustCreateClient(t, s, "client-4")

	now := time.Now().UTC()
	live := Token{
		TokenHash:           "tok-live",
		ClientID:            "client-4",
		SlackTeamID:         "T1",
		SlackUserID:         "U1",
		SlackAccessTokenEnc: []byte{0xAA},
		SlackScope:          "x",
		ExpiresAt:           now.Add(time.Hour),
		RefreshTokenHash:    "rfh-1",
	}
	stale := Token{
		TokenHash:           "tok-stale",
		ClientID:            "client-4",
		SlackTeamID:         "T1",
		SlackUserID:         "U1",
		SlackAccessTokenEnc: []byte{0xBB},
		SlackScope:          "x",
		ExpiresAt:           now.Add(-time.Hour),
	}
	if err := s.CreateToken(ctx, live); err != nil {
		t.Fatalf("CreateToken live: %v", err)
	}
	if err := s.CreateToken(ctx, stale); err != nil {
		t.Fatalf("CreateToken stale: %v", err)
	}

	got, err := s.LookupToken(ctx, "tok-live")
	if err != nil {
		t.Fatalf("LookupToken: %v", err)
	}
	if got.ClientID != "client-4" || got.RefreshTokenHash != "rfh-1" {
		t.Fatalf("unexpected token: %+v", got)
	}

	if _, err := s.LookupToken(ctx, "tok-stale"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound for expired token, got %v", err)
	}
	if _, err := s.LookupToken(ctx, "missing"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound for missing token, got %v", err)
	}

	got, err = s.LookupByRefresh(ctx, "rfh-1")
	if err != nil {
		t.Fatalf("LookupByRefresh: %v", err)
	}
	if got.TokenHash != "tok-live" {
		t.Fatalf("unexpected refresh lookup: %+v", got)
	}
	if _, err := s.LookupByRefresh(ctx, ""); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound for empty refresh, got %v", err)
	}

	if err := s.RevokeToken(ctx, "tok-live"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := s.LookupToken(ctx, "tok-live"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("expected revoked token gone, got %v", err)
	}
	if err := s.RevokeToken(ctx, "tok-live"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound on second revoke, got %v", err)
	}
}

func TestUnitSQLiteSlackAppUpsert(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	if err := s.UpsertSlackApp(ctx, SlackApp{
		TeamID:          "default",
		ClientID:        "first",
		ClientSecretEnc: []byte{0x01},
	}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	if err := s.UpsertSlackApp(ctx, SlackApp{
		TeamID:          "default",
		ClientID:        "second",
		ClientSecretEnc: []byte{0x02, 0x03},
	}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := s.GetSlackApp(ctx, "default")
	if err != nil {
		t.Fatalf("GetSlackApp: %v", err)
	}
	if got.ClientID != "second" {
		t.Fatalf("expected second upsert to win, got %q", got.ClientID)
	}
	if len(got.ClientSecretEnc) != 2 || got.ClientSecretEnc[0] != 0x02 {
		t.Fatalf("unexpected secret blob: %v", got.ClientSecretEnc)
	}

	if _, err := s.GetSlackApp(ctx, "missing"); !errors.Is(err, ErrSlackAppNotFound) {
		t.Fatalf("expected ErrSlackAppNotFound, got %v", err)
	}
}
