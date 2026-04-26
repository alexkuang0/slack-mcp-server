package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	// modernc.org/sqlite is a pure-Go (CGO_ENABLED=0) port of SQLite. Chosen
	// to keep the existing Dockerfile's `CGO_ENABLED=0` build unchanged.
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// SQLiteStore is the default Storage implementation backed by a single
// SQLite database file (or `:memory:` for tests).
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLite opens (or creates) the SQLite database at dsn and applies any
// pending migrations.
//
// dsn examples:
//
//	"file:/var/lib/slack-mcp/auth.db?cache=shared&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
//	"file::memory:?cache=shared"
func OpenSQLite(ctx context.Context, dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("mcpauth/store: open sqlite: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("mcpauth/store: ping sqlite: %w", err)
	}
	s := &SQLiteStore{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// migrate applies any embedded SQL migrations whose version is greater than
// the highest already-recorded one. Migrations are idempotent on re-open
// because we record applied versions in `schema_migrations`.
func (s *SQLiteStore) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("mcpauth/store: create migrations table: %w", err)
	}

	files, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("mcpauth/store: read migrations dir: %w", err)
	}
	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".sql") {
			continue
		}
		// Filename convention: NNNN_description.sql
		var v int
		if _, err := fmt.Sscanf(f.Name(), "%d_", &v); err != nil {
			return fmt.Errorf("mcpauth/store: bad migration filename %q: %w", f.Name(), err)
		}
		migs = append(migs, mig{version: v, name: f.Name()})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	for _, m := range migs {
		var exists int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, m.version,
		).Scan(&exists); err != nil {
			return fmt.Errorf("mcpauth/store: check migration %d: %w", m.version, err)
		}
		if exists > 0 {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + m.name)
		if err != nil {
			return fmt.Errorf("mcpauth/store: read %s: %w", m.name, err)
		}
		// Each migration runs in its own transaction so a partial apply
		// rolls back cleanly.
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("mcpauth/store: begin tx %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("mcpauth/store: apply %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`,
			m.version, time.Now().UTC(),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("mcpauth/store: record %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("mcpauth/store: commit %s: %w", m.name, err)
		}
	}
	return nil
}

// --- OAuth clients --------------------------------------------------------

func (s *SQLiteStore) CreateClient(ctx context.Context, c OAuthClient) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("mcpauth/store: marshal redirect_uris: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oauth_clients (client_id, client_name, redirect_uris, client_secret_hash, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, c.ClientID, c.ClientName, string(uris), c.ClientSecretHash, c.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("mcpauth/store: insert oauth_client: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT client_id, client_name, redirect_uris, client_secret_hash, created_at
		FROM oauth_clients WHERE client_id = ?
	`, clientID)
	var (
		c       OAuthClient
		uris    string
		secret  []byte
		created time.Time
	)
	if err := row.Scan(&c.ClientID, &c.ClientName, &uris, &secret, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("mcpauth/store: scan oauth_client: %w", err)
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("mcpauth/store: unmarshal redirect_uris: %w", err)
	}
	c.ClientSecretHash = secret
	c.CreatedAt = created
	return &c, nil
}

func (s *SQLiteStore) DeleteClient(ctx context.Context, clientID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_clients WHERE client_id = ?`, clientID)
	if err != nil {
		return fmt.Errorf("mcpauth/store: delete oauth_client: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mcpauth/store: rows affected: %w", err)
	}
	if n == 0 {
		return ErrClientNotFound
	}
	return nil
}

// --- Authorization codes --------------------------------------------------

func (s *SQLiteStore) CreateAuthzCode(ctx context.Context, c AuthzCode) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_authz_codes (
			code_hash, client_id, redirect_uri, code_challenge, code_challenge_method,
			resource, slack_team_id, slack_user_id,
			slack_access_token_enc, slack_refresh_token_enc, slack_scope,
			expires_at, consumed
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		c.CodeHash, c.ClientID, c.RedirectURI, c.CodeChallenge, c.CodeChallengeMethod,
		c.Resource, c.SlackTeamID, c.SlackUserID,
		c.SlackAccessTokenEnc, c.SlackRefreshTokenEnc, c.SlackScope,
		c.ExpiresAt.UTC(), boolToInt(c.Consumed),
	)
	if err != nil {
		return fmt.Errorf("mcpauth/store: insert authz_code: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ConsumeAuthzCode(ctx context.Context, codeHash string) (*AuthzCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mcpauth/store: begin consume tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		c               AuthzCode
		consumed        int
		expires         time.Time
		refreshTokenEnc []byte
	)
	row := tx.QueryRowContext(ctx, `
		SELECT code_hash, client_id, redirect_uri, code_challenge, code_challenge_method,
		       resource, slack_team_id, slack_user_id,
		       slack_access_token_enc, slack_refresh_token_enc, slack_scope,
		       expires_at, consumed
		FROM oauth_authz_codes WHERE code_hash = ?
	`, codeHash)
	if err := row.Scan(
		&c.CodeHash, &c.ClientID, &c.RedirectURI, &c.CodeChallenge, &c.CodeChallengeMethod,
		&c.Resource, &c.SlackTeamID, &c.SlackUserID,
		&c.SlackAccessTokenEnc, &refreshTokenEnc, &c.SlackScope,
		&expires, &consumed,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCodeNotFound
		}
		return nil, fmt.Errorf("mcpauth/store: scan authz_code: %w", err)
	}
	c.SlackRefreshTokenEnc = refreshTokenEnc
	c.ExpiresAt = expires
	c.Consumed = consumed != 0
	if c.Consumed {
		return nil, ErrCodeAlreadyConsumed
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE oauth_authz_codes SET consumed = 1 WHERE code_hash = ?`, codeHash,
	); err != nil {
		return nil, fmt.Errorf("mcpauth/store: mark consumed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("mcpauth/store: commit consume: %w", err)
	}
	c.Consumed = true
	return &c, nil
}

func (s *SQLiteStore) GCExpiredAuthzCodes(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_authz_codes WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("mcpauth/store: gc authz_codes: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("mcpauth/store: rows affected: %w", err)
	}
	return int(n), nil
}

// --- Tokens ---------------------------------------------------------------

func (s *SQLiteStore) CreateToken(ctx context.Context, t Token) error {
	var refreshHash any
	if t.RefreshTokenHash != "" {
		refreshHash = t.RefreshTokenHash
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_tokens (
			token_hash, client_id, slack_team_id, slack_user_id,
			slack_access_token_enc, slack_refresh_token_enc, slack_scope,
			expires_at, refresh_token_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		t.TokenHash, t.ClientID, t.SlackTeamID, t.SlackUserID,
		t.SlackAccessTokenEnc, t.SlackRefreshTokenEnc, t.SlackScope,
		t.ExpiresAt.UTC(), refreshHash,
	)
	if err != nil {
		return fmt.Errorf("mcpauth/store: insert token: %w", err)
	}
	return nil
}

func (s *SQLiteStore) LookupToken(ctx context.Context, tokenHash string) (*Token, error) {
	// Filter on expires_at server-side: callers must not be able to use a
	// stale token even if the local clock disagrees with the DB.
	row := s.db.QueryRowContext(ctx, `
		SELECT token_hash, client_id, slack_team_id, slack_user_id,
		       slack_access_token_enc, slack_refresh_token_enc, slack_scope,
		       expires_at, COALESCE(refresh_token_hash, '')
		FROM oauth_tokens
		WHERE token_hash = ? AND expires_at >= ?
	`, tokenHash, time.Now().UTC())
	return scanToken(row)
}

func (s *SQLiteStore) RevokeToken(ctx context.Context, tokenHash string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_tokens WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return fmt.Errorf("mcpauth/store: delete token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mcpauth/store: rows affected: %w", err)
	}
	if n == 0 {
		return ErrTokenNotFound
	}
	return nil
}

func (s *SQLiteStore) LookupByRefresh(ctx context.Context, refreshHash string) (*Token, error) {
	if refreshHash == "" {
		return nil, ErrTokenNotFound
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT token_hash, client_id, slack_team_id, slack_user_id,
		       slack_access_token_enc, slack_refresh_token_enc, slack_scope,
		       expires_at, COALESCE(refresh_token_hash, '')
		FROM oauth_tokens
		WHERE refresh_token_hash = ?
	`, refreshHash)
	return scanToken(row)
}

func scanToken(row *sql.Row) (*Token, error) {
	var (
		t            Token
		expires      time.Time
		refreshEnc   []byte
		refreshHash  string
	)
	if err := row.Scan(
		&t.TokenHash, &t.ClientID, &t.SlackTeamID, &t.SlackUserID,
		&t.SlackAccessTokenEnc, &refreshEnc, &t.SlackScope,
		&expires, &refreshHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("mcpauth/store: scan token: %w", err)
	}
	t.SlackRefreshTokenEnc = refreshEnc
	t.ExpiresAt = expires
	t.RefreshTokenHash = refreshHash
	return &t, nil
}

// --- Slack apps -----------------------------------------------------------

func (s *SQLiteStore) UpsertSlackApp(ctx context.Context, app SlackApp) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO slack_apps (team_id, client_id, client_secret_enc)
		VALUES (?, ?, ?)
		ON CONFLICT(team_id) DO UPDATE SET
			client_id = excluded.client_id,
			client_secret_enc = excluded.client_secret_enc
	`, app.TeamID, app.ClientID, app.ClientSecretEnc)
	if err != nil {
		return fmt.Errorf("mcpauth/store: upsert slack_app: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetSlackApp(ctx context.Context, teamID string) (*SlackApp, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT team_id, client_id, client_secret_enc
		FROM slack_apps WHERE team_id = ?
	`, teamID)
	var a SlackApp
	if err := row.Scan(&a.TeamID, &a.ClientID, &a.ClientSecretEnc); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSlackAppNotFound
		}
		return nil, fmt.Errorf("mcpauth/store: scan slack_app: %w", err)
	}
	return &a, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
