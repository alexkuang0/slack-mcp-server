CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,           -- JSON array
    client_secret_hash BLOB,               -- nullable
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_authz_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    resource TEXT NOT NULL,
    slack_team_id TEXT NOT NULL,
    slack_user_id TEXT NOT NULL,
    slack_access_token_enc BLOB NOT NULL,
    slack_refresh_token_enc BLOB,
    slack_scope TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_authz_codes_expires ON oauth_authz_codes(expires_at);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    slack_team_id TEXT NOT NULL,
    slack_user_id TEXT NOT NULL,
    slack_access_token_enc BLOB NOT NULL,
    slack_refresh_token_enc BLOB,
    slack_scope TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    refresh_token_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_tokens_refresh ON oauth_tokens(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON oauth_tokens(expires_at);

CREATE TABLE IF NOT EXISTS slack_apps (
    team_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    client_secret_enc BLOB NOT NULL
);
