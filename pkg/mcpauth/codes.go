package mcpauth

// This file holds small token/code helpers used across the OAuth Authorization
// Server: opaque-token generation, canonical SHA-256 hashing, and PKCE S256
// validation per RFC 7636.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// MCPTokenPrefix is the human-recognizable prefix for opaque MCP access tokens.
const MCPTokenPrefix = "mcp_at_"

// MCPRefreshPrefix is the prefix for opaque MCP refresh tokens (Phase 6).
const MCPRefreshPrefix = "mcp_rt_"

// MCPCodePrefix is the prefix for opaque MCP authorization codes.
const MCPCodePrefix = "mcp_code_"

// opaqueRandomBytes is the entropy size of generated opaque tokens.
// 32 bytes (256 bits) is comfortable margin; encoded as base64url it produces
// a 43-character body.
const opaqueRandomBytes = 32

// NewOpaqueToken returns (raw, hashHex). The raw value should be returned to
// the client exactly once and never persisted; only the hashHex is stored.
//
// Format: <prefix><base64url-no-padding(32 random bytes)>.
func NewOpaqueToken(prefix string) (raw, hashHex string, err error) {
	buf := make([]byte, opaqueRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("mcpauth: read random: %w", err)
	}
	raw = prefix + base64.RawURLEncoding.EncodeToString(buf)
	hashHex = HashToken(raw)
	return raw, hashHex, nil
}

// HashToken returns the canonical hashHex for the given raw token; used by
// lookup paths to produce the same key the issuer stored.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ValidatePKCE checks an S256 code_challenge against a raw code_verifier per
// RFC 7636. Both sides must be base64url-no-padding. A constant-time compare
// is used to prevent timing oracles on the verifier check.
func ValidatePKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if len(want) != len(challenge) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

// ErrInvalidPrefix is returned when a token doesn't match its expected prefix.
// Provided for callers that want to fast-fail on obvious garbage before a DB
// lookup; the lookup itself remains the source of truth.
var ErrInvalidPrefix = errors.New("mcpauth: invalid token prefix")
