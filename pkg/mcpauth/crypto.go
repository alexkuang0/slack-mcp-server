// Package mcpauth holds the OAuth + DCR machinery the server uses to act as
// an MCP-spec authorization server in front of Slack.
//
// This file implements the AES-256-GCM symmetric envelope used to protect
// Slack-issued tokens at rest. The master key is supplied by the operator
// (env var) and never leaves process memory.
package mcpauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// keyLen is fixed at 32 bytes so we always use AES-256.
const keyLen = 32

// nonceLen is the standard 96-bit GCM nonce size.
const nonceLen = 12

// Crypto is an AES-256-GCM AEAD bound to a single master key.
//
// It is safe for concurrent use: cipher.AEAD is documented as such and we
// never mutate state after construction.
type Crypto struct {
	aead cipher.AEAD
}

// NewCrypto constructs an AES-256-GCM AEAD from a 32-byte key.
//
// cipher.NewGCM panics on a zero-length nonce or unsupported block; the
// length guard below makes the failure mode an error instead.
func NewCrypto(key []byte) (*Crypto, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("mcpauth: key must be %d bytes, got %d", keyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mcpauth: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mcpauth: cipher.NewGCM: %w", err)
	}
	return &Crypto{aead: aead}, nil
}

// NewCryptoFromBase64 decodes a base64url-encoded 32-byte key.
//
// Both padded ("=") and unpadded variants are accepted so operators can
// paste the value of `openssl rand -base64 32` or `head -c 32 /dev/urandom
// | base64 | tr -d '='` interchangeably.
func NewCryptoFromBase64(b64 string) (*Crypto, error) {
	if b64 == "" {
		return nil, errors.New("mcpauth: empty base64 key")
	}
	key, err := decodeBase64Key(b64)
	if err != nil {
		return nil, err
	}
	return NewCrypto(key)
}

func decodeBase64Key(b64 string) ([]byte, error) {
	// Try the most common variants in order of likelihood.
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		out, err := enc.DecodeString(b64)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("mcpauth: invalid base64 key: %w", lastErr)
}

// Encrypt seals plaintext and returns nonce||ciphertext||tag.
//
// A fresh random nonce is generated per call; reusing a (key, nonce) pair
// would catastrophically break GCM authenticity, so we never accept a
// caller-supplied nonce.
func (c *Crypto) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("mcpauth: nil Crypto")
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("mcpauth: read nonce: %w", err)
	}
	// Seal appends the ciphertext+tag onto the dst slice (the nonce here),
	// giving us the desired nonce||ct||tag layout in a single allocation.
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt opens a blob produced by Encrypt.
//
// Authentication failures (wrong key, tampered ciphertext, truncated input)
// all surface as an opaque error so callers cannot fingerprint the failure
// mode.
func (c *Crypto) Decrypt(blob []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("mcpauth: nil Crypto")
	}
	if len(blob) < nonceLen+c.aead.Overhead() {
		return nil, errors.New("mcpauth: ciphertext too short")
	}
	nonce, ct := blob[:nonceLen], blob[nonceLen:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("mcpauth: decrypt: %w", err)
	}
	return pt, nil
}
