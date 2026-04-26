package mcpauth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestUnitCryptoRoundTrip(t *testing.T) {
	c, err := NewCrypto(mustKey(t))
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}
	for _, n := range []int{0, 1, 16, 1024} {
		pt := make([]byte, n)
		if _, err := rand.Read(pt); err != nil {
			t.Fatalf("rand: %v", err)
		}
		blob, err := c.Encrypt(pt)
		if err != nil {
			t.Fatalf("Encrypt(%d): %v", n, err)
		}
		got, err := c.Decrypt(blob)
		if err != nil {
			t.Fatalf("Decrypt(%d): %v", n, err)
		}
		if !bytes.Equal(pt, got) {
			t.Fatalf("size %d: round-trip mismatch", n)
		}
	}
}

func TestUnitCryptoWrongKeyFails(t *testing.T) {
	c1, err := NewCrypto(mustKey(t))
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}
	c2, err := NewCrypto(mustKey(t))
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}
	blob, err := c1.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := c2.Decrypt(blob); err == nil {
		t.Fatal("expected decrypt with wrong key to fail")
	}
}

func TestUnitCryptoTamperedCiphertextFails(t *testing.T) {
	c, err := NewCrypto(mustKey(t))
	if err != nil {
		t.Fatalf("NewCrypto: %v", err)
	}
	blob, err := c.Encrypt([]byte("the quick brown fox"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Flip a bit in the ciphertext (past the nonce).
	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[nonceLen] ^= 0x01
	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatal("expected tampered decrypt to fail")
	}

	// A blob shorter than nonce+tag must also fail cleanly.
	if _, err := c.Decrypt([]byte{0x00}); err == nil {
		t.Fatal("expected short-blob decrypt to fail")
	}
}

func TestUnitCryptoBase64KeyParsing(t *testing.T) {
	raw := mustKey(t)

	// Padded URL-safe.
	padded := base64.URLEncoding.EncodeToString(raw)
	if c, err := NewCryptoFromBase64(padded); err != nil || c == nil {
		t.Fatalf("padded url-safe key rejected: %v", err)
	}
	// Unpadded URL-safe.
	unpadded := base64.RawURLEncoding.EncodeToString(raw)
	if c, err := NewCryptoFromBase64(unpadded); err != nil || c == nil {
		t.Fatalf("unpadded url-safe key rejected: %v", err)
	}
	// Standard padded.
	stdpad := base64.StdEncoding.EncodeToString(raw)
	if c, err := NewCryptoFromBase64(stdpad); err != nil || c == nil {
		t.Fatalf("std padded key rejected: %v", err)
	}

	// Wrong length: 16 bytes encoded.
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	if _, err := NewCryptoFromBase64(short); err == nil {
		t.Fatal("expected short key to be rejected")
	}

	// Empty.
	if _, err := NewCryptoFromBase64(""); err == nil {
		t.Fatal("expected empty key to be rejected")
	}

	// Garbage non-base64.
	if _, err := NewCryptoFromBase64("@@@not-base64@@@"); err == nil {
		t.Fatal("expected garbage to be rejected")
	}
}
