package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	aead, err := NewAEAD(key)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	plaintext := []byte("Hello, Phantom!")

	ciphertext, err := aead.Seal(plaintext)
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}

	// Create new AEAD for opening (same key, same counter state)
	aead2, err := NewAEAD(key)
	if err != nil {
		t.Fatalf("failed to create AEAD for open: %v", err)
	}

	decrypted, err := aead2.Open(ciphertext)
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestAEADNonceUnique(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	aead, err := NewAEAD(key)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	plaintext := []byte("test data")
	ciphertexts := make([]string, 1000)

	for i := 0; i < 1000; i++ {
		ct, err := aead.Seal(plaintext)
		if err != nil {
			t.Fatalf("seal failed at iteration %d: %v", i, err)
		}
		ciphertexts[i] = string(ct)
	}

	// Check all ciphertexts are unique
	seen := make(map[string]bool)
	for i, ct := range ciphertexts {
		if seen[ct] {
			t.Errorf("duplicate ciphertext at iteration %d", i)
		}
		seen[ct] = true
	}
}

func TestAEADCounterExhaustion(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	aead, err := NewAEAD(key)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	// Set counter near max
	aead.counter = ^uint64(0) - 1

	// First seal should work
	_, err = aead.Seal([]byte("test"))
	if err != nil {
		t.Fatalf("first seal failed: %v", err)
	}

	// Second seal should fail (counter exhausted)
	_, err = aead.Seal([]byte("test"))
	if err == nil {
		t.Error("expected error on counter exhaustion, got nil")
	}
}

func TestDeriveKeys(t *testing.T) {
	shared := make([]byte, 32)
	nonceS := make([]byte, 16)
	nonceC := make([]byte, 16)

	if _, err := rand.Read(shared); err != nil {
		t.Fatalf("failed to generate shared: %v", err)
	}
	if _, err := rand.Read(nonceS); err != nil {
		t.Fatalf("failed to generate nonceS: %v", err)
	}
	if _, err := rand.Read(nonceC); err != nil {
		t.Fatalf("failed to generate nonceC: %v", err)
	}

	c2s, s2c, err := DeriveKeys(shared, nonceS, nonceC)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	if len(c2s) != 32 {
		t.Errorf("c2s key length mismatch: got %d, want 32", len(c2s))
	}
	if len(s2c) != 32 {
		t.Errorf("s2c key length mismatch: got %d, want 32", len(s2c))
	}

	// Test determinism
	c2s2, s2c2, err := DeriveKeys(shared, nonceS, nonceC)
	if err != nil {
		t.Fatalf("DeriveKeys second call failed: %v", err)
	}

	if !bytes.Equal(c2s, c2s2) {
		t.Error("c2s keys not deterministic")
	}
	if !bytes.Equal(s2c, s2c2) {
		t.Error("s2c keys not deterministic")
	}
}

func TestHKDFReadError(t *testing.T) {
	shared := make([]byte, 32)
	rand.Read(shared)
	nonceS := make([]byte, 16)
	rand.Read(nonceS)
	nonceC := make([]byte, 16)
	rand.Read(nonceC)

	c2s, s2c, err := DeriveKeys(shared, nonceS, nonceC)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	if len(c2s) != 32 || len(s2c) != 32 {
		t.Errorf("key length mismatch: c2s=%d, s2c=%d", len(c2s), len(s2c))
	}
}

func TestSessionSeed(t *testing.T) {
	psk := []byte("test-pre-shared-key-32-bytes!!")
	nonceC := make([]byte, 16)
	nonceS := make([]byte, 16)

	if _, err := rand.Read(nonceC); err != nil {
		t.Fatalf("failed to generate nonceC: %v", err)
	}
	if _, err := rand.Read(nonceS); err != nil {
		t.Fatalf("failed to generate nonceS: %v", err)
	}

	seed1 := SessionSeed(psk, nonceC, nonceS)
	seed2 := SessionSeed(psk, nonceC, nonceS)

	if seed1 != seed2 {
		t.Error("SessionSeed not deterministic")
	}

	// Different inputs should produce different seeds
	nonceC2 := make([]byte, 16)
	if _, err := rand.Read(nonceC2); err != nil {
		t.Fatalf("failed to generate nonceC2: %v", err)
	}
	seed3 := SessionSeed(psk, nonceC2, nonceS)

	if seed1 == seed3 {
		t.Error("SessionSeed should differ with different nonceC")
	}
}

func TestNewAEADInvalidKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33, 64} {
		if _, err := NewAEAD(make([]byte, n)); err == nil {
			t.Errorf("key size %d: expected error", n)
		}
	}
}

func TestAEADOpenTampered(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tx, _ := NewAEAD(key)
	plaintext := []byte("secret message")
	ct, err := tx.Seal(plaintext)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}

	mutations := []func([]byte){
		func(b []byte) { b[0] ^= 0x01 },
		func(b []byte) { b[len(b)-1] ^= 0x80 },
		func(b []byte) { b[len(b)-16] ^= 0xFF },
	}

	for i, mutate := range mutations {
		rx, _ := NewAEAD(key) // fresh instance for each mutation
		bad := append([]byte{}, ct...)
		mutate(bad)
		if _, err := rx.Open(bad); err == nil {
			t.Fatalf("mutation %d: tampered ciphertext accepted", i)
		}
	}
}

func TestAEADOpenTruncated(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	rx, _ := NewAEAD(key)
	// shorter than Poly1305 tag (16B) → error, NOT panic
	if _, err := rx.Open([]byte{1, 2, 3}); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
}

func TestAEADDirectionalRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tx, _ := NewAEAD(key)
	rx, _ := NewAEAD(key) // separate instances — as in protocol

	msg := []byte("probe")
	ct, err := tx.Seal(msg)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}

	got, err := rx.Open(ct)
	if err != nil || !bytes.Equal(msg, got) {
		t.Fatalf("directional roundtrip failed: %v", err)
	}
}

func TestX25519KeyAgreement(t *testing.T) {
// Generate key pairs for both parties
privA, pubA, err := GenerateX25519KeyPair()
if err != nil {
t.Fatalf("GenerateX25519KeyPair A failed: %v", err)
}

privB, pubB, err := GenerateX25519KeyPair()
if err != nil {
t.Fatalf("GenerateX25519KeyPair B failed: %v", err)
}

// Both parties compute shared secret
sharedA, err := X25519(privA[:], pubB[:])
if err != nil {
t.Fatalf("X25519 A failed: %v", err)
}

sharedB, err := X25519(privB[:], pubA[:])
if err != nil {
t.Fatalf("X25519 B failed: %v", err)
}

// Shared secrets must match
if !bytes.Equal(sharedA, sharedB) {
t.Error("shared secrets do not match")
}

// Shared secret must be 32 bytes
if len(sharedA) != 32 {
t.Errorf("shared secret length mismatch: got %d, want 32", len(sharedA))
}
}

func TestX25519InvalidKeyLength(t *testing.T) {
shortKey := make([]byte, 16)
longKey := make([]byte, 64)
validKey := make([]byte, 32)

if _, err := X25519(shortKey, validKey); err == nil {
t.Error("X25519 accepted short private key")
}
if _, err := X25519(longKey, validKey); err == nil {
t.Error("X25519 accepted long private key")
}
if _, err := X25519(validKey, shortKey); err == nil {
t.Error("X25519 accepted short public key")
}
}
