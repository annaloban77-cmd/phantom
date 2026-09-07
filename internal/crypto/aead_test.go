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
