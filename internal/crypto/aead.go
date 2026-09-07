package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// AEAD provides authenticated encryption with associated data
type AEAD struct {
	aead    cipher.AEAD
	counter uint64
	mu      sync.Mutex
}

// NewAEAD creates a new AEAD instance with ChaCha20-Poly1305
func NewAEAD(key []byte) (*AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return &AEAD{
		aead:    a,
		counter: 0,
	}, nil
}

// nonce generates a 12-byte nonce from counter
func (a *AEAD) nonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

// Seal encrypts and authenticates plaintext
func (a *AEAD) Seal(pt []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.counter == ^uint64(0) {
		return nil, fmt.Errorf("nonce exhausted")
	}

	n := a.nonce(a.counter)
	a.counter++

	return a.aead.Seal(nil, n, pt, nil), nil
}

// Open decrypts and verifies ciphertext
func (a *AEAD) Open(ct []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.counter == ^uint64(0) {
		return nil, fmt.Errorf("nonce exhausted")
	}

	n := a.nonce(a.counter)
	a.counter++

	return a.aead.Open(nil, n, ct, nil)
}

// GenerateX25519KeyPair генерирует пару ключей X25519
func GenerateX25519KeyPair() ([32]byte, [32]byte, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return privateKey, [32]byte{}, err
	}

	// Clamp private key для X25519
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return privateKey, publicKey, nil
}

// X25519 вычисляет shared secret используя X25519 ECDH
func X25519(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != 32 || len(peerPublicKey) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}

	var result [32]byte
	var priv, pub [32]byte
	copy(priv[:], privateKey)
	copy(pub[:], peerPublicKey)

	curve25519.ScalarMult(&result, &priv, &pub)

	return result[:], nil
}
