package crypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

// DeriveKeys derives client-to-server and server-to-client keys using HKDF-SHA256
func DeriveKeys(shared, nonceS, nonceC []byte) (c2s, s2c []byte, err error) {
	salt := append(append([]byte{}, nonceS...), nonceC...)

	r := hkdf.New(sha256.New, shared, salt, []byte("phantom-v2.1-session"))

	km := make([]byte, 64)
	if _, err = r.Read(km); err != nil {
		return nil, nil, err
	}

	return km[:32], km[32:], nil
}

// SessionSeed computes a deterministic session seed from PSK and nonces
func SessionSeed(psk, nonceC, nonceS []byte) [32]byte {
	h := sha256.New()
	h.Write(psk)
	h.Write(nonceC)
	h.Write(nonceS)

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
