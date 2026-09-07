package handshake

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/phantom-tunnel/phantom/internal/common"
	"github.com/phantom-tunnel/phantom/internal/crypto"
)

var (
	ErrInvalidMessage     = errors.New("invalid handshake message")
	ErrReplayDetected     = errors.New("replay attack detected")
	ErrTimestampExpired   = errors.New("client timestamp expired")
	ErrAuthFailed         = errors.New("authentication failed")
	ErrRateLimited        = errors.New("rate limit exceeded")
	ErrHandshakeTimeout   = errors.New("handshake timeout")
)

// PSKUser представляет пользователя с pre-shared key
type PSKUser struct {
	Key  []byte
	Name string
}

// RateLimiter реализует sliding window rate limiting
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	window   time.Duration
	limit    int
}

// NewRateLimiter создаёт rate limiter с окном и лимитом запросов
func NewRateLimiter(window time.Duration, limit int) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		limit:    limit,
	}
}

// Allow проверяет можно ли сделать запрос с данного IP
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Фильтруем старые запросы
	var valid []time.Time
	for _, ts := range rl.requests[ip] {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}

	// Проверяем лимит
	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	// Добавляем текущий запрос
	rl.requests[ip] = append(valid, now)
	return true
}

// ServerHandshake управляет серверной стороной handshake
type ServerHandshake struct {
	psks        []PSKUser
	replay      *ReplayWindow
	rateLimiter *RateLimiter
	mu          sync.Mutex
}

// NewServerHandshake создаёт новый серверный handshake менеджер
func NewServerHandshake(psks []PSKUser) *ServerHandshake {
	return &ServerHandshake{
		psks:        psks,
		replay:      NewReplayWindow(10000),
		rateLimiter: NewRateLimiter(time.Second, 10), // 10 req/s per IP
	}
}

// Perform выполняет серверную сторону handshake протокола
// Возвращает AEAD для incoming (C2S) и outgoing (S2C) трафика
func (h *ServerHandshake) Perform(conn io.ReadWriter, remoteIP string) (*crypto.AEAD, *crypto.AEAD, *PSKUser, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Проверка rate limit
	if !h.rateLimiter.Allow(remoteIP) {
		return nil, nil, nil, ErrRateLimited
	}

	// 1. Read ClientHello (58 bytes)
	chBuf := make([]byte, common.ClientHelloSize)
	if _, err := io.ReadFull(conn, chBuf); err != nil {
		return nil, nil, nil, err
	}

	clientHello, err := UnmarshalClientHello(chBuf)
	if err != nil {
		return nil, nil, nil, err
	}

	// 2. Validate timestamp (±120 seconds)
	now := time.Now().UnixMilli()
	tsDiff := now - int64(clientHello.Timestamp)
	if tsDiff < -120000 || tsDiff > 120000 {
		return nil, nil, nil, ErrTimestampExpired
	}

	// 3. Replay check
	if !h.replay.CheckAndAdd(clientHello.Nonce) {
		return nil, nil, nil, ErrReplayDetected
	}

	// 4. Generate ephemeral X25519 keypair
	serverPrivKey, serverPubKey, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, nil, err
	}

	// 5. ECDH shared secret
	sharedSecret, err := crypto.X25519(serverPrivKey[:], clientHello.PubKey[:])
	if err != nil {
		return nil, nil, nil, err
	}

	// 6. Generate server nonce
	var serverNonce [16]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		return nil, nil, nil, err
	}

	// 7. Send ServerHello
	serverHello := &ServerHello{
		Type:   uint16(common.HsServerHello),
		PubKey: serverPubKey,
		Nonce:  serverNonce,
	}
	shBuf := MarshalServerHello(serverHello)
	if _, err := conn.Write(shBuf); err != nil {
		return nil, nil, nil, err
	}

	// 8. Read ClientProof (34 bytes)
	cpBuf := make([]byte, common.ClientProofSize)
	if _, err := io.ReadFull(conn, cpBuf); err != nil {
		return nil, nil, nil, err
	}

	clientProof, err := UnmarshalClientProof(cpBuf)
	if err != nil {
		return nil, nil, nil, err
	}

	// 8b. Check ALL PSKs constant-time (no early break)
	found := false
	var matchedUser *PSKUser
	for i := range h.psks {
		expectedProof := ComputeClientProof(h.psks[i].Key, clientHello.Nonce[:], clientHello.PubKey[:])
		if subtle.ConstantTimeCompare(clientProof.HMAC[:], expectedProof[:]) == 1 {
			found = true
			matchedUser = &h.psks[i]
		}
	}

	if !found {
		return nil, nil, nil, ErrAuthFailed
	}

	// 9. Derive session keys
	c2sKey, s2cKey, err := crypto.DeriveKeys(sharedSecret, serverNonce[:], clientHello.Nonce[:])
	if err != nil {
		return nil, nil, nil, err
	}

	aeadC2S, err := crypto.NewAEAD(c2sKey)
	if err != nil {
		return nil, nil, nil, err
	}

	aeadS2C, err := crypto.NewAEAD(s2cKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// 10. Send SessionConfirm
	sessionConfirm := &SessionConfirm{
		Type: uint16(common.HsSessionConfirm),
		HMAC: ComputeSessionConfirm(matchedUser.Key, clientHello.Nonce[:], serverNonce[:]),
	}
	scBuf := MarshalSessionConfirm(sessionConfirm)
	if _, err := conn.Write(scBuf); err != nil {
		return nil, nil, nil, err
	}

	return aeadC2S, aeadS2C, matchedUser, nil
}

// ClientHandshake выполняет клиентскую сторону handshake
func ClientHandshake(conn io.ReadWriter, psk []byte) (*crypto.AEAD, *crypto.AEAD, error) {
	// Generate ephemeral X25519 keypair
	clientPrivKey, clientPubKey, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Generate client nonce
	var clientNonce [16]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return nil, nil, err
	}

	// Send ClientHello
	clientHello := &ClientHello{
		Type:      uint16(common.HsClientHello),
		PubKey:    clientPubKey,
		Timestamp: uint64(time.Now().UnixMilli()),
		Nonce:     clientNonce,
	}
	chBuf := MarshalClientHello(clientHello)
	if _, err := conn.Write(chBuf); err != nil {
		return nil, nil, err
	}

	// Read ServerHello (50 bytes)
	shBuf := make([]byte, common.ServerHelloSize)
	if _, err := io.ReadFull(conn, shBuf); err != nil {
		return nil, nil, err
	}

	serverHello, err := UnmarshalServerHello(shBuf)
	if err != nil {
		return nil, nil, err
	}

	// ECDH shared secret
	sharedSecret, err := crypto.X25519(clientPrivKey[:], serverHello.PubKey[:])
	if err != nil {
		return nil, nil, err
	}

	// Send ClientProof
	clientProof := &ClientProof{
		Type: uint16(common.HsClientProof),
		HMAC: ComputeClientProof(psk, clientNonce[:], clientPubKey[:]),
	}
	cpBuf := MarshalClientProof(clientProof)
	if _, err := conn.Write(cpBuf); err != nil {
		return nil, nil, err
	}

	// Read SessionConfirm (34 bytes)
	scBuf := make([]byte, common.SessionConfirmSize)
	if _, err := io.ReadFull(conn, scBuf); err != nil {
		return nil, nil, err
	}

	sessionConfirm, err := UnmarshalSessionConfirm(scBuf)
	if err != nil {
		return nil, nil, err
	}

	// Verify SessionConfirm
	expectedConfirm := ComputeSessionConfirm(psk, clientNonce[:], serverHello.Nonce[:])
	if subtle.ConstantTimeCompare(sessionConfirm.HMAC[:], expectedConfirm[:]) != 1 {
		return nil, nil, ErrAuthFailed
	}

	// Derive session keys
	s2cKey, c2sKey, err := crypto.DeriveKeys(sharedSecret, serverHello.Nonce[:], clientNonce[:])
	if err != nil {
		return nil, nil, err
	}

	aeadS2C, err := crypto.NewAEAD(s2cKey)
	if err != nil {
		return nil, nil, err
	}

	aeadC2S, err := crypto.NewAEAD(c2sKey)
	if err != nil {
		return nil, nil, err
	}

	return aeadC2S, aeadS2C, nil
}
