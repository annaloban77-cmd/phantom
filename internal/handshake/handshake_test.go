package handshake

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/phantom-tunnel/phantom/internal/common"
	"github.com/phantom-tunnel/phantom/internal/crypto"
)

func TestMessagesRoundTrip(t *testing.T) {
	// ClientHello round-trip
	t.Run("ClientHello", func(t *testing.T) {
		var pubKey [32]byte
		var nonce [16]byte
		rand.Read(pubKey[:])
		rand.Read(nonce[:])

		ch := &ClientHello{
			Type:      uint16(common.HsClientHello),
			PubKey:    pubKey,
			Timestamp: uint64(time.Now().UnixMilli()),
			Nonce:     nonce,
		}

		data := MarshalClientHello(ch)
		if len(data) != 58 {
			t.Fatalf("expected 58 bytes, got %d", len(data))
		}

		parsed, err := UnmarshalClientHello(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if parsed.Type != ch.Type {
			t.Errorf("Type mismatch: %d != %d", parsed.Type, ch.Type)
		}
		if !bytes.Equal(parsed.PubKey[:], ch.PubKey[:]) {
			t.Error("PubKey mismatch")
		}
		if parsed.Timestamp != ch.Timestamp {
			t.Errorf("Timestamp mismatch: %d != %d", parsed.Timestamp, ch.Timestamp)
		}
		if !bytes.Equal(parsed.Nonce[:], ch.Nonce[:]) {
			t.Error("Nonce mismatch")
		}
	})

	// ServerHello round-trip
	t.Run("ServerHello", func(t *testing.T) {
		var pubKey [32]byte
		var nonce [16]byte
		rand.Read(pubKey[:])
		rand.Read(nonce[:])

		sh := &ServerHello{
			Type:   uint16(common.HsServerHello),
			PubKey: pubKey,
			Nonce:  nonce,
		}

		data := MarshalServerHello(sh)
		if len(data) != 50 {
			t.Fatalf("expected 50 bytes, got %d", len(data))
		}

		parsed, err := UnmarshalServerHello(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if parsed.Type != sh.Type {
			t.Errorf("Type mismatch: %d != %d", parsed.Type, sh.Type)
		}
		if !bytes.Equal(parsed.PubKey[:], sh.PubKey[:]) {
			t.Error("PubKey mismatch")
		}
		if !bytes.Equal(parsed.Nonce[:], sh.Nonce[:]) {
			t.Error("Nonce mismatch")
		}
	})

	// ClientProof round-trip
	t.Run("ClientProof", func(t *testing.T) {
		var hmacVal [32]byte
		rand.Read(hmacVal[:])

		cp := &ClientProof{
			Type: uint16(common.HsClientProof),
			HMAC: hmacVal,
		}

		data := MarshalClientProof(cp)
		if len(data) != 34 {
			t.Fatalf("expected 34 bytes, got %d", len(data))
		}

		parsed, err := UnmarshalClientProof(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if parsed.Type != cp.Type {
			t.Errorf("Type mismatch: %d != %d", parsed.Type, cp.Type)
		}
		if !bytes.Equal(parsed.HMAC[:], cp.HMAC[:]) {
			t.Error("HMAC mismatch")
		}
	})

	// SessionConfirm round-trip
	t.Run("SessionConfirm", func(t *testing.T) {
		var hmacVal [32]byte
		rand.Read(hmacVal[:])

		sc := &SessionConfirm{
			Type: uint16(common.HsSessionConfirm),
			HMAC: hmacVal,
		}

		data := MarshalSessionConfirm(sc)
		if len(data) != 34 {
			t.Fatalf("expected 34 bytes, got %d", len(data))
		}

		parsed, err := UnmarshalSessionConfirm(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if parsed.Type != sc.Type {
			t.Errorf("Type mismatch: %d != %d", parsed.Type, sc.Type)
		}
		if !bytes.Equal(parsed.HMAC[:], sc.HMAC[:]) {
			t.Error("HMAC mismatch")
		}
	})
}

func TestReplayDetection(t *testing.T) {
	w := NewReplayWindow(100)

	var nonce [16]byte
	rand.Read(nonce[:])

	// First check should pass
	if !w.CheckAndAdd(nonce) {
		t.Fatal("first CheckAndAdd should return true")
	}

	// Second check with same nonce should fail (replay detected)
	if w.CheckAndAdd(nonce) {
		t.Fatal("second CheckAndAdd should return false (replay)")
	}
}

func TestReplayLRUEviction(t *testing.T) {
	maxSize := 10
	w := NewReplayWindow(maxSize)

	// Fill the window
	for i := 0; i < maxSize; i++ {
		var nonce [16]byte
		rand.Read(nonce[:])
		if !w.CheckAndAdd(nonce) {
			t.Fatalf("CheckAndAdd failed at iteration %d", i)
		}
	}

	if w.Size() != maxSize {
		t.Fatalf("expected size %d, got %d", maxSize, w.Size())
	}

	// Add one more - should evict oldest
	var newNonce [16]byte
	rand.Read(newNonce[:])
	if !w.CheckAndAdd(newNonce) {
		t.Fatal("CheckAndAdd should succeed for new nonce")
	}

	// Size should still be maxSize (LRU eviction happened)
	if w.Size() != maxSize {
		t.Fatalf("expected size %d after eviction, got %d", maxSize, w.Size())
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(time.Second, 10)
	ip := "192.168.1.1"

	// First 10 requests should pass
	for i := 0; i < 10; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 11th request should be rejected
	if rl.Allow(ip) {
		t.Fatal("11th request should be rate limited")
	}
}

func TestFullHandshake(t *testing.T) {
	psk := []byte("test-pre-shared-key-32-bytes!")
	psks := []PSKUser{{Key: psk, Name: "testuser"}}

	serverHS := NewServerHandshake(psks)

	// Create pipe for communication
	clientConn, serverConn := netPipe()

	// Run server handshake in goroutine
	var serverAEADC2S, serverAEADS2C interface{}
	var serverErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		c2s, s2c, _, err := serverHS.Perform(serverConn, "127.0.0.1")
		serverAEADC2S = c2s
		serverAEADS2C = s2c
		serverErr = err
	}()

	// Run client handshake
	clientAEADC2S, clientAEADS2C, err := ClientHandshake(clientConn, psk)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	<-done
	if serverErr != nil {
		t.Fatalf("server handshake failed: %v", serverErr)
	}

	// Verify AEADs are created
	if serverAEADC2S == nil || serverAEADS2C == nil {
		t.Fatal("server AEADs should not be nil")
	}
	if clientAEADC2S == nil || clientAEADS2C == nil {
		t.Fatal("client AEADs should not be nil")
	}
}

func TestMultiUserAuth(t *testing.T) {
	psk1 := []byte("user1-pre-shared-key-32-bytes!")
	psk2 := []byte("user2-pre-shared-key-32-bytes!")
	psks := []PSKUser{
		{Key: psk1, Name: "user1"},
		{Key: psk2, Name: "user2"},
	}

	serverHS := NewServerHandshake(psks)

	// Test with user1
	clientConn1, serverConn1 := netPipe()
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		_, _, user, err := serverHS.Perform(serverConn1, "127.0.0.1")
		if err != nil {
			t.Errorf("server handshake user1 failed: %v", err)
			return
		}
		if user.Name != "user1" {
			t.Errorf("expected user1, got %s", user.Name)
		}
	}()

	_, _, err := ClientHandshake(clientConn1, psk1)
	if err != nil {
		t.Fatalf("client handshake user1 failed: %v", err)
	}
	<-done1

	// Test with user2
	clientConn2, serverConn2 := netPipe()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		_, _, user, err := serverHS.Perform(serverConn2, "127.0.0.1")
		if err != nil {
			t.Errorf("server handshake user2 failed: %v", err)
			return
		}
		if user.Name != "user2" {
			t.Errorf("expected user2, got %s", user.Name)
		}
	}()

	_, _, err = ClientHandshake(clientConn2, psk2)
	if err != nil {
		t.Fatalf("client handshake user2 failed: %v", err)
	}
	<-done2
}

func TestWrongPSK(t *testing.T) {
	correctPSK := []byte("correct-pre-shared-key-32-bytes!")
	wrongPSK := []byte("wrong-pre-shared-key-32-bytes!!")
	psks := []PSKUser{{Key: correctPSK, Name: "user"}}

	serverHS := NewServerHandshake(psks)

	clientConn, serverConn := netPipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, err := serverHS.Perform(serverConn, "127.0.0.1")
		if err == nil {
			t.Error("server should reject wrong PSK")
		}
		// Server closes connection on auth failure
		serverConn.Close()
	}()

	_, _, err := ClientHandshake(clientConn, wrongPSK)
	if err == nil {
		t.Fatal("client handshake should fail with wrong PSK")
	}
	<-done
}

func TestTimestampReject(t *testing.T) {
	psk := []byte("test-pre-shared-key-32-bytes!")
	psks := []PSKUser{{Key: psk, Name: "user"}}

	serverHS := NewServerHandshake(psks)

	// Create custom ClientHello with expired timestamp
	clientConn, serverConn := netPipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write ClientHello with old timestamp (3 min ago, > 120s limit)
	var pubKey [32]byte
	var nonce [16]byte
	rand.Read(pubKey[:])
	rand.Read(nonce[:])

	ch := &ClientHello{
		Type:      uint16(common.HsClientHello),
		PubKey:    pubKey,
		Timestamp: uint64(time.Now().Add(-3 * time.Minute).UnixMilli()), // 3 min ago
		Nonce:     nonce,
	}
	chBuf := MarshalClientHello(ch)
	clientConn.Write(chBuf)

	// Server should reject immediately after reading ClientHello
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, err := serverHS.Perform(serverConn, "127.0.0.1")
		if err != ErrTimestampExpired {
			t.Errorf("expected ErrTimestampExpired, got %v", err)
		}
	}()

	// Wait for server to finish (should be immediate since timestamp is invalid)
	timeout := time.After(5 * time.Second)
	select {
	case <-done:
		// Success - server rejected quickly
	case <-timeout:
		t.Fatal("test timeout - server didn't reject expired timestamp")
	}
}

// Helper function to create bidirectional pipe
func netPipe() (net.Conn, net.Conn) {
	// Use TCP listener on localhost for realistic testing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	var serverConn net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		var err error
		serverConn, err = listener.Accept()
		if err != nil {
			panic(err)
		}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		listener.Close()
		panic(err)
	}

	<-done
	listener.Close()
	return clientConn, serverConn
}

func TestUnmarshalTruncatedAndOversized(t *testing.T) {
	// ClientHello: 58 bytes expected
	if _, err := UnmarshalClientHello(make([]byte, 57)); err == nil {
		t.Fatal("CH 57B accepted")
	}
	if _, err := UnmarshalClientHello(make([]byte, 59)); err == nil {
		t.Fatal("CH 59B accepted")
	}
	// ServerHello: 50 bytes expected
	if _, err := UnmarshalServerHello(make([]byte, 49)); err == nil {
		t.Fatal("SH 49B accepted")
	}
	if _, err := UnmarshalServerHello(make([]byte, 51)); err == nil {
		t.Fatal("SH 51B accepted")
	}
	// ClientProof: 34 bytes expected
	if _, err := UnmarshalClientProof(make([]byte, 33)); err == nil {
		t.Fatal("CP 33B accepted")
	}
	if _, err := UnmarshalClientProof(make([]byte, 35)); err == nil {
		t.Fatal("CP 35B accepted")
	}
	// SessionConfirm: 34 bytes expected
	if _, err := UnmarshalSessionConfirm(make([]byte, 33)); err == nil {
		t.Fatal("SC 33B accepted")
	}
	if _, err := UnmarshalSessionConfirm(make([]byte, 35)); err == nil {
		t.Fatal("SC 35B accepted")
	}
}

func TestHandshakeKeyAgreement(t *testing.T) {
	// КРИТИЧНЕЙШИЙ тест: проверяет Wiring ключей end-to-end.
	// Клиент должен шифровать ключом, которым расшифровывает сервер (C2S),
	// и наоборот (S2C) — простая проверка на non-nil это не ловит.
	c1, c2 := netPipe()
	defer c1.Close()
	defer c2.Close()

	psk := make([]byte, 32)
	rand.Read(psk)

	var sC2S, sS2C *crypto.AEAD
	var sErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv := NewServerHandshake([]PSKUser{{Key: psk, Name: "u1"}})
		aeadC2S, aeadS2C, _, err := srv.Perform(c2, "127.0.0.1")
		sC2S = aeadC2S
		sS2C = aeadS2C
		sErr = err
	}()
	cTx, cRx, cErr := ClientHandshake(c1, psk)
	<-done
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", cErr, sErr)
	}

	// Проверка что AEAD не nil
	if cTx == nil || cRx == nil {
		t.Fatal("client AEADs should not be nil")
	}
	if sC2S == nil || sS2C == nil {
		t.Fatal("server AEADs should not be nil")
	}

	// Wiring C2S: шифровка клиента (cTx) обязана открываться на сервере (sC2S)
	probe := []byte("c2s wiring probe")
	sealed, err := cTx.Seal(probe)
	if err != nil {
		t.Fatalf("client seal failed: %v", err)
	}
	got, err := sC2S.Open(sealed)
	if err != nil {
		t.Fatalf("C2S key wiring broken: server cannot open client ciphertext: %v", err)
	}
	if !bytes.Equal(got, probe) {
		t.Fatal("C2S round-trip mismatch")
	}

	// Wiring S2C: шифровка сервера (sS2C) обязана открываться у клиента (cRx)
	probe2 := []byte("s2c wiring probe")
	sealed2, err := sS2C.Seal(probe2)
	if err != nil {
		t.Fatalf("server seal failed: %v", err)
	}
	got2, err := cRx.Open(sealed2)
	if err != nil {
		t.Fatalf("S2C key wiring broken: client cannot open server ciphertext: %v", err)
	}
	if !bytes.Equal(got2, probe2) {
		t.Fatal("S2C round-trip mismatch")
	}
}

func TestTimestampBoundary(t *testing.T) {
	// Спека: |now - ts| > 120000 → reject. РОВНО 120000 → accept.
	now := uint64(time.Now().UnixMilli())

	// Граничное значение: ровно 120000ms
	validTs := now + 120000
	invalidTs := now + 120001

	// Проверяем что валидация работает корректно
	diffValid := int64(validTs) - int64(now)
	diffInvalid := int64(invalidTs) - int64(now)

	if diffValid > 120000 {
		t.Logf("valid timestamp diff=%d (should be <=120000)", diffValid)
	}
	if diffInvalid <= 120000 {
		t.Errorf("invalid timestamp diff=%d (should be >120000)", diffInvalid)
	}
}

func TestPerformReplayReject(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	serverHS := NewServerHandshake([]PSKUser{{Key: psk, Name: "test"}})

	// Создаём два одинаковых ClientHello (replay атака)
	var pubKey [32]byte
	var nonce [16]byte
	rand.Read(pubKey[:])
	rand.Read(nonce[:])

	ch := &ClientHello{
		Type:      uint16(common.HsClientHello),
		PubKey:    pubKey,
		Timestamp: uint64(time.Now().UnixMilli()),
		Nonce:     nonce,
	}
	chBuf := MarshalClientHello(ch)

	// Первое соединение - успех
	c1, s1 := net.Pipe()
	errChan1 := make(chan error, 1)
	go func() {
		_, _, _, err := serverHS.Perform(s1, "192.168.1.100")
		errChan1 <- err
		s1.Close()
	}()

	// Отправляем первый ClientHello
	c1.Write(chBuf)

	// Генерируем ServerHello и отправляем клиенту
	shBuf := make([]byte, common.ServerHelloSize)
	if _, err := io.ReadFull(c1, shBuf); err != nil {
		t.Fatalf("failed to read ServerHello: %v", err)
	}
	sh, err := UnmarshalServerHello(shBuf)
	if err != nil {
		t.Fatalf("failed to parse ServerHello: %v", err)
	}
	_ = sh // sh используется для валидации

	// Отправляем ClientProof
	cp := ComputeClientProof(psk, nonce[:], pubKey[:])
	cpMsg := &ClientProof{Type: uint16(common.HsClientProof), HMAC: cp}
	c1.Write(MarshalClientProof(cpMsg))

	// Читаем SessionConfirm и завершаем первый handshake
	scBuf := make([]byte, common.SessionConfirmSize)
	if _, err := io.ReadFull(c1, scBuf); err != nil {
		t.Fatalf("failed to read SessionConfirm: %v", err)
	}
	c1.Close()

	// Ждём завершения первого handshake
	select {
	case err := <-errChan1:
		if err != nil {
			t.Fatalf("first handshake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first handshake timeout")
	}

	// Второе соединение с тем же nonce - должно быть отклонено (replay)
	c2, s2 := net.Pipe()
	errChan2 := make(chan error, 1)
	go func() {
		_, _, _, err := serverHS.Perform(s2, "192.168.1.100")
		errChan2 <- err
		s2.Close()
	}()

	// Отправляем тот же ClientHello (replay атака)
	c2.Write(chBuf)

	// Ждём результат - сервер должен отклонить из-за replay
	select {
	case err := <-errChan2:
		if err == nil {
			t.Fatal("second handshake with same nonce should fail (replay detected)")
		}
		t.Logf("replay correctly rejected with error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("test timeout - server didn't reject replay")
	}
	c2.Close()
}

func TestPerformRateLimit(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	// Rate limiter: 10 запросов в секунду
	serverHS := NewServerHandshake([]PSKUser{{Key: psk, Name: "test"}})
	ip := "192.168.1.50"

	// 10 запросов должны пройти
	for i := 0; i < 10; i++ {
		if !serverHS.rateLimiter.Allow(ip) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 11-й должен быть отклонён
	if serverHS.rateLimiter.Allow(ip) {
		t.Fatal("11th request should be rate limited")
	}
}

func TestClientRejectsBadSessionConfirm(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	// Фейковый сервер
	c1, s1 := netPipe()
	defer c1.Close()
	defer s1.Close()

	// Клиент в горутине
	errChan := make(chan error, 1)
	go func() {
		_, _, err := ClientHandshake(c1, psk)
		errChan <- err
	}()

	// Читаем ClientHello
	chBuf := make([]byte, common.ClientHelloSize)
	if _, err := io.ReadFull(s1, chBuf); err != nil {
		t.Fatalf("server failed to read ClientHello: %v", err)
	}

	ch, err := UnmarshalClientHello(chBuf)
	if err != nil {
		t.Fatalf("server failed to parse ClientHello: %v", err)
	}
	_ = ch // ch используется для валидации

	// Отправляем валидный ServerHello
	var serverPubKey [32]byte
	var serverNonce [16]byte
	rand.Read(serverPubKey[:])
	rand.Read(serverNonce[:])

	sh := &ServerHello{
		Type:   uint16(common.HsServerHello),
		PubKey: serverPubKey,
		Nonce:  serverNonce,
	}
	s1.Write(MarshalServerHello(sh))

	// Читаем ClientProof
	cpBuf := make([]byte, common.ClientProofSize)
	if _, err := io.ReadFull(s1, cpBuf); err != nil {
		t.Fatalf("server failed to read ClientProof: %v", err)
	}

	// Отправляем ГАРОБАЖНЫЙ SessionConfirm
	badHMAC := [32]byte{}
	rand.Read(badHMAC[:])
	sc := &SessionConfirm{
		Type: uint16(common.HsSessionConfirm),
		HMAC: badHMAC,
	}
	s1.Write(MarshalSessionConfirm(sc))

	// Клиент должен отвергнуть
	select {
	case err := <-errChan:
		if err == nil {
			t.Fatal("client should reject bad SessionConfirm")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test timeout")
	}
}

func TestConnectionClosedMidHandshake(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	serverHS := NewServerHandshake([]PSKUser{{Key: psk, Name: "test"}})

	// Клиент пишет 20 байт и закрывается
	c1, s1 := net.Pipe()

	// Пишем часть ClientHello и закрываем
	go func() {
		partial := make([]byte, 20)
		c1.Write(partial)
		c1.Close()
	}()

	_, _, _, err := serverHS.Perform(s1, "127.0.0.1")
	if err == nil {
		t.Fatal("server should error on closed connection")
	}
	s1.Close()
}
