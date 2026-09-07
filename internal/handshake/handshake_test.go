package handshake

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/phantom-tunnel/phantom/internal/common"
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

	// Write ClientHello with old timestamp
	var pubKey [32]byte
	var nonce [16]byte
	rand.Read(pubKey[:])
	rand.Read(nonce[:])

	ch := &ClientHello{
		Type:      uint16(common.HsClientHello),
		PubKey:    pubKey,
		Timestamp: uint64(time.Now().Add(-2 * time.Minute).UnixMilli()), // 2 min ago
		Nonce:     nonce,
	}
	chBuf := MarshalClientHello(ch)
	clientConn.Write(chBuf)

	// Server should reject
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, err := serverHS.Perform(serverConn, "127.0.0.1")
		if err != ErrTimestampExpired {
			t.Errorf("expected ErrTimestampExpired, got %v", err)
		}
	}()
	<-done
}

// Helper function to create bidirectional pipe
func netPipe() (io.ReadWriter, io.ReadWriter) {
	// Using simple pipe for testing
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1 := &pipeConn{r: r1, w: w2}
	c2 := &pipeConn{r: r2, w: w1}

	return c1, c2
}

// pipeConn implements io.ReadWriter for testing
type pipeConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipeConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func (p *pipeConn) Write(b []byte) (int, error) {
	return p.w.Write(b)
}
