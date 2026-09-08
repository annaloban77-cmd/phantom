package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/phantom-tunnel/phantom/internal/common"
	"github.com/phantom-tunnel/phantom/internal/handshake"
	utls "github.com/refraction-networking/utls"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

// newMockWSServer поднимает TLS WS-сервер: апгрейд → серверная сторона
// PHANTOM handshake (handshake.NewServerHandshake) → эхо зашифрованных
// пакетов. Моделирует origin за Cloudflare Worker (WS binary ↔ TCP):
// PHANTOM-протокол идёт внутри WS binary frames.
func newMockWSServer(psk []byte) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()

		stream := newWSStream(ws)
		hs := handshake.NewServerHandshake([]handshake.PSKUser{{Key: psk, Name: "test"}})
		aeadRx, aeadTx, _, err := hs.Perform(stream, r.RemoteAddr)
		if err != nil {
			return
		}

		tun := NewTunnelConn(stream, ws, aeadTx, aeadRx)
		for {
			msgType, payload, err := tun.Read()
			if err != nil {
				return
			}
			if err := tun.Write(msgType, payload); err != nil {
				return
			}
		}
	}))
}

func mockWSSURL(srv *httptest.Server) string {
	return "wss" + strings.TrimPrefix(srv.URL, "https") + "/"
}

// TestModeBRoundTrip: mock WS relay (серверная сторона через
// handshake.NewServerHandshake), round-trip пакетов клиент→сервер→клиент
func TestModeBRoundTrip(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	srv := newMockWSServer(psk)
	defer srv.Close()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := DialModeB(ctx, mockWSSURL(srv), psk, &spec, testTLSOptions()...)
	if err != nil {
		t.Fatalf("DialModeB failed: %v", err)
	}
	defer conn.Close()

	messages := []string{"mode-b hello", "second message", "final packet"}
	for i, msg := range messages {
		if err := conn.Write(common.MsgData, []byte(msg)); err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
		msgType, data, err := conn.Read()
		if err != nil {
			t.Fatalf("Read %d failed: %v", i, err)
		}
		if msgType != common.MsgData {
			t.Errorf("message %d: expected MsgData, got %v", i, msgType)
		}
		if string(data) != msg {
			t.Errorf("message %d: expected %q, got %q", i, msg, data)
		}
	}
}

// TestModeBUsesUTLS: применён ClientHelloSpec (не nil) и согласован TLS 1.3
func TestModeBUsesUTLS(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	srv := newMockWSServer(psk)
	defer srv.Close()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := DialModeB(ctx, mockWSSURL(srv), psk, &spec, testTLSOptions()...)
	if err != nil {
		t.Fatalf("DialModeB failed: %v", err)
	}
	defer conn.Close()

	if conn.TLSConn() == nil {
		t.Fatal("utls connection not captured: spec was not applied over utls")
	}
	cs := conn.TLSConn().ConnectionState()
	if cs.Version != uint16(tls.VersionTLS13) {
		t.Errorf("expected TLS 1.3, got 0x%04x", cs.Version)
	}
	if cs.CipherSuite == 0 {
		t.Error("no cipher suite negotiated")
	}
	if !cs.HandshakeComplete {
		t.Error("TLS handshake not complete")
	}
}

// TestModeBWrongPSK: сервер отклоняет handshake при неверном PSK
func TestModeBWrongPSK(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	wrongPSK := make([]byte, 32)
	if _, err := rand.Read(wrongPSK); err != nil {
		t.Fatal(err)
	}

	srv := newMockWSServer(psk)
	defer srv.Close()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = DialModeB(ctx, mockWSSURL(srv), wrongPSK, &spec, testTLSOptions()...)
	if err == nil {
		t.Fatal("expected error with wrong PSK, got nil")
	}
}
