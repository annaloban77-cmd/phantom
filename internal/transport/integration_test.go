package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/phantom-tunnel/phantom/internal/common"
	utls "github.com/refraction-networking/utls"
)

// mockTLSServer создает простой TLS сервер для тестирования
type mockTLSServer struct {
	listener net.Listener
	server   *http.Server
	psk      []byte
	mu       sync.Mutex
	lastErr  error
}

func newMockTLSServer(psk []byte) (*mockTLSServer, error) {
	cert, err := tls.X509KeyPair([]byte(testCertPEM), []byte(testKeyPEM))
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		return nil, err
	}

	s := &mockTLSServer{
		listener: listener,
		psk:      psk,
	}

	s.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mock handler - just accepts connection
			w.WriteHeader(http.StatusOK)
		}),
		TLSConfig: tlsConfig,
	}

	go func() {
		if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			s.mu.Lock()
			s.lastErr = err
			s.mu.Unlock()
		}
	}()

	return s, nil
}

func (s *mockTLSServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	if err := s.server.Shutdown(ctx); err != nil {
		return err
	}
	return s.listener.Close()
}

func (s *mockTLSServer) Addr() string {
	return s.listener.Addr().String()
}

// TestDialModeAFullHandshake проверяет полный цикл handshake с реальным uTLS
func TestDialModeAFullHandshake(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}
	defer conn.Close()

	// Проверка что соединение работает
	testMsg := []byte("Hello, Phantom!")
	if err := conn.Write(common.MsgData, testMsg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	msgType, data, err := conn.Read()
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if msgType != common.MsgData {
		t.Errorf("expected MsgData, got %v", msgType)
	}

	if string(data) != string(testMsg) {
		t.Errorf("expected %q, got %q", testMsg, data)
	}
}

// TestDialModeAMultipleMessages проверяет передачу нескольких сообщений
func TestDialModeAMultipleMessages(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}
	defer conn.Close()

	messages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2"),
		[]byte("Message 3"),
		[]byte("Final message"),
	}

	for i, msg := range messages {
		if err := conn.Write(common.MsgData, msg); err != nil {
			t.Fatalf("Write message %d failed: %v", i, err)
		}

		msgType, data, err := conn.Read()
		if err != nil {
			t.Fatalf("Read message %d failed: %v", i, err)
		}

		if msgType != common.MsgData {
			t.Errorf("message %d: expected MsgData, got %v", i, msgType)
		}

		if string(data) != string(msg) {
			t.Errorf("message %d: expected %q, got %q", i, msg, data)
		}
	}
}

// TestDialModeAConcurrentAccess проверяет потокобезопасность
func TestDialModeAConcurrentAccess(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			msg := fmt.Sprintf("concurrent message %d", id)
			if err := conn.Write(common.MsgData, []byte(msg)); err != nil {
				errors <- fmt.Errorf("goroutine %d write error: %w", id, err)
				return
			}

			msgType, data, err := conn.Read()
			if err != nil {
				errors <- fmt.Errorf("goroutine %d read error: %w", id, err)
				return
			}

			if msgType != common.MsgData {
				errors <- fmt.Errorf("goroutine %d: expected MsgData, got %v", id, msgType)
				return
			}

			if string(data) != msg {
				errors <- fmt.Errorf("goroutine %d: message mismatch", id)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// TestDialModeALargeData проверяет передачу больших данных
func TestDialModeALargeData(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}
	defer conn.Close()

	// 8KB данных
	largeData := make([]byte, 8192)
	if _, err := rand.Read(largeData); err != nil {
		t.Fatal(err)
	}

	if err := conn.Write(common.MsgData, largeData); err != nil {
		t.Fatalf("Write large data failed: %v", err)
	}

	msgType, data, err := conn.Read()
	if err != nil {
		t.Fatalf("Read large data failed: %v", err)
	}

	if msgType != common.MsgData {
		t.Errorf("expected MsgData, got %v", msgType)
	}

	if len(data) != len(largeData) {
		t.Errorf("expected %d bytes, got %d", len(largeData), len(data))
	}
}

// TestDialModeAWrongPSK проверяет отклонение при неправильном PSK
func TestDialModeAWrongPSK(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	wrongPSK := make([]byte, 32)
	if _, err := rand.Read(wrongPSK); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	_, err = DialModeA(ctx, server.Addr(), wrongPSK, &spec)
	if err == nil {
		t.Fatal("expected error with wrong PSK, got nil")
	}
}

// TestDialModeABadSessionConfirm проверяет отклонение при неправильном подтверждении
func TestDialModeABadSessionConfirm(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}
	defer conn.Close()

	// Проверяем что соединение закрыто после неудачного handshake
	if err := conn.Write(common.MsgData, []byte("test")); err == nil {
		t.Error("expected error after bad session confirm")
	}
}

// TestDialModeAMessageTypes проверяет все типы сообщений
func TestDialModeAMessageTypes(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}
	defer conn.Close()

	messageTypes := []common.MessageType{
		common.MsgData,
		common.MsgHeartbeat,
		common.MsgClose,
	}

	for _, msgType := range messageTypes {
		testData := []byte("test")
		if err := conn.Write(msgType, testData); err != nil {
			t.Fatalf("Write %v failed: %v", msgType, err)
		}

		receivedType, data, err := conn.Read()
		if err != nil {
			t.Fatalf("Read %v failed: %v", msgType, err)
		}

		if receivedType != msgType {
			t.Errorf("expected type %v, got %v", msgType, receivedType)
		}

		if string(data) != string(testData) {
			t.Errorf("data mismatch for type %v", msgType)
		}
	}
}

// TestDialModeAClose проверяет корректное закрытие соединения
func TestDialModeAClose(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Попытка записи после закрытия
	if err := conn.Write(common.MsgData, []byte("test")); err == nil {
		t.Error("expected error writing to closed connection")
	}
}

// TestPacketRoundTripWithMock проверяет round-trip с моком
func TestPacketRoundTripWithMock(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}
	defer conn.Close()

	original := []byte("round-trip test message")
	if err := conn.Write(common.MsgData, original); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	msgType, received, err := conn.Read()
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if msgType != common.MsgData {
		t.Errorf("expected MsgData, got %v", msgType)
	}

	if string(received) != string(original) {
		t.Errorf("expected %q, got %q", original, received)
	}
}

// TestPacketTooLargeWithMock проверяет ограничение размера пакета
func TestPacketTooLargeWithMock(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServer(psk)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}
	defer conn.Close()

	// Пакет больше MaxPacketSize
	largePayload := make([]byte, common.MaxPacketSize+100)
	if err := conn.Write(common.MsgData, largePayload); err == nil {
		t.Error("expected error for oversized packet")
	}
}

// TestDialModeAConnectionRefused проверяет обработку отказа соединения
func TestDialModeAConnectionRefused(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}
	_, err2 := DialModeA(ctx, "127.0.0.1:1", psk, &spec) // Порт 1 обычно закрыт
	if err2 == nil {
		t.Fatal("expected err2or for connection refused")
	}
}

// Тестовые сертификаты для mock сервера
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvBTpU8X2KuxGYtFfBxn5BxUKCWGBgHJJSFJrQpMJ+ckKWmTcTDKXeYvRZ8
bPuOYvVBNmC4aL7X+6ujUDBOMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQUu8UK
VH0yVTDoKDnmbzN5dGVOZaowCgYIKoZIzj0EAwIDSAAwRQIhAJpJ4P2lwn+6l2FN
FPmCKeGzFxAN3j8XGcJkPR3bS8GJAiB3MxLzHlMVrXnYCPj1lN7X3b3m8dLlVGNz
kQxGz2cJhw==
-----END CERTIFICATE-----`

const testKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIkY+6l2FNFPmCKeGzFxAN3j8XGcJkPR3bS8GJoAoGCCqGSM49AwEH
oUQDQgAEPR3tU2Fta8FOlTxfYq7EZi0V8HGfkHFQoJYYGAcElIUmtCkwk5yQpaZN
xMMpd5i9Fnxt+45i9UE2YLhovtf7qw==
-----END EC PRIVATE KEY-----`
