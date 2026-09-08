package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/phantom-tunnel/phantom/internal/common"
	"github.com/phantom-tunnel/phantom/internal/crypto"
	"github.com/phantom-tunnel/phantom/internal/handshake"
	utls "github.com/refraction-networking/utls"
)

// testTLSOptions отключает проверку self-signed сертификата mock-сервера
func testTLSOptions() []DialOption {
	return []DialOption{
		WithTLSConfig(&utls.Config{
			ServerName:         "127.0.0.1",
			InsecureSkipVerify: true,
		}),
	}
}

// mockTLSServer поднимает TLS-сервер, который выполняет полный PHANTOM handshake
// и в tunnel-режиме эхо-отвечает на зашифрованные пакеты клиента.
type mockTLSServer struct {
	listener   net.Listener
	psk        []byte
	badConfirm bool
}

func newMockTLSServer(psk []byte) (*mockTLSServer, error) {
	return newMockTLSServerOpts(psk, false)
}

// newMockTLSServerBadConfirm возвращает сервер, который отправляет
// заведомо неверный SessionConfirm — клиент обязан отвергнуть handshake
func newMockTLSServerBadConfirm(psk []byte) (*mockTLSServer, error) {
	return newMockTLSServerOpts(psk, true)
}

func newMockTLSServerOpts(psk []byte, badConfirm bool) (*mockTLSServer, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("generate cert: %w", err)
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
		listener:   listener,
		psk:        psk,
		badConfirm: badConfirm,
	}

	go s.serve()
	return s, nil
}

// generateSelfSignedCert создаёт валидную self-signed пару ключей на лету.
// Статические PEM-константы не используются: их легко повредить при копировании,
// а сертификат со фиксированным сроком действия со временем истекает.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Phantom Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func (s *mockTLSServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			s.handleConn(c)
		}(conn)
	}
}

func (s *mockTLSServer) handleConn(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if s.badConfirm {
		s.runBadConfirmHandshake(conn)
		return
	}

	hs := handshake.NewServerHandshake([]handshake.PSKUser{{Key: s.psk, Name: "test"}})
	aeadRx, aeadTx, _, err := hs.Perform(conn, conn.RemoteAddr().String())
	if err != nil {
		return
	}

	// Снимаем дедлайн handshake: туннель долгоживущий
	conn.SetDeadline(time.Time{})

	// Echo loop: читаем зашифрованный фрейм, расшифровываем и эхо-отвечаем
	for {
		lengthBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			return
		}
		length := int(lengthBuf[0])<<24 | int(lengthBuf[1])<<16 | int(lengthBuf[2])<<8 | int(lengthBuf[3])
		if length <= 0 || length > common.MaxPacketSize-4 {
			return
		}

		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(conn, ciphertext); err != nil {
			return
		}

		plaintext, err := aeadRx.Open(ciphertext)
		if err != nil {
			return
		}
		if len(plaintext) < 1 {
			return
		}

		// Эхо: тот же msgType+payload, шифруем исходящим (S2C) ключом сервера
		reply, err := aeadTx.Seal(plaintext)
		if err != nil {
			return
		}

		frame := make([]byte, 4+len(reply))
		frame[0] = byte(len(reply) >> 24)
		frame[1] = byte(len(reply) >> 16)
		frame[2] = byte(len(reply) >> 8)
		frame[3] = byte(len(reply))
		copy(frame[4:], reply)

		if _, err := conn.Write(frame); err != nil {
			return
		}
	}
}

// runBadConfirmHandshake выполняет handshake, но отправляет неверный SessionConfirm
func (s *mockTLSServer) runBadConfirmHandshake(conn net.Conn) {
	chBuf := make([]byte, common.ClientHelloSize)
	if _, err := io.ReadFull(conn, chBuf); err != nil {
		return
	}
	ch, err := handshake.UnmarshalClientHello(chBuf)
	if err != nil {
		return
	}

	serverPriv, serverPub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return
	}
	if _, err := crypto.X25519(serverPriv[:], ch.PubKey[:]); err != nil {
		return
	}

	var serverNonce [16]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		return
	}

	sh := &handshake.ServerHello{
		Type:   uint16(common.HsServerHello),
		PubKey: serverPub,
		Nonce:  serverNonce,
	}
	if _, err := conn.Write(handshake.MarshalServerHello(sh)); err != nil {
		return
	}

	cpBuf := make([]byte, common.ClientProofSize)
	if _, err := io.ReadFull(conn, cpBuf); err != nil {
		return
	}

	var badHMAC [32]byte
	sc := &handshake.SessionConfirm{Type: uint16(common.HsSessionConfirm), HMAC: badHMAC}
	if _, err := conn.Write(handshake.MarshalSessionConfirm(sc)); err != nil {
		return
	}

	// Держим соединение открытым, пока клиент не прочитает confirm и не отвергнет его
	time.Sleep(2 * time.Second)
}

func (s *mockTLSServer) Close() error {
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
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec, testTLSOptions()...)
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
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec, testTLSOptions()...)
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

// TestDialModeAConcurrentAccess проверяет потокобезопасность Write/Read:
// N горутин пишут одновременно, затем сверяем, что все N эхо дошли.
// Порядок эхо не определён (зависит от того, в каком порядке сервер принял
// фреймы), поэтому сравниваем множества, а не пары по порядку.
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
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec, testTLSOptions()...)
	if err != nil {
		t.Fatalf("DialModeA failed: %v", err)
	}
	defer conn.Close()

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			msg := fmt.Sprintf("concurrent message %d", id)
			if err := conn.Write(common.MsgData, []byte(msg)); err != nil {
				errs <- fmt.Errorf("goroutine %d write error: %w", id, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// Все n сообщений должны вернуться эхом, каждое ровно один раз
	expected := make(map[string]bool)
	for i := 0; i < n; i++ {
		expected[fmt.Sprintf("concurrent message %d", i)] = true
	}

	for i := 0; i < n; i++ {
		msgType, data, err := conn.Read()
		if err != nil {
			t.Fatalf("read echo %d failed: %v", i, err)
		}
		if msgType != common.MsgData {
			t.Errorf("echo %d: expected MsgData, got %v", i, msgType)
		}
		if !expected[string(data)] {
			t.Errorf("echo %d: unexpected or duplicate message %q", i, data)
			continue
		}
		delete(expected, string(data))
	}

	if len(expected) != 0 {
		t.Errorf("missing %d echo messages", len(expected))
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
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec, testTLSOptions()...)
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
	_, err = DialModeA(ctx, server.Addr(), wrongPSK, &spec, testTLSOptions()...)
	if err == nil {
		t.Fatal("expected error with wrong PSK, got nil")
	}
}

// TestDialModeABadSessionConfirm проверяет, что клиент отвергает
// неверный SessionConfirm (подмена/компрометация сервера)
func TestDialModeABadSessionConfirm(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	server, err := newMockTLSServerBadConfirm(psk)
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
	_, err = DialModeA(ctx, server.Addr(), psk, &spec, testTLSOptions()...)
	if err == nil {
		t.Fatal("expected handshake failure with bad SessionConfirm")
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
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec, testTLSOptions()...)
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
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec, testTLSOptions()...)
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
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec, testTLSOptions()...)
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
	conn, err := DialModeA(ctx, server.Addr(), psk, &spec, testTLSOptions()...)
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
	_, err = DialModeA(ctx, "127.0.0.1:1", psk, &spec, testTLSOptions()...) // Порт 1 обычно закрыт
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}
