package transport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phantom-tunnel/phantom/internal/common"
	utls "github.com/refraction-networking/utls"
)

// TestModeCRoundTrip: mock CONNECT-прокси соединяет клиента с локальным
// тестовым PHANTOM WS-сервером; round-trip пакетов + проверка, что
// Proxy-Authorization передан из user:pass URL прокси.
func TestModeCRoundTrip(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	// Цель: локальный PHANTOM WS-сервер
	wsSrv := newMockWSServer(psk)
	defer wsSrv.Close()
	wssURL := mockWSSURL(wsSrv)

	// Mock CONNECT-прокси
	var gotAuth atomic.Value
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadRequest)
			return
		}
		gotAuth.Store(r.Header.Get("Proxy-Authorization"))

		dst, err := net.DialTimeout("tcp", r.URL.Host, 5*time.Second)
		if err != nil {
			http.Error(w, "dial failed", http.StatusBadGateway)
			return
		}
		defer dst.Close()

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer client.Close()

		if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}

		done := make(chan struct{}, 2)
		go func() { io.Copy(dst, client); done <- struct{}{} }()
		go func() { io.Copy(client, dst); done <- struct{}{} }()
		<-done
	}))
	defer proxy.Close()

	// Прокси с basic-auth в URL
	pu, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	pu.User = url.UserPassword("u", "p")

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := DialModeC(ctx, pu.String(), wssURL, psk, &spec, testTLSOptions()...)
	if err != nil {
		t.Fatalf("DialModeC failed: %v", err)
	}
	defer conn.Close()

	// Round-trip через CONNECT-прокси
	msg := []byte("hello through connect proxy")
	if err := conn.Write(common.MsgData, msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	msgType, data, err := conn.Read()
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if msgType != common.MsgData {
		t.Errorf("expected MsgData, got %v", msgType)
	}
	if string(data) != string(msg) {
		t.Errorf("expected %q, got %q", msg, data)
	}

	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	if got := gotAuth.Load(); got != expectedAuth {
		t.Errorf("proxy auth: got %v, want %s", got, expectedAuth)
	}
}

// TestModeCProxyRefused: прокси отвечает не-200 → ошибка DialModeC
func TestModeCProxyRefused(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer proxy.Close()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = DialModeC(ctx, proxy.URL, "wss://example.com/", psk, &spec, testTLSOptions()...)
	if err == nil {
		t.Fatal("expected error when proxy denies CONNECT")
	}
}
