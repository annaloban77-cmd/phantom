package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DialModeC устанавливает туннель Mode C: HTTPS-прокси с HTTP CONNECT →
// utls к target → WS-upgrade → PHANTOM-handshake.
//
// proxyURL: http://[user:pass@]host:port — basic-auth из user:pass URL
// отправляется как Proxy-Authorization при CONNECT.
// targetURL: wss://host[:port]/path — цель после прокси.
func DialModeC(ctx context.Context, proxyURL, targetURL string, psk []byte, spec *utls.ClientHelloSpec, opts ...DialOption) (*TunnelConn, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}
	if pu.Scheme != "http" {
		return nil, fmt.Errorf("unsupported proxy scheme %q: want http", pu.Scheme)
	}
	pp := pu.Port()
	if pp == "" {
		pp = "8080"
	}

	tu, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target url: %w", err)
	}
	if tu.Scheme != "wss" {
		return nil, fmt.Errorf("unsupported target scheme %q: want wss", tu.Scheme)
	}
	tp := tu.Port()
	if tp == "" {
		tp = "443"
	}
	target := net.JoinHostPort(tu.Hostname(), tp)

	// 1. TCP к прокси
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(pu.Hostname(), pp), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	// 2. HTTP CONNECT (+ Proxy-Authorization: Basic из user:pass URL, если задан)
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if pu.User != nil {
		pass, _ := pu.User.Password()
		cred := pu.User.Username() + ":" + pass
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
	}
	if err := req.Write(raw); err != nil {
		raw.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(raw), req)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	// После 200 прокси молчит до первых байт клиента (TLS ClientHello),
	// поэтому bufio-буферизация не может захватить чужие данные.
	dc := &dialConfig{}
	for _, opt := range opts {
		opt(dc)
	}
	return establishWS(ctx, raw, tu, psk, spec, dc)
}
