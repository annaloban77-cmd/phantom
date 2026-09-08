package transport

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DialModeB устанавливает туннель Mode B: WebSocket поверх utls
// (путь через Cloudflare Workers: TLS терминируется на CDN, PHANTOM-протокол
// идёт внутри WS binary frames; origin-сервер принимает его напрямую).
//
// Схема wsURL обязана быть wss://. Порядок: TCP-dial к host:443 из wsURL →
// utls-handshake (SNI = host, кастомный ClientHelloSpec) → WS-upgrade →
// PHANTOM-handshake внутри WS binary frames → aeadTx=keyC2S, aeadRx=keyS2C.
func DialModeB(ctx context.Context, wsURL string, psk []byte, spec *utls.ClientHelloSpec, opts ...DialOption) (*TunnelConn, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, fmt.Errorf("parse ws url: %w", err)
	}
	if u.Scheme != "wss" {
		return nil, fmt.Errorf("unsupported ws url scheme %q: want wss", u.Scheme)
	}

	port := u.Port()
	if port == "" {
		port = "443"
	}

	netConn, err := net.DialTimeout("tcp", net.JoinHostPort(u.Hostname(), port), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}

	dc := &dialConfig{}
	for _, opt := range opts {
		opt(dc)
	}

	return establishWS(ctx, netConn, u, psk, spec, dc)
}
