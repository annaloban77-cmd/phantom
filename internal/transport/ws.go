package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

// wsStream адаптирует gorilla/websocket (message-oriented) к io.ReadWriter
// (байтовый поток). Каждая Write отправляется одним binary-фреймом RFC 6455:
// один PHANTOM-пакет = один binary frame. Read собирает поток из payload'ов
// входящих binary-сообщений (io.ReadFull поверх wsStream работает корректно).
type wsStream struct {
	ws   *websocket.Conn
	rbuf []byte
}

func newWSStream(ws *websocket.Conn) *wsStream { return &wsStream{ws: ws} }

func (s *wsStream) Read(p []byte) (int, error) {
	for len(s.rbuf) == 0 {
		_, r, err := s.ws.NextReader()
		if err != nil {
			return 0, err
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return 0, err
		}
		s.rbuf = data
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *wsStream) Write(p []byte) (int, error) {
	if err := s.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *wsStream) Close() error { return s.ws.Close() }

// net.Conn-совместимость (нужно handshake.Perform для дедлайнов)
func (s *wsStream) LocalAddr() net.Addr  { return s.ws.NetConn().LocalAddr() }
func (s *wsStream) RemoteAddr() net.Addr { return s.ws.NetConn().RemoteAddr() }
func (s *wsStream) SetDeadline(t time.Time) error {
	if err := s.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return s.ws.SetWriteDeadline(t)
}
func (s *wsStream) SetReadDeadline(t time.Time) error  { return s.ws.SetReadDeadline(t) }
func (s *wsStream) SetWriteDeadline(t time.Time) error { return s.ws.SetWriteDeadline(t) }

// establishWS поднимает WS-туннель поверх уже установленного TCP-соединения
// (напрямую или через HTTP CONNECT-прокси — общий путь Mode B и Mode C):
//
//	utls-handshake (SNI = host из u, кастомный ClientHelloSpec) →
//	WS-upgrade через gorilla поверх utls-соединения (GET path,
//	Sec-WebSocket-Key = base64(16 случайных байт) генерирует gorilla) →
//	PHANTOM-handshake внутри WS binary frames.
func establishWS(ctx context.Context, netConn net.Conn, u *url.URL, psk []byte, spec *utls.ClientHelloSpec, dc *dialConfig) (*TunnelConn, error) {
	host := u.Hostname()
	tlsCfg := buildClientTLSConfig(dc, host)

	helloID := utls.HelloCustom
	if spec == nil {
		helloID = utls.HelloChrome_Auto
	}

	var utlsConn *utls.UConn
	dialer := &websocket.Dialer{
		// gorilla вызывает NetDialTLSContext для wss:// и ожидает уже
		// handshake-нутое TLS-соединение — отдаём ему наш utls-коннект.
		NetDialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			uc := utls.UClient(netConn, tlsCfg, helloID)
			if spec != nil {
				if err := uc.ApplyPreset(spec); err != nil {
					return nil, fmt.Errorf("apply preset: %w", err)
				}
			}
			if err := uc.HandshakeContext(ctx); err != nil {
				return nil, fmt.Errorf("tls handshake: %w", err)
			}
			utlsConn = uc
			return uc, nil
		},
		HandshakeTimeout: 10 * time.Second,
	}

	wsConn, _, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("ws upgrade: %w", err)
	}

	stream := newWSStream(wsConn)
	stream.SetDeadline(time.Now().Add(handshakeTimeout))
	aeadTx, aeadRx, err := performClientHandshake(stream, psk)
	stream.SetDeadline(time.Time{})
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	tun := NewTunnelConn(stream, wsConn, aeadTx, aeadRx)
	tun.setTLSConn(utlsConn)
	return tun, nil
}
