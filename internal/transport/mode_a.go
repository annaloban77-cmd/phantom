package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/phantom-tunnel/phantom/internal/common"
	"github.com/phantom-tunnel/phantom/internal/crypto"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/curve25519"
)

// ModeAConn — клиентское туннельное соединение Mode A (прямой TCP + utls).
// Фрейминг и AEAD — в общем TunnelConn, как и в Mode B/C.
type ModeAConn struct {
	tun     *TunnelConn
	tlsConn *utls.UConn
}

// handshakeTimeout ограничивает длительность phantom handshake,
// чтобы зависший/молчащий сервер не блокировал клиента навсегда
const handshakeTimeout = 15 * time.Second

// DialOption настраивает дополнительные параметры Dial* всех режимов
type DialOption func(*dialConfig)

type dialConfig struct {
	tlsConfig *utls.Config
}

// WithTLSConfig переопределяет конфиг uTLS-клиента (RootCAs,
// InsecureSkipVerify, cert pinning и т.п.). ServerName проставляется
// из адреса цели, если не задан в конфиге.
func WithTLSConfig(cfg *utls.Config) DialOption {
	return func(d *dialConfig) { d.tlsConfig = cfg }
}

// buildClientTLSConfig собирает uTLS-конфиг: клон пользовательского
// (или пустой) + ServerName, если не задан. Общий путь Mode A/B/C.
func buildClientTLSConfig(dc *dialConfig, serverName string) *utls.Config {
	var cfg *utls.Config
	if dc.tlsConfig != nil {
		cfg = dc.tlsConfig.Clone()
	} else {
		cfg = &utls.Config{}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	return cfg
}

func DialModeA(ctx context.Context, addr string, psk []byte, spec *utls.ClientHelloSpec, opts ...DialOption) (*ModeAConn, error) {
	dc := &dialConfig{}
	for _, opt := range opts {
		opt(dc)
	}

	// 1. TCP dial
	netConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}

	// 2. TLS handshake with utls
	helloID, applySpec := utls.HelloChrome_Auto, false
	if spec != nil {
		helloID, applySpec = utls.HelloCustom, true
	}
	tlsConn := utls.UClient(netConn, buildClientTLSConfig(dc, getServerName(addr)), helloID)
	if applySpec {
		if err := tlsConn.ApplyPreset(spec); err != nil {
			netConn.Close()
			return nil, fmt.Errorf("apply preset: %w", err)
		}
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	// 3. PHANTOM handshake inside TLS (под дедлайном)
	tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	aeadTx, aeadRx, err := performClientHandshake(tlsConn, psk)
	tlsConn.SetDeadline(time.Time{})
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return &ModeAConn{
		tun:     NewTunnelConn(tlsConn, tlsConn, aeadTx, aeadRx),
		tlsConn: tlsConn,
	}, nil
}

func getServerName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func performClientHandshake(conn io.ReadWriter, psk []byte) (*crypto.AEAD, *crypto.AEAD, error) {
	// Generate ephemeral X25519 keypair
	privKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(common.RandReader, privKey); err != nil {
		return nil, nil, err
	}
	// Clamp private key for X25519
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	// Generate nonce_C
	nonceC := make([]byte, 16)
	if _, err := io.ReadFull(common.RandReader, nonceC); err != nil {
		return nil, nil, err
	}

	ts := uint64(time.Now().UnixMilli())

	// Send ClientHello
	ch := common.ClientHelloMessage{
		Type:   common.HsClientHello,
		PubKey: pubKey,
		TsMs:   ts,
		Nonce:  nonceC,
	}
	chBytes, err := ch.Marshal()
	if err != nil {
		return nil, nil, err
	}

	if _, err := conn.Write(chBytes); err != nil {
		return nil, nil, err
	}

	// Read ServerHello
	shBytes := make([]byte, common.ServerHelloSize)
	if _, err := io.ReadFull(conn, shBytes); err != nil {
		return nil, nil, err
	}

	sh, err := common.UnmarshalServerHello(shBytes)
	if err != nil {
		return nil, nil, err
	}

	// Compute shared secret
	sharedSecret, err := curve25519.X25519(privKey, sh.PubKey)
	if err != nil {
		return nil, nil, err
	}

	// Send ClientProof
	clientProof := computeClientProof(psk, nonceC, pubKey)
	cp := common.ClientProofMessage{
		Type:  common.HsClientProof,
		Proof: clientProof,
	}
	cpBytes, err := cp.Marshal()
	if err != nil {
		return nil, nil, err
	}

	if _, err := conn.Write(cpBytes); err != nil {
		return nil, nil, err
	}

	// Read SessionConfirm
	scBytes := make([]byte, common.SessionConfirmSize)
	if _, err := io.ReadFull(conn, scBytes); err != nil {
		return nil, nil, err
	}

	sc, err := common.UnmarshalSessionConfirm(scBytes)
	if err != nil {
		return nil, nil, err
	}

	// Verify SessionConfirm
	expectedConfirm := computeSessionConfirm(psk, nonceC, sh.Nonce)
	if !hmac.Equal(sc.Proof[:], expectedConfirm[:]) {
		return nil, nil, fmt.Errorf("session confirm mismatch")
	}

	// Derive keys
	keyC2S, keyS2C, err := crypto.DeriveKeys(sharedSecret, sh.Nonce, nonceC)
	if err != nil {
		return nil, nil, err
	}

	aeadTx, err := crypto.NewAEAD(keyC2S)
	if err != nil {
		return nil, nil, err
	}

	aeadRx, err := crypto.NewAEAD(keyS2C)
	if err != nil {
		return nil, nil, err
	}

	return aeadTx, aeadRx, nil
}

func computeClientProof(psk, nonceC, pubC []byte) [32]byte {
	h := hmac.New(sha256.New, psk)
	h.Write([]byte("client_prove"))
	h.Write(nonceC)
	h.Write(pubC)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func computeSessionConfirm(psk, nonceC, nonceS []byte) [32]byte {
	h := hmac.New(sha256.New, psk)
	h.Write([]byte("session_confirm"))
	h.Write(nonceC)
	h.Write(nonceS)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (mc *ModeAConn) Write(msgType common.MessageType, payload []byte) error {
	return mc.tun.Write(msgType, payload)
}

func (mc *ModeAConn) Read() (common.MessageType, []byte, error) {
	return mc.tun.Read()
}

func (mc *ModeAConn) Close() error {
	return mc.tun.Close()
}
