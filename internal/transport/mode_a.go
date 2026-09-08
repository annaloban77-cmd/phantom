package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/phantom-tunnel/phantom/internal/common"
	"github.com/phantom-tunnel/phantom/internal/crypto"
	"golang.org/x/crypto/curve25519"
	utls "github.com/refraction-networking/utls"
)

type ModeAConn struct {
	tlsConn *utls.UConn
	aeadTx  *crypto.AEAD
	aeadRx  *crypto.AEAD
	mu      sync.Mutex
	closed  bool
	readMu  sync.Mutex
}

// handshakeTimeout ограничивает длительность phantom handshake,
// чтобы зависший/молчащий сервер не блокировал клиента навсегда
const handshakeTimeout = 15 * time.Second

// DialOption настраивает дополнительные параметры DialModeA
type DialOption func(*dialConfig)

type dialConfig struct {
	tlsConfig *utls.Config
}

// WithTLSConfig переопределяет конфиг uTLS-клиента (RootCAs, InsecureSkipVerify и т.п.).
// ServerName проставляется из addr, если не задан в конфиге.
func WithTLSConfig(cfg *utls.Config) DialOption {
	return func(d *dialConfig) { d.tlsConfig = cfg }
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
	var tlsCfg *utls.Config
	if dc.tlsConfig != nil {
		tlsCfg = dc.tlsConfig.Clone()
	} else {
		tlsCfg = &utls.Config{}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = getServerName(addr)
	}

	helloID := utls.HelloCustom
	if spec == nil {
		helloID = utls.HelloChrome_Auto
	}
	tlsConn := utls.UClient(netConn, tlsCfg, helloID)

	if spec != nil {
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
		tlsConn: tlsConn,
		aeadTx:  aeadTx,
		aeadRx:  aeadRx,
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
		Type:    common.HsClientHello,
		PubKey:  pubKey,
		TsMs:    ts,
		Nonce:   nonceC,
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
		Type: common.HsClientProof,
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
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.closed {
		return fmt.Errorf("connection closed")
	}

	// Check max size
	maxPayload := common.MaxPacketSize - 4 - 16 // length + tag
	if len(payload) > maxPayload {
		return fmt.Errorf("payload too large: %d > %d", len(payload), maxPayload)
	}

	// Build plaintext
	plaintext := append([]byte{byte(msgType)}, payload...)

	// Encrypt
	ciphertext, err := mc.aeadTx.Seal(plaintext)
	if err != nil {
		return err
	}

	// Frame: [4B length][ciphertext]
	frame := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(ciphertext)))
	copy(frame[4:], ciphertext)

	_, err = mc.tlsConn.Write(frame)
	return err
}

func (mc *ModeAConn) Read() (common.MessageType, []byte, error) {
	mc.readMu.Lock()
	defer mc.readMu.Unlock()

	if mc.closed {
		return 0, nil, fmt.Errorf("connection closed")
	}

	// Read length prefix
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(mc.tlsConn, lengthBuf); err != nil {
		return 0, nil, err
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length > common.MaxPacketSize-4 {
		return 0, nil, fmt.Errorf("packet too large: %d", length)
	}

	// Read ciphertext
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(mc.tlsConn, ciphertext); err != nil {
		return 0, nil, err
	}

	// Decrypt
	plaintext, err := mc.aeadRx.Open(ciphertext)
	if err != nil {
		return 0, nil, err
	}

	if len(plaintext) < 1 {
		return 0, nil, fmt.Errorf("empty packet")
	}

	msgType := common.MessageType(plaintext[0])
	payload := plaintext[1:]

	return msgType, payload, nil
}

func (mc *ModeAConn) Close() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.closed {
		return nil
	}

	mc.closed = true
	return mc.tlsConn.Close()
}
