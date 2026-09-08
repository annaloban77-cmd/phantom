package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/phantom-tunnel/phantom/internal/common"
	"github.com/phantom-tunnel/phantom/internal/crypto"
	utls "github.com/refraction-networking/utls"
)

// TunnelConn — единая для всех транспортов (Mode A/B/C) обёртка поверх уже
// handshake-нутого соединения: фрейминг [4B length][AEAD(type + payload)].
type TunnelConn struct {
	rw      io.ReadWriter
	closer  io.Closer
	aeadTx  *crypto.AEAD
	aeadRx  *crypto.AEAD
	tlsConn *utls.UConn // utls-соединение под транспортом, если доступно

	mu     sync.Mutex
	readMu sync.Mutex
	closed bool
}

// NewTunnelConn создаёт туннель поверх готового транспорта.
// closer вызывается в Close (TLS/WS/TCP-соединение).
func NewTunnelConn(rw io.ReadWriter, closer io.Closer, aeadTx, aeadRx *crypto.AEAD) *TunnelConn {
	return &TunnelConn{
		rw:     rw,
		closer: closer,
		aeadTx: aeadTx,
		aeadRx: aeadRx,
	}
}

// TLSConn возвращает utls-соединение под транспортом (nil, если транспорт
// не предоставляет доступ — например, сырой WS-стрим без TLS-обёртки).
func (t *TunnelConn) TLSConn() *utls.UConn { return t.tlsConn }

func (t *TunnelConn) setTLSConn(u *utls.UConn) { t.tlsConn = u }

// Write шифрует и отправляет пакет: [4B length][ciphertext(type + payload)].
func (t *TunnelConn) Write(msgType common.MessageType, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return fmt.Errorf("connection closed")
	}

	maxPayload := common.MaxPacketSize - 4 - 16 // length + tag
	if len(payload) > maxPayload {
		return fmt.Errorf("payload too large: %d > %d", len(payload), maxPayload)
	}

	plaintext := append([]byte{byte(msgType)}, payload...)

	ciphertext, err := t.aeadTx.Seal(plaintext)
	if err != nil {
		return err
	}

	frame := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(ciphertext)))
	copy(frame[4:], ciphertext)

	_, err = t.rw.Write(frame)
	return err
}

// Read принимает и расшифровывает следующий пакет.
func (t *TunnelConn) Read() (common.MessageType, []byte, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	if t.closed {
		return 0, nil, fmt.Errorf("connection closed")
	}

	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(t.rw, lengthBuf); err != nil {
		return 0, nil, err
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length > common.MaxPacketSize-4 {
		return 0, nil, fmt.Errorf("packet too large: %d", length)
	}

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(t.rw, ciphertext); err != nil {
		return 0, nil, err
	}

	plaintext, err := t.aeadRx.Open(ciphertext)
	if err != nil {
		return 0, nil, err
	}

	if len(plaintext) < 1 {
		return 0, nil, fmt.Errorf("empty packet")
	}

	return common.MessageType(plaintext[0]), plaintext[1:], nil
}

// Close закрывает транспорт (идемпотентно).
func (t *TunnelConn) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.closer != nil {
		return t.closer.Close()
	}
	return nil
}
