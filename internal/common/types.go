package common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// MessageType defines the type of message in encrypted tunnel
type MessageType byte

const (
	MsgData      MessageType = 0x01
	MsgHeartbeat MessageType = 0x02
	MsgClose     MessageType = 0x03
)

// HandshakeType defines handshake message types
type HandshakeType uint16

const (
	HsClientHello    HandshakeType = 0x0001
	HsServerHello    HandshakeType = 0x0002
	HsClientProof    HandshakeType = 0x0003
	HsSessionConfirm HandshakeType = 0x0004
)

// Protocol constants
const (
	ClientHelloSize    = 58
	ServerHelloSize    = 50
	ClientProofSize    = 34
	SessionConfirmSize = 34
	MaxPacketSize      = 16384
	NonceSize          = 12
	X25519PubKeySize   = 32
	PSKMinLength       = 32
	HMACSize           = 32
	TimestampWindowMs  = 120000 // 2 minutes
)

var (
	ErrInvalidMessageSize = errors.New("invalid message size")
	ErrTimestampExpired   = errors.New("timestamp expired")
	ErrReplayDetected     = errors.New("replay detected")
	ErrAuthFailed         = errors.New("authentication failed")
)

// RandReader is the random reader used for cryptographic operations
var RandReader = rand.Reader

// ClientHelloMessage represents the ClientHello handshake message
type ClientHelloMessage struct {
	Type   HandshakeType
	PubKey []byte // 32 bytes
	TsMs   uint64
	Nonce  []byte // 16 bytes
}

func (m *ClientHelloMessage) Marshal() ([]byte, error) {
	buf := make([]byte, ClientHelloSize)
	binary.BigEndian.PutUint16(buf[0:2], uint16(m.Type))
	if len(m.PubKey) != X25519PubKeySize {
		return nil, ErrInvalidMessageSize
	}
	copy(buf[2:34], m.PubKey)
	binary.BigEndian.PutUint64(buf[34:42], m.TsMs)
	if len(m.Nonce) != 16 {
		return nil, ErrInvalidMessageSize
	}
	copy(buf[42:58], m.Nonce)
	return buf, nil
}

func UnmarshalClientHello(data []byte) (*ClientHelloMessage, error) {
	if len(data) != ClientHelloSize {
		return nil, ErrInvalidMessageSize
	}
	return &ClientHelloMessage{
		Type:   HandshakeType(binary.BigEndian.Uint16(data[0:2])),
		PubKey: append([]byte{}, data[2:34]...),
		TsMs:   binary.BigEndian.Uint64(data[34:42]),
		Nonce:  append([]byte{}, data[42:58]...),
	}, nil
}

// ServerHelloMessage represents the ServerHello handshake message
type ServerHelloMessage struct {
	Type   HandshakeType
	PubKey []byte // 32 bytes
	Nonce  []byte // 16 bytes
}

func (m *ServerHelloMessage) Marshal() ([]byte, error) {
	buf := make([]byte, ServerHelloSize)
	binary.BigEndian.PutUint16(buf[0:2], uint16(m.Type))
	if len(m.PubKey) != X25519PubKeySize {
		return nil, ErrInvalidMessageSize
	}
	copy(buf[2:34], m.PubKey)
	if len(m.Nonce) != 16 {
		return nil, ErrInvalidMessageSize
	}
	copy(buf[34:50], m.Nonce)
	return buf, nil
}

func UnmarshalServerHello(data []byte) (*ServerHelloMessage, error) {
	if len(data) != ServerHelloSize {
		return nil, ErrInvalidMessageSize
	}
	return &ServerHelloMessage{
		Type:   HandshakeType(binary.BigEndian.Uint16(data[0:2])),
		PubKey: append([]byte{}, data[2:34]...),
		Nonce:  append([]byte{}, data[34:50]...),
	}, nil
}

// ClientProofMessage represents the ClientProof handshake message
type ClientProofMessage struct {
	Type  HandshakeType
	Proof [HMACSize]byte
}

func (m *ClientProofMessage) Marshal() ([]byte, error) {
	buf := make([]byte, ClientProofSize)
	binary.BigEndian.PutUint16(buf[0:2], uint16(m.Type))
	copy(buf[2:34], m.Proof[:])
	return buf, nil
}

func UnmarshalClientProof(data []byte) (*ClientProofMessage, error) {
	if len(data) != ClientProofSize {
		return nil, ErrInvalidMessageSize
	}
	var proof [HMACSize]byte
	copy(proof[:], data[2:34])
	return &ClientProofMessage{
		Type:  HandshakeType(binary.BigEndian.Uint16(data[0:2])),
		Proof: proof,
	}, nil
}

// SessionConfirmMessage represents the SessionConfirm handshake message
type SessionConfirmMessage struct {
	Type  HandshakeType
	Proof [HMACSize]byte
}

func (m *SessionConfirmMessage) Marshal() ([]byte, error) {
	buf := make([]byte, SessionConfirmSize)
	binary.BigEndian.PutUint16(buf[0:2], uint16(m.Type))
	copy(buf[2:34], m.Proof[:])
	return buf, nil
}

func UnmarshalSessionConfirm(data []byte) (*SessionConfirmMessage, error) {
	if len(data) != SessionConfirmSize {
		return nil, ErrInvalidMessageSize
	}
	var proof [HMACSize]byte
	copy(proof[:], data[2:34])
	return &SessionConfirmMessage{
		Type:  HandshakeType(binary.BigEndian.Uint16(data[0:2])),
		Proof: proof,
	}, nil
}
