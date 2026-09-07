package common

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
