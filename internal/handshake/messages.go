package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// ClientHello представляет первое сообщение клиента
type ClientHello struct {
	Type      uint16 // 0x0001
	PubKey    [32]byte // X25519 public key
	Timestamp uint64 // milliseconds since epoch
	Nonce     [16]byte // random nonce
}

// ServerHello представляет ответ сервера
type ServerHello struct {
	Type   uint16 // 0x0002
	PubKey [32]byte // X25519 public key
	Nonce  [16]byte // random nonce
}

// ClientProof представляет доказательство клиента
type ClientProof struct {
	Type uint16 // 0x0003
	HMAC [32]byte // HMAC-SHA256
}

// SessionConfirm представляет подтверждение сессии
type SessionConfirm struct {
	Type uint16 // 0x0004
	HMAC [32]byte // HMAC-SHA256
}

// MarshalClientHello сериализует ClientHello в байты
func MarshalClientHello(ch *ClientHello) []byte {
	buf := make([]byte, 58)
	binary.BigEndian.PutUint16(buf[0:2], ch.Type)
	copy(buf[2:34], ch.PubKey[:])
	binary.BigEndian.PutUint64(buf[34:42], ch.Timestamp)
	copy(buf[42:58], ch.Nonce[:])
	return buf
}

// UnmarshalClientHello десериализует ClientHello из байтов
func UnmarshalClientHello(data []byte) (*ClientHello, error) {
	if len(data) != 58 {
		return nil, fmt.Errorf("invalid ClientHello size: %d", len(data))
	}
	ch := &ClientHello{}
	ch.Type = binary.BigEndian.Uint16(data[0:2])
	copy(ch.PubKey[:], data[2:34])
	ch.Timestamp = binary.BigEndian.Uint64(data[34:42])
	copy(ch.Nonce[:], data[42:58])
	return ch, nil
}

// MarshalServerHello сериализует ServerHello в байты
func MarshalServerHello(sh *ServerHello) []byte {
	buf := make([]byte, 50)
	binary.BigEndian.PutUint16(buf[0:2], sh.Type)
	copy(buf[2:34], sh.PubKey[:])
	copy(buf[34:50], sh.Nonce[:])
	return buf
}

// UnmarshalServerHello десериализует ServerHello из байтов
func UnmarshalServerHello(data []byte) (*ServerHello, error) {
	if len(data) != 50 {
		return nil, fmt.Errorf("invalid ServerHello size: %d", len(data))
	}
	sh := &ServerHello{}
	sh.Type = binary.BigEndian.Uint16(data[0:2])
	copy(sh.PubKey[:], data[2:34])
	copy(sh.Nonce[:], data[34:50])
	return sh, nil
}

// MarshalClientProof сериализует ClientProof в байты
func MarshalClientProof(cp *ClientProof) []byte {
	buf := make([]byte, 34)
	binary.BigEndian.PutUint16(buf[0:2], cp.Type)
	copy(buf[2:34], cp.HMAC[:])
	return buf
}

// UnmarshalClientProof десериализует ClientProof из байтов
func UnmarshalClientProof(data []byte) (*ClientProof, error) {
	if len(data) != 34 {
		return nil, fmt.Errorf("invalid ClientProof size: %d", len(data))
	}
	cp := &ClientProof{}
	cp.Type = binary.BigEndian.Uint16(data[0:2])
	copy(cp.HMAC[:], data[2:34])
	return cp, nil
}

// MarshalSessionConfirm сериализует SessionConfirm в байты
func MarshalSessionConfirm(sc *SessionConfirm) []byte {
	buf := make([]byte, 34)
	binary.BigEndian.PutUint16(buf[0:2], sc.Type)
	copy(buf[2:34], sc.HMAC[:])
	return buf
}

// UnmarshalSessionConfirm десериализует SessionConfirm из байтов
func UnmarshalSessionConfirm(data []byte) (*SessionConfirm, error) {
	if len(data) != 34 {
		return nil, fmt.Errorf("invalid SessionConfirm size: %d", len(data))
	}
	sc := &SessionConfirm{}
	sc.Type = binary.BigEndian.Uint16(data[0:2])
	copy(sc.HMAC[:], data[2:34])
	return sc, nil
}

// ComputeClientProof вычисляет HMAC для ClientProof
func ComputeClientProof(psk, nonceC, pubC []byte) [32]byte {
	h := hmac.New(sha256.New, psk)
	h.Write([]byte("client_prove"))
	h.Write(nonceC)
	h.Write(pubC)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// ComputeServerAuth вычисляет HMAC для ServerHello (если понадобится)
func ComputeServerAuth(psk, nonceS, pubS []byte) [32]byte {
	h := hmac.New(sha256.New, psk)
	h.Write([]byte("server_prove"))
	h.Write(nonceS)
	h.Write(pubS)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// ComputeSessionConfirm вычисляет HMAC для SessionConfirm
func ComputeSessionConfirm(psk, nonceC, nonceS []byte) [32]byte {
	h := hmac.New(sha256.New, psk)
	h.Write([]byte("session_confirm"))
	h.Write(nonceC)
	h.Write(nonceS)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
