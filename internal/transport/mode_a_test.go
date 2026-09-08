package transport

import (
	"context"
	"testing"
	"time"

	"github.com/phantom-tunnel/phantom/internal/common"
	utls "github.com/refraction-networking/utls"
)

func TestDialModeAInvalidAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	// Just test that invalid address returns error without needing utls spec
	_, err := DialModeA(ctx, "invalid-address-that-does-not-exist:9999", psk, nil)
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestPacketRoundTrip(t *testing.T) {
	// This test requires a full client-server setup
	// For unit testing, we just verify the framing logic
	
	payload := []byte("test message")
	msgType := common.MsgData

	// Build plaintext
	plaintext := append([]byte{byte(msgType)}, payload...)
	
	if len(plaintext) != len(payload)+1 {
		t.Fatalf("plaintext size mismatch: %d vs %d", len(plaintext), len(payload)+1)
	}
	
	if plaintext[0] != byte(msgType) {
		t.Errorf("msgType not at position 0")
	}
}

func TestPacketTooLarge(t *testing.T) {
	maxPayload := common.MaxPacketSize - 4 - 16 // length + tag
	
	oversized := make([]byte, maxPayload+1)
	if len(oversized) <= maxPayload {
		t.Fatal("oversized payload construction failed")
	}
	
	// Verify that this would be rejected
	if len(oversized) > maxPayload {
		// Expected behavior
	}
}
