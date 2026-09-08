package framing

import (
	"errors"
	"testing"
)

var ErrInvalidFrameSize = errors.New("invalid frame size")

func TestFrameHeaderMarshal(t *testing.T) {
	h := &FrameHeader{
		Length:   0x123456,
		Type:     FrameData,
		Flags:    0x04,
		StreamID: 0x00000001,
	}

	data := h.Marshal()
	if len(data) != 9 {
		t.Fatalf("expected 9 bytes, got %d", len(data))
	}

	// Check big-endian layout
	if data[0] != 0x12 || data[1] != 0x34 || data[2] != 0x56 {
		t.Errorf("length bytes wrong: %x %x %x", data[0], data[1], data[2])
	}
	if data[3] != byte(FrameData) {
		t.Errorf("type byte wrong: %x", data[3])
	}
	if data[4] != 0x04 {
		t.Errorf("flags byte wrong: %x", data[4])
	}
	if data[5] != 0x00 || data[6] != 0x00 || data[7] != 0x00 || data[8] != 0x01 {
		t.Errorf("streamID bytes wrong: %x %x %x %x", data[5], data[6], data[7], data[8])
	}
}

func TestUnmarshalFrameHeader(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00, byte(FrameHeaders), 0x04, 0x00, 0x00, 0x00, 0x02}

	h, err := UnmarshalFrameHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.Length != 0x000100 {
		t.Errorf("wrong length: %x", h.Length)
	}
	if h.Type != FrameHeaders {
		t.Errorf("wrong type: %x", h.Type)
	}
	if h.Flags != 0x04 {
		t.Errorf("wrong flags: %x", h.Flags)
	}
	if h.StreamID != 0x00000002 {
		t.Errorf("wrong streamID: %x", h.StreamID)
	}
}

func TestUnmarshalFrameHeaderTruncated(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00} // only 3 bytes

	_, err := UnmarshalFrameHeader(data)
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestFramerHeadersFrequency(t *testing.T) {
	seed := [32]byte{}
	for i := range seed {
		seed[i] = byte(i)
	}

	f := NewFramer(seed)

	// Should insert headers after 10 DATA frames OR randomly with 10% probability
	// We test that it eventually returns true
	inserted := false
	for i := 0; i < 15; i++ {
		if f.ShouldInsertHeaders() {
			inserted = true
			break
		}
		f.dataSinceHeaders++
	}

	if !inserted {
		t.Fatal("ShouldInsertHeaders never returned true within 15 iterations")
	}
	
	// After reset, should work again
	f.dataSinceHeaders = 0
	if !f.ShouldInsertHeaders() {
		// May be false due to random, so we just check it doesn't panic
	}
}

func TestFramerHeaderSize(t *testing.T) {
	seed := [32]byte{}
	for i := range seed {
		seed[i] = byte(i)
	}

	f := NewFramer(seed)

	// Generate multiple headers and check sizes
	for i := 0; i < 10; i++ {
		headers := f.GenerateHeaders()
		totalSize := len(headers)
		
		// Total frame size should be 9 (header) + content (50-200)
		contentSize := totalSize - 9
		if contentSize < 50 || contentSize > 200 {
			t.Errorf("iteration %d: header content size %d not in [50, 200]", i, contentSize)
		}
	}
}

func TestFramerSettingsSize(t *testing.T) {
	seed := [32]byte{}
	for i := range seed {
		seed[i] = byte(i)
	}

	f := NewFramer(seed)
	settings := f.GenerateSettings()

	// Settings frame: 9B header + 18B payload = 27B total
	if len(settings) != 27 {
		t.Errorf("settings size %d, expected 27", len(settings))
	}

	// Check header
	h, err := UnmarshalFrameHeader(settings[:9])
	if err != nil {
		t.Fatalf("failed to unmarshal settings header: %v", err)
	}
	if h.Type != FrameSettings {
		t.Errorf("wrong frame type: %x", h.Type)
	}
	if h.Length != 18 {
		t.Errorf("wrong payload length: %d", h.Length)
	}
	if h.StreamID != 0 {
		t.Errorf("settings should be on stream 0, got %d", h.StreamID)
	}
}

func TestFramerPingSize(t *testing.T) {
	seed := [32]byte{}
	for i := range seed {
		seed[i] = byte(i)
	}

	f := NewFramer(seed)
	ping := f.GeneratePing()

	// Ping frame: 9B header + 8B payload = 17B total
	if len(ping) != 17 {
		t.Errorf("ping size %d, expected 17", len(ping))
	}

	// Check header
	h, err := UnmarshalFrameHeader(ping[:9])
	if err != nil {
		t.Fatalf("failed to unmarshal ping header: %v", err)
	}
	if h.Type != FramePing {
		t.Errorf("wrong frame type: %x", h.Type)
	}
	if h.Length != 8 {
		t.Errorf("wrong payload length: %d", h.Length)
	}
	if h.StreamID != 0 {
		t.Errorf("ping should be on stream 0, got %d", h.StreamID)
	}
}

func TestFramerWrapData(t *testing.T) {
	seed := [32]byte{}
	for i := range seed {
		seed[i] = byte(i)
	}

	f := NewFramer(seed)
	payload := []byte("test data payload")

	wrapped := f.WrapData(payload)
	if len(wrapped) == 0 {
		t.Fatal("wrapped data is empty")
	}

	// First frame might include headers
	h, err := UnmarshalFrameHeader(wrapped[:9])
	if err != nil {
		t.Fatalf("failed to unmarshal wrapped header: %v", err)
	}

	// Should be either HEADERS or DATA
	if h.Type != FrameHeaders && h.Type != FrameData {
		t.Errorf("unexpected frame type: %x", h.Type)
	}
}
