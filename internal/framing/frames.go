package framing

import (
	"encoding/binary"
	"math/rand"
)

type FrameType uint8

const (
	FrameData     FrameType = 0x00
	FrameHeaders  FrameType = 0x01
	FrameSettings FrameType = 0x04
	FramePing     FrameType = 0x06
)

type FrameHeader struct {
	Length   uint32
	Type     FrameType
	Flags    uint8
	StreamID uint32
}

func (h *FrameHeader) Marshal() []byte {
	buf := make([]byte, 9)
	buf[0] = byte(h.Length >> 16)
	buf[1] = byte(h.Length >> 8)
	buf[2] = byte(h.Length)
	buf[3] = byte(h.Type)
	buf[4] = byte(h.Flags)
	binary.BigEndian.PutUint32(buf[5:9], h.StreamID)
	return buf
}

func UnmarshalFrameHeader(data []byte) (*FrameHeader, error) {
	if len(data) < 9 {
		return nil, ErrInvalidFrameSize
	}
	length := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	return &FrameHeader{
		Length:   length,
		Type:     FrameType(data[3]),
		Flags:    data[4],
		StreamID: binary.BigEndian.Uint32(data[5:9]),
	}, nil
}

type Framer struct {
	rng               *rand.Rand
	streamID          uint32
	dataSinceHeaders  int
	headerPaths       []string
}

var headerPaths = []string{
	"/api/v2/data",
	"/static/js/app.js",
	"/img/logo.png",
	"/favicon.ico",
	"/css/main.css",
	"/api/v1/status",
}

func NewFramer(seed [32]byte) *Framer {
	src := rand.NewSource(int64(binary.BigEndian.Uint64(seed[:8])))
	return &Framer{
		rng:              rand.New(src),
		streamID:         1,
		dataSinceHeaders: 0,
		headerPaths:      headerPaths,
	}
}

func (f *Framer) WrapData(payload []byte) []byte {
	f.dataSinceHeaders++

	// Check if we should insert headers first
	if f.ShouldInsertHeaders() {
		headers := f.GenerateHeaders()
		dataFrame := f.generateDataFrame(payload)
		return append(headers, dataFrame...)
	}

	return f.generateDataFrame(payload)
}

func (f *Framer) generateDataFrame(payload []byte) []byte {
	h := &FrameHeader{
		Length:   uint32(len(payload)),
		Type:     FrameData,
		Flags:    0x00,
		StreamID: f.streamID,
	}

	frame := h.Marshal()
	frame = append(frame, payload...)
	return frame
}

func (f *Framer) GenerateHeaders() []byte {
	// Select random path
	pathIdx := f.rng.Intn(len(f.headerPaths))
	path := f.headerPaths[pathIdx]

	// Target size: 50-200 bytes total
	targetSize := 50 + f.rng.Intn(151)

	// Start with HPACK-simulated headers
	// First byte 0x82 (indexed :method GET)
	// Second byte 0x84 (indexed :path /)
	content := []byte{0x82, 0x84}
	
	// Add authority and scheme
	content = append(content, 0x87) // :scheme https
	content = append(content, 0x83) // :authority indexed
	
	// Add path (simplified - just append bytes)
	content = append(content, []byte(path)...)
	
	// Add random padding to reach target size
	for len(content) < targetSize-9 {
		content = append(content, byte(f.rng.Intn(256)))
	}

	// Final frame size = content length
	h := &FrameHeader{
		Length:   uint32(len(content)),
		Type:     FrameHeaders,
		Flags:    0x04, // END_HEADERS
		StreamID: f.streamID,
	}

	f.streamID += 2 // Next stream
	f.dataSinceHeaders = 0

	frame := h.Marshal()
	frame = append(frame, content...)
	return frame
}

func (f *Framer) GenerateSettings() []byte {
	// Settings payload: MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=6291456, ENABLE_PUSH=0
	// Each setting: 2B ID + 4B value = 6B, 3 settings = 18B
	settings := make([]byte, 0, 18)
	
	// ENABLE_PUSH (0x2) = 0
	settings = append(settings, 0x00, 0x02)
	settings = append(settings, 0x00, 0x00, 0x00, 0x00)
	
	// MAX_CONCURRENT_STREAMS (0x3) = 100
	settings = append(settings, 0x00, 0x03)
	settings = append(settings, 0x00, 0x00, 0x00, 0x64)
	
	// INITIAL_WINDOW_SIZE (0x4) = 6291456
	settings = append(settings, 0x00, 0x04)
	settings = append(settings, 0x00, 0x60, 0x00, 0x00)

	h := &FrameHeader{
		Length:   uint32(len(settings)),
		Type:     FrameSettings,
		Flags:    0x00,
		StreamID: 0, // Settings always on stream 0
	}

	frame := h.Marshal()
	frame = append(frame, settings...)
	return frame
}

func (f *Framer) GeneratePing() []byte {
	// Ping payload: 8 random bytes
	payload := make([]byte, 8)
	for i := range payload {
		payload[i] = byte(f.rng.Intn(256))
	}

	h := &FrameHeader{
		Length:   uint32(len(payload)),
		Type:     FramePing,
		Flags:    0x00,
		StreamID: 0, // Ping always on stream 0
	}

	frame := h.Marshal()
	frame = append(frame, payload...)
	return frame
}

func (f *Framer) ShouldInsertHeaders() bool {
	// Insert headers every ~10 DATA frames
	if f.dataSinceHeaders >= 10 {
		return true
	}
	// Or randomly with 10% probability
	return f.rng.Float64() < 0.1
}
