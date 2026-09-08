package evasion

import (
	"testing"
	"time"
)

func TestDetectorAnomaly(t *testing.T) {
	d := NewDetector()

	// Establish baseline RTT of 100ms
	for i := 0; i < 5; i++ {
		d.RecordRTT(100 * time.Millisecond)
	}

	// Very fast response (< 30% of baseline) - possible honeypot
	signal := d.DetectAnomaly(20 * time.Millisecond)
	if signal != SignalTCPRST {
		t.Errorf("Expected SignalTCPRST for very fast RTT, got %v", signal)
	}
}

func TestDetectorTimeout(t *testing.T) {
	d := NewDetector()

	// Establish baseline
	for i := 0; i < 5; i++ {
		d.RecordRTT(100 * time.Millisecond)
	}

	// Timeout (> 5 seconds)
	signal := d.DetectAnomaly(6 * time.Second)
	if signal != SignalTimeout {
		t.Errorf("Expected SignalTimeout for long RTT, got %v", signal)
	}
}

func TestDetectorBlockCount(t *testing.T) {
	d := NewDetector()

	// Record 3 blocking events
	d.RecordBlock(SignalTCPRST)
	d.RecordBlock(SignalTimeout)
	d.RecordBlock(SignalHTTP403)

	if !d.IsBlocked() {
		t.Error("Expected IsBlocked() = true after 3 failures")
	}
}

func TestDetectorNotBlocked(t *testing.T) {
	d := NewDetector()

	// Record only 2 blocking events
	d.RecordBlock(SignalTCPRST)
	d.RecordBlock(SignalTimeout)

	if d.IsBlocked() {
		t.Error("Expected IsBlocked() = false with only 2 failures")
	}
}

func TestDetectorReset(t *testing.T) {
	d := NewDetector()

	// Establish state
	for i := 0; i < 5; i++ {
		d.RecordRTT(100 * time.Millisecond)
	}
	d.RecordBlock(SignalTCPRST)
	d.RecordBlock(SignalTimeout)

	// Reset
	d.Reset()

	if d.GetFailureCount() != 0 {
		t.Errorf("Expected failure count 0 after reset, got %d", d.GetFailureCount())
	}
	if d.GetBaselineRTT() != 0 {
		t.Errorf("Expected baseline RTT 0 after reset, got %v", d.GetBaselineRTT())
	}
}

func TestDetectorNoBaseline(t *testing.T) {
	d := NewDetector()

	// No baseline established yet
	signal := d.DetectAnomaly(50 * time.Millisecond)
	if signal != SignalNone {
		t.Errorf("Expected SignalNone when no baseline, got %v", signal)
	}
}

func TestDetectorNormalRTT(t *testing.T) {
	d := NewDetector()

	// Establish baseline of 100ms
	for i := 0; i < 5; i++ {
		d.RecordRTT(100 * time.Millisecond)
	}

	// Normal RTT (close to baseline)
	signal := d.DetectAnomaly(90 * time.Millisecond)
	if signal != SignalNone {
		t.Errorf("Expected SignalNone for normal RTT, got %v", signal)
	}
}

func TestDetectorMedianCalculation(t *testing.T) {
	d := NewDetector()

	// Add samples: 10, 20, 30, 40, 50 ms
	samples := []time.Duration{10, 20, 30, 40, 50}
	for _, s := range samples {
		d.RecordRTT(s * time.Millisecond)
	}

	baseline := d.GetBaselineRTT()
	expected := 30 * time.Millisecond // median of [10,20,30,40,50]

	if baseline != expected {
		t.Errorf("Expected median %v, got %v", expected, baseline)
	}
}

func TestDetectorSampleWindow(t *testing.T) {
	d := NewDetector()

	// Add more than maxSamples (10)
	for i := 0; i < 15; i++ {
		d.RecordRTT(time.Duration(i) * time.Millisecond)
	}

	// Should only keep last 10 samples
	if len(d.rttSamples) != 10 {
		t.Errorf("Expected 10 samples, got %d", len(d.rttSamples))
	}
}
