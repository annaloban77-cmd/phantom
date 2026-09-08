package evasion

import (
	"sync"
	"time"
)

// BlockSignal represents different types of blocking signals
type BlockSignal int

const (
	SignalNone BlockSignal = iota
	SignalTCPRST
	SignalTimeout
	SignalHTTP403
	SignalHTTP451
	SignalDNSPoison
)

// Detector monitors connection health and detects blocking
type Detector struct {
	mu           sync.Mutex
	baselineRTT  time.Duration
	rttSamples   []time.Duration
	failureCount int
	maxSamples   int
}

// NewDetector creates a new block detector
func NewDetector() *Detector {
	return &Detector{
		rttSamples: make([]time.Duration, 0, 10),
		maxSamples: 10,
	}
}

// RecordRTT records an RTT sample and updates baseline
func (d *Detector) RecordRTT(rtt time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.rttSamples = append(d.rttSamples, rtt)

	// Keep only last N samples
	if len(d.rttSamples) > d.maxSamples {
		d.rttSamples = d.rttSamples[1:]
	}

	// Update baseline (median of samples)
	d.updateBaseline()
}

// updateBaseline computes median RTT from samples
func (d *Detector) updateBaseline() {
	if len(d.rttSamples) == 0 {
		return
	}

	// Simple median calculation
	sorted := make([]time.Duration, len(d.rttSamples))
	copy(sorted, d.rttSamples)

	// Bubble sort for small arrays
	for i := 0; i < len(sorted)-1; i++ {
		for j := 0; j < len(sorted)-i-1; j++ {
			if sorted[j] > sorted[j+1] {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}

	medianIdx := len(sorted) / 2
	d.baselineRTT = sorted[medianIdx]
}

// DetectAnomaly checks if current RTT indicates blocking
func (d *Detector) DetectAnomaly(rtt time.Duration) BlockSignal {
	d.mu.Lock()
	defer d.mu.Unlock()

	// No baseline yet
	if d.baselineRTT == 0 {
		return SignalNone
	}

	// Too fast - possible honeypot (< 30% of baseline)
	threshold := d.baselineRTT * 3 / 10
	if rtt < threshold && d.baselineRTT > 10*time.Millisecond {
		return SignalTCPRST
	}

	// Timeout (> 5 seconds)
	if rtt > 5*time.Second {
		return SignalTimeout
	}

	return SignalNone
}

// RecordBlock records a blocking event
func (d *Detector) RecordBlock(signal BlockSignal) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if signal != SignalNone {
		d.failureCount++
	}
}

// IsBlocked returns true if failure count exceeds threshold
func (d *Detector) IsBlocked() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.failureCount >= 3
}

// Reset resets all detector state
func (d *Detector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.baselineRTT = 0
	d.rttSamples = make([]time.Duration, 0, d.maxSamples)
	d.failureCount = 0
}

// GetFailureCount returns current failure count (for testing)
func (d *Detector) GetFailureCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failureCount
}

// GetBaselineRTT returns current baseline RTT (for testing)
func (d *Detector) GetBaselineRTT() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.baselineRTT
}
