package shaper

import (
	"testing"
	"time"
)

func TestAddNoiseVariance(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	policy := IdlePolicy{
		Enabled:        false,
		MinIdle:        time.Second,
		MaxIdle:        time.Minute,
		BufferSize:     1024,
		TriggerOnBytes: 4096,
	}

	b := NewBehavior(seed, policy)

	samples := make([]int, 1000)
	payload := 1000

	for i := 0; i < 1000; i++ {
		samples[i] = b.AddNoise(payload)
	}

	// Вычисляем дисперсию
	var sum float64
	for _, s := range samples {
		sum += float64(s)
	}
	mean := sum / float64(len(samples))

	var variance float64
	for _, s := range samples {
		diff := float64(s) - mean
		variance += diff * diff
	}
	variance /= float64(len(samples))

	if variance <= 0 {
		t.Fatal("variance should be > 0")
	}

	// Ожидаемая дисперсия примерно sigma^2 где sigma = max(100, 0.15*1000) = 150
	// variance ≈ 150^2 = 22500
	t.Logf("variance = %.2f, mean = %.2f", variance, mean)
}

func TestAddNoiseClamp(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	policy := IdlePolicy{}
	b := NewBehavior(seed, policy)

	payload := 1000
	minExpected := payload - 500
	maxExpected := payload + 2000

	for i := 0; i < 100; i++ {
		result := b.AddNoise(payload)
		if result < minExpected {
			t.Errorf("result %d < min %d", result, minExpected)
		}
		if result > maxExpected {
			t.Errorf("result %d > max %d", result, maxExpected)
		}
	}
}

func TestInterBurstDelay(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	policy := IdlePolicy{}
	b := NewBehavior(seed, policy)

	delays := make([]time.Duration, 100)
	payload := 500

	for i := 0; i < 100; i++ {
		delays[i] = b.InterBurstDelay(payload)
	}

	// Вычисляем среднее
	var totalMs float64
	for _, d := range delays {
		totalMs += float64(d.Milliseconds())
	}
	meanMs := totalMs / float64(len(delays))

	// base = 50 + 500/1000 = 50.5ms
	// jitter mean = 100ms
	// expected mean ≈ 150ms, допустимый диапазон 50-250ms
	if meanMs < 50 || meanMs > 250 {
		t.Errorf("mean delay %.2fms outside expected range [50, 250]", meanMs)
	}

	t.Logf("mean delay = %.2fms", meanMs)
}

func TestIdleTrigger(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	policy := IdlePolicy{
		Enabled:        true,
		TriggerOnBytes: 1000,
	}
	b := NewBehavior(seed, policy)

	// До достижения порога
	if b.ShouldTriggerIdle() {
		t.Fatal("ShouldTriggerIdle should be false before threshold")
	}

	// Записываем данные
	b.RecordBytesSent(500)
	if b.ShouldTriggerIdle() {
		t.Fatal("ShouldTriggerIdle should be false at half threshold")
	}

	b.RecordBytesSent(500)
	if !b.ShouldTriggerIdle() {
		t.Fatal("ShouldTriggerIdle should be true after threshold")
	}
}

func TestIdleDurationRange(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	minIdle := 2 * time.Second
	maxIdle := 10 * time.Second

	policy := IdlePolicy{
		Enabled: true,
		MinIdle: minIdle,
		MaxIdle: maxIdle,
	}
	b := NewBehavior(seed, policy)

	for i := 0; i < 100; i++ {
		duration := b.IdleDuration()
		if duration < minIdle {
			t.Errorf("duration %v < minIdle %v", duration, minIdle)
		}
		if duration > maxIdle {
			t.Errorf("duration %v > maxIdle %v", duration, maxIdle)
		}
	}
}

func TestHeartbeatInterval(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	policy := IdlePolicy{}
	b := NewBehavior(seed, policy)

	intervals := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		intervals[i] = b.HeartbeatInterval()
	}

	// Проверяем диапазон [10s, 30s]
	for _, interval := range intervals {
		secs := interval.Seconds()
		if secs < 10 || secs > 30 {
			t.Errorf("heartbeat interval %.2fs outside [10, 30]", secs)
		}
	}

	// Проверяем наличие вариации
	var sum float64
	for _, i := range intervals {
		sum += i.Seconds()
	}
	mean := sum / float64(len(intervals))

	// Вычисляем дисперсию
	var variance float64
	for _, i := range intervals {
		diff := i.Seconds() - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	if variance <= 0 {
		t.Fatal("heartbeat intervals should have variance")
	}

	t.Logf("mean heartbeat = %.2fs, variance = %.2f", mean, variance)
}

func TestIntraBurstPacing(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	policy := IdlePolicy{}
	b := NewBehavior(seed, policy)

	for i := 0; i < 100; i++ {
		delay := b.IntraBurstPacing()
		if delay < 0 {
			t.Errorf("delay %v < 0", delay)
		}
		if delay > time.Millisecond {
			t.Errorf("delay %v > 1ms", delay)
		}
	}
}

func TestResetBytesSent(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	policy := IdlePolicy{
		Enabled:        true,
		TriggerOnBytes: 1000,
	}
	b := NewBehavior(seed, policy)

	b.RecordBytesSent(1500)
	if !b.ShouldTriggerIdle() {
		t.Fatal("ShouldTriggerIdle should be true")
	}

	b.ResetBytesSent()
	if b.ShouldTriggerIdle() {
		t.Fatal("ShouldTriggerIdle should be false after reset")
	}
}

func TestGeneratePadding(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	policy := IdlePolicy{}
	b := NewBehavior(seed, policy)

	padding := b.GeneratePadding(100)
	if len(padding) != 100 {
		t.Errorf("padding length %d != 100", len(padding))
	}

	// Проверяем, что байты не все нулевые (случайные)
	allZero := true
	for _, p := range padding {
		if p != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("padding should not be all zeros")
	}
}
