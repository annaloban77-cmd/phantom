package shaper

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	mrand "math/rand"
	"sync"
	"time"
)

// IdlePolicy конфигурирует поведение в режиме простоя
type IdlePolicy struct {
	Enabled        bool          `yaml:"enabled"`
	MinIdle        time.Duration `yaml:"min_idle"`
	MaxIdle        time.Duration `yaml:"max_idle"`
	BufferSize     int           `yaml:"buffer_size"`
	TriggerOnBytes int64         `yaml:"trigger_on_bytes"`
}

// Behavior управляет параметрической моделью трафика
type Behavior struct {
	mu        sync.Mutex
	rng       *mrand.Rand
	bytesSent int64
	policy    IdlePolicy
}

// NewBehavior создает новую поведенческую модель
func NewBehavior(seed [32]byte, policy IdlePolicy) *Behavior {
	// Используем первые 8 байт seed для rand.Source
	src := int64(binary.BigEndian.Uint64(seed[:8]))
	rng := mrand.New(mrand.NewSource(src))

	return &Behavior{
		rng:    rng,
		policy: policy,
	}
}

// AddNoise добавляет шум к размеру пакета согласно нормальному распределению
// sigma = max(100, 0.15*payload)
// noise = Normal(0, sigma)
// result = clamp(payload+noise, payload-500, payload+2000)
func (b *Behavior) AddNoise(payload int) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	sigma := math.Max(100, float64(payload)*0.15)
	noise := b.rng.NormFloat64() * sigma

	result := int(math.Ceil(float64(payload) + noise))

	// Clamp
	minSize := payload - 500
	maxSize := payload + 2000

	if result < minSize {
		result = minSize
	}
	if result > maxSize {
		result = maxSize
	}

	return result
}

// InterBurstDelay вычисляет задержку между сериями пакетов
// base = 50ms + payload/1000ms
// jitter = Exponential(mean=100ms)
func (b *Behavior) InterBurstDelay(payload int) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	baseMs := 50 + (payload / 1000)

	// Exponential distribution with mean=100ms
	// F(x) = 1 - e^(-λx), λ = 1/mean
	u := b.rng.Float64()
	jitterMs := -math.Log(1.0-u) * 100 // mean=100ms

	totalMs := float64(baseMs) + jitterMs
	if totalMs < 0 {
		totalMs = 0
	}

	return time.Duration(totalMs) * time.Millisecond
}

// IntraBurstPacing вычисляет микро-задержку внутри серии пакетов
// Uniform(0, 1ms)
func (b *Behavior) IntraBurstPacing() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	return time.Duration(b.rng.Float64() * 1000000) // 0-1ms в наносекундах
}

// ShouldTriggerIdle проверяет, пора ли переходить в idle-режим
func (b *Behavior) ShouldTriggerIdle() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.policy.Enabled {
		return false
	}

	return b.bytesSent >= b.policy.TriggerOnBytes
}

// RecordBytesSent записывает количество отправленных байт
func (b *Behavior) RecordBytesSent(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.bytesSent += int64(n)
}

// ResetBytesSent сбрасывает счётчик байт
func (b *Behavior) ResetBytesSent() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.bytesSent = 0
}

// IdleDuration вычисляет длительность idle-периода
// Exponential(8s), clamp[MinIdle, MaxIdle]
func (b *Behavior) IdleDuration() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Exponential with mean=8s
	u := b.rng.Float64()
	durationSecs := -math.Log(1.0-u) * 8

	duration := time.Duration(durationSecs * float64(time.Second))

	// Clamp
	if duration < b.policy.MinIdle {
		duration = b.policy.MinIdle
	}
	if duration > b.policy.MaxIdle {
		duration = b.policy.MaxIdle
	}

	return duration
}

// GeneratePadding генерирует случайные байты для padding
func (b *Behavior) GeneratePadding(n int) []byte {
	padding := make([]byte, n)
	_, _ = rand.Read(padding)
	return padding
}

// HeartbeatInterval вычисляет интервал heartbeat
// Uniform(10s, 30s)
func (b *Behavior) HeartbeatInterval() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Uniform(10, 30) seconds
	secs := 10 + b.rng.Float64()*20

	return time.Duration(secs * float64(time.Second))
}
