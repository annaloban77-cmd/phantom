package shaper

import (
	"sync"
	"time"
)

// IdleBuffer управляет буферизацией данных в idle-режиме
type IdleBuffer struct {
	mu        sync.Mutex
	data      []byte
	maxSize   int
	inIdle    bool
	idleUntil time.Time
}

// NewIdleBuffer создает новый idle-буфер
func NewIdleBuffer(maxSize int) *IdleBuffer {
	return &IdleBuffer{
		data:    make([]byte, 0, maxSize),
		maxSize: maxSize,
	}
}

// Write добавляет данные в буфер
// Возвращает true, если буфер заполнен
func (b *IdleBuffer) Write(data []byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.inIdle {
		// В idle-режиме данные не принимаем
		return false
	}

	b.data = append(b.data, data...)

	return len(b.data) >= b.maxSize
}

// Flush возвращает и очищает буфер
func (b *IdleBuffer) Flush() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	data := make([]byte, len(b.data))
	copy(data, b.data)
	b.data = b.data[:0]

	return data
}

// StartIdle запускает idle-режим на указанную длительность
func (b *IdleBuffer) StartIdle(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.inIdle = true
	b.idleUntil = time.Now().Add(d)
}

// IsIdle проверяет, активен ли idle-режим
func (b *IdleBuffer) IsIdle() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.inIdle {
		return false
	}

	if time.Now().After(b.idleUntil) {
		b.inIdle = false
		return false
	}

	return true
}

// EndIdle завершает idle-режим досрочно
func (b *IdleBuffer) EndIdle() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.inIdle = false
}

// GetData возвращает текущие данные без очистки
func (b *IdleBuffer) GetData() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	data := make([]byte, len(b.data))
	copy(data, b.data)
	return data
}

// Clear очищает буфер
func (b *IdleBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.data = b.data[:0]
}
