package shaper

import (
	"testing"
	"time"
)

func TestIdleBufferWrite(t *testing.T) {
	buf := NewIdleBuffer(100)

	data := []byte("hello world")
	full := buf.Write(data)

	if full {
		t.Fatal("buffer should not be full after single write")
	}

	got := buf.GetData()
	if string(got) != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestIdleBufferMaxSize(t *testing.T) {
	buf := NewIdleBuffer(10)

	// Записываем больше чем maxSize
	data := []byte("this is more than 10 bytes")
	full := buf.Write(data)

	if !full {
		t.Fatal("buffer should be full after exceeding maxSize")
	}
}

func TestIdleBufferFlush(t *testing.T) {
	buf := NewIdleBuffer(100)

	buf.Write([]byte("first"))
	buf.Write([]byte("second"))

	flushed := buf.Flush()

	if string(flushed) != "firstsecond" {
		t.Errorf("got %q, want %q", flushed, "firstsecond")
	}

	// После flush буфер пуст
	got := buf.GetData()
	if len(got) != 0 {
		t.Errorf("buffer should be empty after flush, got %d bytes", len(got))
	}
}

func TestIdleBufferStartIdle(t *testing.T) {
	buf := NewIdleBuffer(100)

	buf.StartIdle(100 * time.Millisecond)

	if !buf.IsIdle() {
		t.Fatal("buffer should be in idle mode")
	}

	// В idle-режиме Write должен вернуть false
	written := buf.Write([]byte("data"))
	if written {
		t.Fatal("Write should return false during idle")
	}

	// Ждём окончания idle
	time.Sleep(150 * time.Millisecond)

	if buf.IsIdle() {
		t.Fatal("idle should have expired")
	}
}

func TestIdleBufferEndIdle(t *testing.T) {
	buf := NewIdleBuffer(100)

	buf.StartIdle(time.Hour) // Долгий idle

	if !buf.IsIdle() {
		t.Fatal("buffer should be in idle mode")
	}

	buf.EndIdle()

	if buf.IsIdle() {
		t.Fatal("idle should have ended")
	}

	// После EndIdle можно писать
	written := buf.Write([]byte("data"))
	if !written && len(buf.GetData()) == 0 {
		t.Fatal("Write should work after EndIdle")
	}
}

func TestIdleBufferClear(t *testing.T) {
	buf := NewIdleBuffer(100)

	buf.Write([]byte("some data"))
	buf.Clear()

	got := buf.GetData()
	if len(got) != 0 {
		t.Errorf("buffer should be empty after clear, got %d bytes", len(got))
	}
}

func TestIdleBufferConcurrentAccess(t *testing.T) {
	buf := NewIdleBuffer(1000)

	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 100; i++ {
			buf.Write([]byte("test data"))
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			buf.Flush()
		}
		done <- true
	}()

	<-done
	<-done

	// Если не было паники - тест пройден
}

func TestIdleBufferIsIdleExpired(t *testing.T) {
	buf := NewIdleBuffer(100)

	buf.StartIdle(50 * time.Millisecond)

	if !buf.IsIdle() {
		t.Fatal("should be idle initially")
	}

	// Ждём истечения
	time.Sleep(100 * time.Millisecond)

	if buf.IsIdle() {
		t.Fatal("idle should have expired")
	}
}
