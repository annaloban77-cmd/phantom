package handshake

import (
	"container/list"
	"sync"
)

// ReplayWindow защищает от replay-атак, храня использованные nonces
type ReplayWindow struct {
	mu      sync.Mutex
	seen    map[string]struct{}
	order   *list.List
	maxSize int
}

// NewReplayWindow создаёт новое окно replay защиты с LRU eviction
func NewReplayWindow(maxSize int) *ReplayWindow {
	return &ReplayWindow{
		seen:    make(map[string]struct{}),
		order:   list.New(),
		maxSize: maxSize,
	}
}

// CheckAndAdd проверяет nonce и добавляет в окно если новый
// Возвращает true если nonce новый, false если уже был (replay detected)
func (w *ReplayWindow) CheckAndAdd(nonce [16]byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := string(nonce[:])

	// Проверка на дубликат
	if _, exists := w.seen[key]; exists {
		return false // replay detected
	}

	// Добавляем в seen
	w.seen[key] = struct{}{}
	w.order.PushBack(key)

	// LRU eviction если превышен размер
	for w.order.Len() > w.maxSize {
		oldest := w.order.Front()
		if oldest != nil {
			oldKey := oldest.Value.(string)
			delete(w.seen, oldKey)
			w.order.Remove(oldest)
		}
	}

	return true // new nonce accepted
}

// Size возвращает текущее количество stored nonces
func (w *ReplayWindow) Size() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.order.Len()
}

// Clear очищает окно
func (w *ReplayWindow) Clear() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = make(map[string]struct{})
	w.order = list.New()
}
