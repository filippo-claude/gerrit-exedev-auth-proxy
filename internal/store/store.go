package store

import (
	"crypto/rand"
	"sync"
	"time"
)

type Entry[T any] struct {
	Value   T
	Expires time.Time
}

type Store[T any] struct {
	mu      sync.Mutex
	entries map[string]Entry[T]
	now     func() time.Time
}

func New[T any]() *Store[T] {
	return NewWithClock[T](time.Now)
}

func NewWithClock[T any](now func() time.Time) *Store[T] {
	return &Store[T]{entries: make(map[string]Entry[T]), now: now}
}

func (s *Store[T]) Issue(value T, lifetime time.Duration) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		token := rand.Text()
		if _, exists := s.entries[token]; exists {
			continue
		}
		s.entries[token] = Entry[T]{Value: value, Expires: s.now().Add(lifetime)}
		return token
	}
}

func (s *Store[T]) Lookup(token string) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[token]
	if !ok {
		var zero T
		return zero, false
	}
	if !s.now().Before(entry.Expires) {
		delete(s.entries, token)
		var zero T
		return zero, false
	}
	return entry.Value, true
}

func (s *Store[T]) Consume(token string) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[token]
	if ok {
		delete(s.entries, token)
	}
	if !ok || !s.now().Before(entry.Expires) {
		var zero T
		return zero, false
	}
	return entry.Value, true
}

func (s *Store[T]) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, token)
}

func (s *Store[T]) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	removed := 0
	for token, entry := range s.entries {
		if !now.Before(entry.Expires) {
			delete(s.entries, token)
			removed++
		}
	}
	return removed
}
