package store

import (
	"testing"
	"time"
)

func TestLookupConsumeAndExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewWithClock[string](func() time.Time { return now })
	token := s.Issue("alice@example.com", time.Hour)
	if got, ok := s.Lookup(token); !ok || got != "alice@example.com" {
		t.Fatalf("Lookup = %q, %v", got, ok)
	}
	if got, ok := s.Consume(token); !ok || got != "alice@example.com" {
		t.Fatalf("Consume = %q, %v", got, ok)
	}
	if _, ok := s.Lookup(token); ok {
		t.Fatal("consumed token remained valid")
	}

	expiring := s.Issue("bob@example.com", time.Hour)
	now = now.Add(time.Hour)
	if _, ok := s.Lookup(expiring); ok {
		t.Fatal("expired token remained valid")
	}
}
