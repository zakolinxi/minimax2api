package gateway

import (
	"testing"

	"minimax2api/internal/store"
)

// A key with no concurrency limit must not be stopped at four.
//
// Zero used to fall back to 4 inside the limiter, so "unset" silently meant
// "four simultaneous requests" and there was no way to express unlimited at all.
func TestLimiterTreatsZeroConcurrencyAsUnlimited(t *testing.T) {
	l := newLimiter()
	key := &store.ClientKey{ID: "key_unlimited"}
	for i := 0; i < 64; i++ {
		if err := l.acquire(key); err != nil {
			t.Fatalf("acquire %d of an unlimited key: %v", i+1, err)
		}
	}
	if got := l.Inflight(key.ID); got != 64 {
		t.Fatalf("inflight = %d, want 64", got)
	}
}

// A positive limit is still enforced, and releasing frees the slot again.
func TestLimiterEnforcesPositiveConcurrency(t *testing.T) {
	l := newLimiter()
	key := &store.ClientKey{ID: "key_two", MaxConcurrent: 2}
	if err := l.acquire(key); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := l.acquire(key); err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if err := l.acquire(key); err == nil {
		t.Fatal("the third simultaneous request must be refused")
	}
	l.release(key)
	if err := l.acquire(key); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
}
