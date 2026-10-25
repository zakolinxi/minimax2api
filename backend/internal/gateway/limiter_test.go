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

// A request refused for concurrency must not burn a request-per-minute slot.
// The other order let a key pinned at its ceiling spend its whole RPM budget
// on its own 429s.
func TestLimiterConcurrencyRejectionDoesNotBurnRPM(t *testing.T) {
	l := newLimiter()
	key := &store.ClientKey{ID: "k", RPMLimit: 2, MaxConcurrent: 1}

	if err := l.acquire(key); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := l.acquire(key); err == nil {
		t.Fatal("second acquire over the concurrency ceiling should fail")
	}
	l.release(key)

	// The RPM window holds only the one request that actually ran: the
	// concurrency 429 counted for nothing. This acquire is the second real
	// request and fits the budget of two.
	if err := l.acquire(key); err != nil {
		t.Fatalf("acquire after the slot freed: %v — the concurrency rejection must not have charged RPM", err)
	}
	// Now the RPM window is genuinely spent: three requests against a budget
	// of two, only two of which ever ran.
	if err := l.acquire(key); err == nil {
		t.Fatal("third acquire within the same minute should hit the RPM limit")
	}
}
