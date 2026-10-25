package gateway

import (
	"fmt"
	"sync"
	"time"

	"minimax2api/internal/store"
)

// limiter enforces per-key RPM and concurrency limits.
type limiter struct {
	mu       sync.Mutex
	windows  map[string][]time.Time
	inflight map[string]int
}

func newLimiter() *limiter {
	return &limiter{
		windows:  make(map[string][]time.Time),
		inflight: make(map[string]int),
	}
}

func (l *limiter) acquire(key *store.ClientKey) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Concurrency is checked before the RPM window is charged. The other order
	// burned a request-per-minute slot for a request that never ran: a key
	// pinned at its concurrency ceiling spent its whole RPM budget on its own
	// 429s, and by the time a slot freed up there was no rate budget left to
	// serve it. A rejected request does not count.
	if limit := key.MaxConcurrent; limit > 0 && l.inflight[key.ID] >= limit {
		return fmt.Errorf("concurrency limit exceeded (%d simultaneous requests)", limit)
	}

	if key.RPMLimit > 0 {
		cutoff := time.Now().Add(-time.Minute)
		recent := l.windows[key.ID][:0]
		for _, stamp := range l.windows[key.ID] {
			if stamp.After(cutoff) {
				recent = append(recent, stamp)
			}
		}
		if len(recent) >= key.RPMLimit {
			l.windows[key.ID] = recent
			return fmt.Errorf("rate limit exceeded (%d requests per minute)", key.RPMLimit)
		}
		l.windows[key.ID] = append(recent, time.Now())
	}

	// A non-positive MaxConcurrent means unlimited, the same way RPMLimit reads
	// zero. It used to fall back to 4, which made "unset" mean "four" and left
	// no way to ask for no limit at all.
	l.inflight[key.ID]++
	return nil
}

func (l *limiter) release(key *store.ClientKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inflight[key.ID] > 0 {
		l.inflight[key.ID]--
	}
}

// Inflight reports current concurrency for one key (used by the console).
func (l *limiter) Inflight(id string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inflight[id]
}
