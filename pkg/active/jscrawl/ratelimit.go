package jscrawl

import (
	"context"
	"net/url"
	"sync"
	"time"
)

// rateLimiter implements a per-host minimum interval between fetches. It is
// intentionally lightweight (no buffered bucket): we simply track the next
// allowed timestamp per host and sleep until then. Good enough for crawl-rate
// politeness; if you need precise QPS shaping use golang.org/x/time/rate.
//
// Concurrency: safe for any number of concurrent callers. Each call to wait()
// is independently rate-limited; callers are not serialised globally beyond
// what the per-host interval already enforces.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     map[string]time.Time
}

// newRateLimiter returns nil when perSec <= 0 (callers must check). Using a
// nil receiver for wait() is a deliberate no-op so call sites stay clean.
func newRateLimiter(perSec int) *rateLimiter {
	if perSec <= 0 {
		return nil
	}
	return &rateLimiter{
		interval: time.Second / time.Duration(perSec),
		next:     make(map[string]time.Time),
	}
}

// wait blocks until this host's next slot is allowed, or ctx is cancelled.
// Returns ctx.Err() when ctx was cancelled while sleeping.
func (r *rateLimiter) wait(ctx context.Context, rawURL string) error {
	if r == nil {
		return nil
	}
	host := hostKey(rawURL)

	r.mu.Lock()
	now := time.Now()
	slot := r.next[host]
	if slot.Before(now) {
		slot = now
	}
	r.next[host] = slot.Add(r.interval)
	sleep := slot.Sub(now)
	r.mu.Unlock()

	if sleep <= 0 {
		return nil
	}
	t := time.NewTimer(sleep)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// hostKey reduces a URL down to its host (incl. port) for limiter bucketing.
// On parse failure we fall back to the full string so we still rate-limit
// something rather than nothing.
func hostKey(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	return rawURL
}
