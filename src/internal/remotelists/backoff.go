package remotelists

import (
	"math/rand"
	"time"
)

// Backoff is the retry delay abstraction. Ordinary list retries use hours,
// not seconds.
type Backoff interface {
	Next(attempt int) time.Duration
}

// ExponentialBackoff is Base * 2^(attempt-1), capped at Max, with optional jitter.
type ExponentialBackoff struct {
	Base   time.Duration
	Max    time.Duration
	Jitter float64
	Rand   func() float64
}

// DefaultBackoff is 1h base, 24h cap, 20% jitter — hours/days, not seconds.
func DefaultBackoff() ExponentialBackoff {
	return ExponentialBackoff{
		Base:   time.Hour,
		Max:    24 * time.Hour,
		Jitter: 0.2,
	}
}

// Next returns the delay before the given 1-based attempt's retry wait.
// attempt 1 is the delay after the first failure.
func (b ExponentialBackoff) Next(attempt int) time.Duration {
	base := b.Base
	if base <= 0 {
		base = time.Hour
	}
	max := b.Max
	if max < base {
		max = base
	}
	if attempt < 1 {
		attempt = 1
	}
	d := base
	for i := 1; i < attempt; i++ {
		next := d * 2
		if next > max || next < d {
			d = max
			break
		}
		d = next
	}
	if d > max {
		d = max
	}
	j := b.Jitter
	if j <= 0 {
		return d
	}
	rnd := b.Rand
	if rnd == nil {
		rnd = rand.Float64
	}
	// d * (1 ± jitter)
	delta := float64(d) * j * (2*rnd() - 1)
	out := time.Duration(float64(d) + delta)
	if out < 0 {
		return 0
	}
	return out
}

// DefaultRefreshInterval is 12 hours for ordinary lists.
func DefaultRefreshInterval() time.Duration { return defaultTTL }
