package supervisor

import "time"

// RestartPolicy limits crash-driven restarts (no restart storm).
// Explicit Stop does not auto-restart. Child crash does.
type RestartPolicy struct {
	MaxRestarts    int
	Window         time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Multiplier     float64
}

// DefaultRestartPolicy is conservative for a router daemon.
func DefaultRestartPolicy() RestartPolicy {
	return RestartPolicy{
		MaxRestarts:    5,
		Window:         time.Minute,
		InitialBackoff: time.Second,
		MaxBackoff:     30 * time.Second,
		Multiplier:     2,
	}
}

// Backoff returns the delay after crashIndex successful crash observations
// in the current window (0 = first crash).
func (p RestartPolicy) Backoff(crashIndex int) time.Duration {
	d := p.InitialBackoff
	if d <= 0 {
		d = time.Millisecond
	}
	mult := p.Multiplier
	if mult < 1 {
		mult = 2
	}
	max := p.MaxBackoff
	if max <= 0 {
		max = d
	}
	for i := 0; i < crashIndex; i++ {
		next := time.Duration(float64(d) * mult)
		if next > max || next < d {
			return max
		}
		d = next
	}
	if d > max {
		return max
	}
	return d
}
