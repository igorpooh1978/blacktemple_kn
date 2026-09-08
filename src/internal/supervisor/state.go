package supervisor

// State is the frozen Xray child lifecycle state.
type State string

const (
	StateStopped   State = "STOPPED"
	StateStarting  State = "STARTING"
	StateRunning   State = "RUNNING"
	StateReloading State = "RELOADING"
	StateFailed    State = "FAILED"
	StateBackoff   State = "BACKOFF"
)

func (s State) Valid() bool {
	switch s {
	case StateStopped, StateStarting, StateRunning, StateReloading, StateFailed, StateBackoff:
		return true
	default:
		return false
	}
}

var allowedTransitions = map[State]map[State]struct{}{
	StateStopped: {
		StateStarting: {},
	},
	StateStarting: {
		StateRunning: {},
		StateFailed:  {},
		StateStopped: {},
	},
	StateRunning: {
		StateStopped:   {},
		StateReloading: {},
		StateBackoff:   {},
		StateFailed:    {},
	},
	StateReloading: {
		StateRunning: {},
		StateFailed:  {},
		StateStopped: {},
		StateBackoff: {},
	},
	StateBackoff: {
		StateStarting: {},
		StateStopped:  {},
		StateFailed:   {},
	},
	StateFailed: {
		StateStarting: {},
		StateStopped:  {},
	},
}

// CanTransition reports whether a direct state change is allowed.
func CanTransition(from, to State) bool {
	if from == to {
		return true
	}
	next, ok := allowedTransitions[from]
	if !ok {
		return false
	}
	_, ok = next[to]
	return ok
}
