package routing

import (
	"fmt"
	"strings"
)

// Mode is the product routing mode (contracts/schemas/config.schema.json).
type Mode string

const (
	ModeSmart    Mode = "smart"
	ModeAll      Mode = "all"
	ModeSelected Mode = "selected"
)

func (m Mode) Valid() error {
	switch m {
	case ModeSmart, ModeAll, ModeSelected:
		return nil
	default:
		return fmt.Errorf("routing: invalid mode %q: %w", m, ErrInvalidRule)
	}
}

func ParseMode(s string) (Mode, error) {
	m := Mode(strings.ToLower(strings.TrimSpace(s)))
	if err := m.Valid(); err != nil {
		return "", err
	}
	return m, nil
}

// Action is the routing outcome for a matched flow.
type Action string

const (
	ActionProxy  Action = "proxy"
	ActionDirect Action = "direct"
	ActionBlock  Action = "block"
)

func (a Action) Valid() error {
	switch a {
	case ActionProxy, ActionDirect, ActionBlock:
		return nil
	default:
		return fmt.Errorf("routing: invalid action %q: %w", a, ErrInvalidRule)
	}
}

// Source is who contributed a rule.
type Source string

const (
	SourceBuiltin      Source = "builtin"
	SourceUser         Source = "user"
	SourceProvider     Source = "provider"
	SourceRemoteList   Source = "remote-list"
	SourceRemotePolicy Source = "remote-policy"
)

func (s Source) Valid() error {
	switch s {
	case SourceBuiltin, SourceUser, SourceProvider, SourceRemoteList, SourceRemotePolicy:
		return nil
	default:
		return fmt.Errorf("routing: invalid source %q: %w", s, ErrInvalidRule)
	}
}

// Priority bands (lower number wins). Planner sorts stably by (priority, id).
//
//	explicit user override > device override later > provider explicit policy
//	> remote list > builtin smart defaults > fallback
const (
	PriorityUserOverride   = 100
	PriorityDeviceOverride = 200 // reserved; LAN device match is unused this wave
	PriorityProviderPolicy = 300
	PriorityRemotePolicy   = 350
	PriorityRemoteList     = 400
	PriorityBuiltinSmart   = 500
	PriorityFallback       = 900
)

func defaultPriority(src Source) int {
	switch src {
	case SourceUser:
		return PriorityUserOverride
	case SourceProvider:
		return PriorityProviderPolicy
	case SourceRemotePolicy:
		return PriorityRemotePolicy
	case SourceRemoteList:
		return PriorityRemoteList
	case SourceBuiltin:
		return PriorityBuiltinSmart
	default:
		return PriorityFallback
	}
}
