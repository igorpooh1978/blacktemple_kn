package routing

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidRule   = errors.New("routing: invalid rule")
	ErrDuplicateRule = errors.New("routing: duplicate rule id")
)

// Rule is one routing entry. Disabled extra rules are omitted from the plan.
type Rule struct {
	ID       string
	Source   Source
	Priority int
	Action   Action
	Match    Match
	Enabled  bool
}

func (r Rule) clone() Rule {
	return r
}

func (r *Rule) normalize() error {
	if r == nil {
		return fmt.Errorf("routing: nil rule: %w", ErrInvalidRule)
	}
	r.ID = strings.TrimSpace(r.ID)
	if r.ID == "" {
		return fmt.Errorf("routing: empty rule id: %w", ErrInvalidRule)
	}
	if err := r.Source.Valid(); err != nil {
		return err
	}
	if err := r.Action.Valid(); err != nil {
		return err
	}
	if err := r.Match.normalize(); err != nil {
		return err
	}
	if r.Priority == 0 {
		r.Priority = defaultPriority(r.Source)
	}
	return nil
}
