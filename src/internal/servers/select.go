package servers

import (
	"errors"
	"strings"
)

var (
	ErrNotFound = errors.New("server not found")
	ErrEmpty    = errors.New("no servers")
)

// Mode matches contracts/schemas/config.schema.json server.mode.
type Mode string

const (
	ModeAuto     Mode = "auto"
	ModeManual   Mode = "manual"
	ModeFailover Mode = "failover"
	ModeRotate   Mode = "rotate"
)

func ParseMode(s string) Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeManual:
		return ModeManual
	case ModeFailover:
		return ModeFailover
	case ModeRotate:
		return ModeRotate
	default:
		return ModeAuto
	}
}

// Server is an endpoint identity without protocol secrets.
type Server struct {
	ID        string
	ProfileID string
	Host      string
	Port      int
	Transport string
	Security  string
	CountryID string
	Remark    string
}

func (s Server) String() string {
	return "Server{ID:" + s.ID +
		" Host:" + s.Host +
		" Port:" + itoa(s.Port) +
		" Transport:" + s.Transport +
		" Security:" + s.Security +
		" CountryID:" + s.CountryID + "}"
}

func (s Server) GoString() string { return s.String() }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Select picks a candidate server. Health probing lives in diagnostics;
// here AUTO is first remaining, FAILOVER/ROTATE walk the list.
func Select(mode Mode, list []Server, manualID, previousID string) (Server, error) {
	if len(list) == 0 {
		return Server{}, ErrEmpty
	}
	switch mode {
	case ModeManual:
		if manualID == "" {
			return Server{}, ErrNotFound
		}
		return byID(list, manualID)
	case ModeFailover, ModeRotate:
		return nextAfter(list, previousID)
	default:
		if previousID != "" {
			if s, err := byID(list, previousID); err == nil {
				return s, nil
			}
		}
		return list[0], nil
	}
}

func byID(list []Server, id string) (Server, error) {
	for _, s := range list {
		if s.ID == id {
			return s, nil
		}
	}
	return Server{}, ErrNotFound
}

func nextAfter(list []Server, previousID string) (Server, error) {
	if previousID == "" {
		return list[0], nil
	}
	for i, s := range list {
		if s.ID == previousID {
			return list[(i+1)%len(list)], nil
		}
	}
	return list[0], nil
}
