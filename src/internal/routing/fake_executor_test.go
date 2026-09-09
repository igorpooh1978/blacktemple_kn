package routing

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// fakeExecutor records argv and returns canned probe outputs. Tests must not
// require a real iptables binary.
type fakeExecutor struct {
	mu sync.Mutex

	calls []Argv

	natS     string
	mangleS  string
	ipRule   string
	tableOut string
	tableErr error
	ssOut    string
	ssErr    error
	pidofOut string
	pidofErr error

	failAtMut int
	mutCount  int
	failErr   error
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{
		pidofErr: errors.New("fake: no xkeen process"),
	}
}

func (f *fakeExecutor) Run(ctx context.Context, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	cp := make([]string, len(args))
	copy(cp, args)
	call := Argv{Name: name, Args: cp}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)

	if !isProbe(name, args) {
		f.mutCount++
		if f.failAtMut > 0 && f.mutCount == f.failAtMut {
			err := f.failErr
			if err == nil {
				err = errors.New("fake executor injected failure")
			}
			return "", err
		}
		return "", nil
	}

	switch {
	case name == "iptables" && hasSeq(args, "-t", "nat", "-S"):
		return f.natS, nil
	case name == "iptables" && hasSeq(args, "-t", "mangle", "-S"):
		return f.mangleS, nil
	case name == "ip" && hasSeq(args, "-4", "rule", "show"):
		return f.ipRule, nil
	case name == "ip" && hasSeq(args, "-4", "route", "show", "table"):
		return f.tableOut, f.tableErr
	case name == "ss":
		return f.ssOut, f.ssErr
	case name == "cat":
		return f.ssOut, nil
	case name == "pidof" && hasSeq(args, "xkeen"):
		return f.pidofOut, f.pidofErr
	default:
		return "", nil
	}
}

func (f *fakeExecutor) snapshot() []Argv {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Argv, len(f.calls))
	copy(out, f.calls)
	return out
}

func isProbe(name string, args []string) bool {
	if name == "ss" || name == "pidof" || name == "cat" {
		return true
	}
	if name == "iptables" && hasToken(args, "-S") {
		return true
	}
	if name == "ip" && hasToken(args, "show") {
		return true
	}
	return false
}

func hasToken(args []string, tok string) bool {
	for _, a := range args {
		if a == tok {
			return true
		}
	}
	return false
}

func hasSeq(args []string, seq ...string) bool {
	if len(seq) == 0 || len(args) < len(seq) {
		return false
	}
	for i := 0; i <= len(args)-len(seq); i++ {
		ok := true
		for j := range seq {
			if args[i+j] != seq[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func argvLine(c Argv) string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}
