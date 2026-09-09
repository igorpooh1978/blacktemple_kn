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

	natS      string
	mangleS   string
	natErr    error
	mangleErr error
	ipRule    string
	ruleErr   error
	tableOut  string
	tableErr  error
	ssOut     string
	ssErr     error
	tcpOut    string
	udpOut    string
	pidofOut  string
	pidofErr  error
	exeByPID  map[int]string

	failAtMut      int
	mutCount       int
	failErr        error
	failDetach     bool
	failPermission bool
	ipsetPresent   bool
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
		if f.failDetach && hasSeq(args, "-D", "PREROUTING", "-j", ChainPRE) {
			return "", errors.New("fake detach jump failed")
		}
		if f.failPermission && hasSeq(args, "-D", "PREROUTING", "-j", ChainPRE) {
			return "iptables: Permission denied.\n", errors.New("exit status 1")
		}
		if f.failAtMut > 0 && f.mutCount == f.failAtMut {
			err := f.failErr
			if err == nil {
				err = errors.New("fake executor injected failure")
			}
			return "", err
		}
		if isUninstallCmd(name, args) && !f.uninstallTargetPresent(name, args) {
			return absentCombinedOutput(name, args)
		}
		f.applySuccess(name, args)
		return "", nil
	}

	switch {
	case name == "iptables" && hasSeq(args, "-t", "nat", "-S"):
		return f.natS, f.natErr
	case name == "iptables" && hasSeq(args, "-t", "mangle", "-S"):
		return f.mangleS, f.mangleErr
	case name == "ip" && hasSeq(args, "-4", "rule", "show"):
		return f.ipRule, f.ruleErr
	case name == "ip" && hasSeq(args, "-4", "route", "show", "table"):
		return f.tableOut, f.tableErr
	case name == "ss":
		return f.ssOut, f.ssErr
	case name == "cat" && hasToken(args, "/proc/net/tcp"):
		if f.tcpOut != "" {
			return f.tcpOut, nil
		}
		return f.ssOut, nil
	case name == "cat" && hasToken(args, "/proc/net/udp"):
		if f.udpOut != "" {
			return f.udpOut, nil
		}
		return f.ssOut, nil
	case name == "cat":
		return f.ssOut, nil
	case name == "readlink":
		return f.readlink(args), nil
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

func (f *fakeExecutor) readlink(args []string) string {
	if len(args) == 0 || f.exeByPID == nil {
		return ""
	}
	p := args[0]
	const prefix = "/proc/"
	if !strings.HasPrefix(p, prefix) || !strings.HasSuffix(p, "/exe") {
		return ""
	}
	num := strings.TrimSuffix(strings.TrimPrefix(p, prefix), "/exe")
	var pid int
	for _, c := range num {
		if c < '0' || c > '9' {
			return ""
		}
		pid = pid*10 + int(c-'0')
	}
	return f.exeByPID[pid]
}

func (f *fakeExecutor) applySuccess(name string, args []string) {
	if hasSeq(args, "-D", "PREROUTING", "-j", ChainPRE) {
		f.natS = stripJump(f.natS, ChainPRE)
		f.mangleS = stripJump(f.mangleS, ChainPRE)
	}
	if name == "ip" && hasToken(args, "del") && hasToken(args, "fwmark") {
		f.ipRule = ""
	}
	if name == "ip" && hasToken(args, "del") && hasToken(args, "table") {
		f.tableOut = ""
		f.tableErr = errors.New("Error: ipv4: FIB table does not exist.")
	}
	if name == "iptables" && (hasToken(args, "-X") || hasToken(args, "-F")) {
		for _, ch := range []string{ChainPRE, ChainTCP, ChainUDP, ChainOUT} {
			if hasToken(args, ch) {
				f.natS = strings.ReplaceAll(f.natS, ch, "")
				f.mangleS = strings.ReplaceAll(f.mangleS, ch, "")
			}
		}
	}
	if name == "ipset" && hasToken(args, "create") {
		f.ipsetPresent = true
	}
	if name == "ipset" && hasToken(args, "destroy") {
		f.ipsetPresent = false
	}
}

func isUninstallCmd(name string, args []string) bool {
	if name == "iptables" {
		return hasToken(args, "-D") || hasToken(args, "-X") || hasToken(args, "-F")
	}
	if name == "ip" {
		return hasToken(args, "del") || hasToken(args, "delete")
	}
	if name == "ipset" {
		return hasToken(args, "destroy") || hasToken(args, "flush")
	}
	return false
}

func (f *fakeExecutor) uninstallTargetPresent(name string, args []string) bool {
	if name == "iptables" && hasSeq(args, "-D", "PREROUTING", "-j", ChainPRE) {
		dump := f.natS
		if hasSeq(args, "-t", "mangle") {
			dump = f.mangleS
		}
		return jumpPresent(dump, "PREROUTING", ChainPRE)
	}
	if name == "iptables" && (hasToken(args, "-X") || hasToken(args, "-F")) {
		dump := f.natS + "\n" + f.mangleS
		for _, ch := range []string{ChainPRE, ChainTCP, ChainUDP, ChainOUT} {
			if hasToken(args, ch) && strings.Contains(dump, ch) {
				return true
			}
		}
		return false
	}
	if name == "ip" && hasToken(args, "rule") {
		return ownedMarkRulePresent(f.ipRule)
	}
	if name == "ip" && hasToken(args, "route") {
		return tableStillPresent(f.tableOut, f.tableErr)
	}
	if name == "ipset" {
		return f.ipsetPresent
	}
	return true
}

func absentCombinedOutput(name string, args []string) (string, error) {
	switch {
	case name == "iptables" && hasToken(args, "-D"):
		return "iptables: Bad rule (does a matching rule exist in that chain?).\n", errors.New("exit status 1")
	case name == "iptables":
		return "iptables: No chain/target/match by that name.\n", errors.New("exit status 1")
	case name == "ip" && hasToken(args, "rule"):
		return "RTNETLINK answers: No such process\n", errors.New("exit status 2")
	case name == "ip":
		return "Error: ipv4: FIB table does not exist.\nDump terminated\n", errors.New("exit status 2")
	case name == "ipset":
		return "ipset v7: The set with the given name does not exist\n", errors.New("exit status 1")
	default:
		return "", errors.New("exit status 1")
	}
}

func stripJump(dump, chain string) string {
	var b strings.Builder
	for _, line := range strings.Split(dump, "\n") {
		fields := strings.Fields(line)
		if hasSeq(fields, "-A", "PREROUTING", "-j", chain) {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
	}
	return b.String()
}

func isProbe(name string, args []string) bool {
	if name == "ss" || name == "pidof" || name == "cat" || name == "readlink" {
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

func argvLine(c Argv) string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}
