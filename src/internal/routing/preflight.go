package routing

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

func (e *HybridIptablesEngine) Preflight(ctx context.Context) (PreflightReport, error) {
	if err := ctx.Err(); err != nil {
		return PreflightReport{}, err
	}

	report := PreflightReport{
		OK:          true,
		IPv6Capture: IPv6CaptureUnverified,
	}

	natS, _ := e.exec.Run(ctx, "iptables", "-t", "nat", "-S")
	mangleS, _ := e.exec.Run(ctx, "iptables", "-t", "mangle", "-S")
	rules, _ := e.exec.Run(ctx, "ip", "-4", "rule", "show")
	tableOut, tableErr := e.exec.Run(ctx, "ip", "-4", "route", "show", "table", strconv.Itoa(RouteTable))
	ssOut, ssErr := e.exec.Run(ctx, "ss", "-lntuH")
	if ssErr != nil {
		tcpOut, _ := e.exec.Run(ctx, "cat", "/proc/net/tcp")
		udpOut, _ := e.exec.Run(ctx, "cat", "/proc/net/udp")
		ssOut = tcpOut + "\n" + udpOut
	}
	pidofOut, pidofErr := e.exec.Run(ctx, "pidof", "xkeen")

	e.mu.Lock()
	applied := e.applied
	e.mu.Unlock()

	blob := natS + "\n" + mangleS + "\n" + rules
	if markInUse(blob) && !applied {
		report.Collisions = append(report.Collisions, Collision{
			Kind:   CollisionMark,
			Detail: "mark 0x42544b4e already in use",
		})
	}
	if tableInUse(tableOut, tableErr) && !applied {
		report.Collisions = append(report.Collisions, Collision{
			Kind:   CollisionTable,
			Detail: "table 4254 already exists",
		})
	}
	if listenPortUsed(ssOut, CapturePort) && !applied {
		report.Collisions = append(report.Collisions, Collision{
			Kind:   CollisionPort,
			Detail: "port 11820 already in use",
		})
	}
	if btknChainsPresent(natS, mangleS) && !applied {
		report.Collisions = append(report.Collisions, Collision{
			Kind:   CollisionChain,
			Detail: "BTKN chains unexpectedly exist",
		})
	}

	xkeen := detectXKeen(natS, mangleS, ssOut, pidofOut, pidofErr == nil)
	if xkeen {
		report.XKeenActive = true
		report.Collisions = append(report.Collisions, Collision{
			Kind:   CollisionXKeen,
			Detail: "xkeen capture engine detected",
		})
	}

	if len(report.Collisions) > 0 {
		report.OK = false
	}
	return report, nil
}

func markInUse(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "0x42544b4e") {
		return true
	}
	return strings.Contains(s, strconv.FormatUint(TProxyMark, 10))
}

func tableInUse(out string, err error) bool {
	msg := strings.ToLower(strings.TrimSpace(out))
	if err != nil {
		em := strings.ToLower(err.Error() + " " + msg)
		if strings.Contains(em, "does not exist") || strings.Contains(em, "no such file") {
			return false
		}
		return false
	}
	return msg != ""
}

var portBoundary = func(port int) *regexp.Regexp {
	return regexp.MustCompile(`:` + strconv.Itoa(port) + `([^0-9]|$)`)
}

func listenPortUsed(s string, port int) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	if portBoundary(port).MatchString(s) {
		return true
	}
	p := strconv.Itoa(port)
	return strings.Contains(s, "--to-ports "+p) || strings.Contains(s, "--on-port "+p)
}

func btknChainsPresent(natS, mangleS string) bool {
	blob := natS + "\n" + mangleS
	for _, name := range []string{ChainPRE, ChainTCP, ChainUDP, ChainOUT} {
		if strings.Contains(blob, name) {
			return true
		}
	}
	return false
}

func detectXKeen(natS, mangleS, listenOut, pidofOut string, pidofOK bool) bool {
	blob := natS + "\n" + mangleS
	lower := strings.ToLower(blob)
	if strings.Contains(lower, "xkeen") || strings.Contains(lower, "xkeen_rule") {
		return true
	}
	if listenPortUsed(listenOut, 1181) {
		return true
	}
	if strings.Contains(blob, "--to-ports 1181") || strings.Contains(blob, "--on-port 1181") {
		return true
	}
	if pidofOK && strings.TrimSpace(pidofOut) != "" {
		return true
	}
	return false
}
