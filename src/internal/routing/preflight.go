package routing

import (
	"context"
	"fmt"
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

	natS, err := e.exec.Run(ctx, "iptables", "-t", "nat", "-S")
	if err != nil {
		return PreflightReport{}, fmt.Errorf("%w: iptables nat -S: %v", ErrPreflightProbe, err)
	}
	mangleS, err := e.exec.Run(ctx, "iptables", "-t", "mangle", "-S")
	if err != nil {
		return PreflightReport{}, fmt.Errorf("%w: iptables mangle -S: %v", ErrPreflightProbe, err)
	}
	ip := e.ipBin()
	rules, err := e.exec.Run(ctx, ip, "-4", "rule", "show")
	if err != nil {
		return PreflightReport{}, fmt.Errorf("%w: ip rule show: %v", ErrPreflightProbe, err)
	}

	tableOut, tableErr := e.exec.Run(ctx, ip, "-4", "route", "show", "table", strconv.Itoa(RouteTable))
	if tableErr != nil && !isTableAbsent(tableOut, tableErr) {
		return PreflightReport{}, fmt.Errorf("%w: ip route show table %d: %v", ErrPreflightProbe, RouteTable, tableErr)
	}

	listenOut, listenErr := e.probeListenText(ctx)
	if listenErr != nil {
		return PreflightReport{}, fmt.Errorf("%w: listen probe: %v", ErrPreflightProbe, listenErr)
	}
	owners, ownerErr := e.probePortOwners(ctx, listenOut, CapturePort)
	if ownerErr != nil {
		return PreflightReport{}, fmt.Errorf("%w: port owner probe: %v", ErrPreflightProbe, ownerErr)
	}

	pidofOut, pidofErr := e.exec.Run(ctx, "pidof", "xkeen")

	e.mu.Lock()
	applied := e.applied
	expected := e.expected
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
	if portOccupiedForeign(listenOut, owners, CapturePort, expected) && !applied {
		report.Collisions = append(report.Collisions, Collision{
			Kind:   CollisionPort,
			Detail: "port 11820 owned by a foreign process",
		})
	}
	if btknChainsPresent(natS, mangleS) && !applied {
		report.Collisions = append(report.Collisions, Collision{
			Kind:   CollisionChain,
			Detail: "BTKN chains unexpectedly exist",
		})
	}

	xkeen := ClassifyXKeen(natS, mangleS, listenOut, pidofOut, rules, pidofErr == nil)
	report.XKeenState = xkeen
	if xkeen == XKeenLive {
		report.XKeenActive = true
	}
	if xkeen == XKeenResidual {
		report.XKeenActive = true
		report.Collisions = append(report.Collisions, Collision{
			Kind:   CollisionXKeen,
			Detail: "xkeen capture engine detected " + string(xkeen),
		})
	}

	if e.usePolicyRouting() {
		report.UDPCapture = UDPCaptureSupported
		report.IPRoute2 = e.ipBin()
	} else {
		report.UDPCapture = UDPCaptureUnsupported
		report.IPRoute2 = ClassIPRoute2FullRequired
	}
	report.Addrtype = e.useAddrtype()

	if len(report.Collisions) > 0 {
		report.OK = false
	}
	return report, nil
}

func (e *HybridIptablesEngine) probeListenText(ctx context.Context) (string, error) {
	ssOut, ssErr := e.exec.Run(ctx, "ss", "-lntup")
	if ssErr == nil {
		return ssOut, nil
	}
	var b strings.Builder
	var lastErr error
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		out, err := e.exec.Run(ctx, "cat", path)
		if err != nil {
			lastErr = err
			continue
		}
		b.WriteString(out)
		b.WriteByte('\n')
	}
	text := b.String()
	if strings.TrimSpace(text) == "" {
		if ssErr != nil {
			return "", ssErr
		}
		if lastErr != nil {
			return "", lastErr
		}
		return "", fmt.Errorf("%w: listen probes empty", ErrPreflightProbe)
	}
	return text, nil
}

func (e *HybridIptablesEngine) probePortOwners(ctx context.Context, listenOut string, port int) ([]string, error) {
	e.mu.Lock()
	expected := e.expected
	e.mu.Unlock()

	var owners []string
	seen := map[string]bool{}
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		owners = append(owners, path)
	}

	for _, pid := range parseListenPIDs(listenOut, port) {
		out, err := e.exec.Run(ctx, "readlink", "/proc/"+strconv.Itoa(pid)+"/exe")
		if err != nil {
			continue
		}
		add(out)
	}
	if expected.PID > 0 {
		out, err := e.exec.Run(ctx, "readlink", "/proc/"+strconv.Itoa(expected.PID)+"/exe")
		if err == nil {
			add(out)
		}
	}
	return owners, nil
}

func parseListenPIDs(s string, port int) []int {
	if !listenPortUsed(s, port) {
		return nil
	}
	p := strconv.Itoa(port)
	var pids []int
	seen := map[int]bool{}
	for _, line := range strings.Split(s, "\n") {
		if !strings.Contains(line, ":"+p) && !strings.Contains(line, "*:"+p) {
			continue
		}
		rest := line
		for {
			i := strings.Index(rest, "pid=")
			if i < 0 {
				break
			}
			rest = rest[i+4:]
			n := 0
			for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
				n++
			}
			if n == 0 {
				continue
			}
			pid, err := strconv.Atoi(rest[:n])
			if err != nil || pid <= 0 || seen[pid] {
				continue
			}
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	return pids
}

func markInUse(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "0x42544b4e") {
		return true
	}
	return strings.Contains(s, strconv.FormatUint(TProxyMark, 10))
}

func tableInUse(out string, err error) bool {
	if isTableAbsent(out, err) {
		return false
	}
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) != ""
}

func listenPortUsed(s string, port int) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	if looksLikeProcNet(s) {
		return procNetHexPortOpen(s, port)
	}
	p := strconv.Itoa(port)
	if strings.Contains(s, ":"+p) {
		return true
	}
	return strings.Contains(s, "--to-ports "+p) || strings.Contains(s, "--on-port "+p)
}

func looksLikeProcNet(s string) bool {
	return strings.Contains(s, "local_address") || strings.Contains(s, " rem_address")
}

func procNetHexPortOpen(s string, port int) bool {
	want := strings.ToUpper(fmt.Sprintf("%04X", port))
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "sl" {
			continue
		}
		local := fields[1]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		if strings.EqualFold(local[i+1:], want) {
			return true
		}
	}
	return false
}

func portOccupiedForeign(listenOut string, owners []string, port int, expected ExpectedListener) bool {
	if !listenPortUsed(listenOut, port) {
		return false
	}
	exe := expected.Executable
	if exe == "" {
		exe = OurXrayExecutable
	}
	if len(owners) == 0 {
		// /proc/net has no pid= field. If OUR Xray is the expected
		// listener and is alive, 11820 belongs to the capture engine.
		if expected.PID > 0 {
			return false
		}
		return true
	}
	for _, o := range owners {
		if o == exe {
			continue
		}
		return true
	}
	return false
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

// ClassifyXKeen reports LIVE, residual effective capture, or absent.
// Comment-only xkeen_rule strings without jumps/redirects are ABSENT.
func ClassifyXKeen(natS, mangleS, listenOut, pidofOut, ipRules string, pidofOK bool) XKeenPresence {
	if listenPortUsed(listenOut, 1181) || (pidofOK && strings.TrimSpace(pidofOut) != "") {
		return XKeenLive
	}
	if xkeenEffectiveCapture(natS, mangleS, ipRules) {
		return XKeenResidual
	}
	return XKeenAbsent
}

func xkeenEffectiveCapture(natS, mangleS, ipRules string) bool {
	blob := natS + "\n" + mangleS
	if strings.Contains(blob, "--to-ports 1181") || strings.Contains(blob, "--on-port 1181") {
		return true
	}
	for _, line := range strings.Split(blob, "\n") {
		fields := strings.Fields(line)
		if hasSeq(fields, "-A", "PREROUTING", "-j", "xkeen") {
			return true
		}
	}
	low := strings.ToLower(ipRules)
	if strings.Contains(low, "0x111") && strings.Contains(ipRules, " lookup 111") {
		return true
	}
	return false
}
