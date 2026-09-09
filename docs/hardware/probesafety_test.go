package hardware_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestControlDependsUserland(t *testing.T) {
	s := readRepoFile(t, "packaging", "control", "control")
	if !strings.Contains(s, "Depends: ip-full, iptables, ipset") {
		t.Fatal("IPK Depends must be ip-full, iptables, ipset")
	}
	if strings.Contains(s, "ca-bundle") {
		t.Fatal("ca-bundle must not be in Depends")
	}
	if strings.Contains(s, "xkeen") {
		t.Fatal("XKeen must not be an IPK dependency")
	}
}

func TestControlStanzaKeepsArchitecture(t *testing.T) {
	s := readRepoFile(t, "packaging", "control", "control")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.TrimRight(s, "\n")
	para := s
	if i := strings.Index(s, "\n\n"); i >= 0 {
		para = s[:i]
	}
	lines := strings.Split(para, "\n")
	var kept []string
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			t.Fatalf("whitespace-only line ends Entware opkg paragraph before Architecture:\n%s", s)
		}
		kept = append(kept, line)
	}
	joined := strings.Join(kept, "\n")
	if !strings.Contains(joined, "Architecture: mipsel-3.4_kn") {
		t.Fatal("Architecture must stay in the first control paragraph")
	}
}

func TestPackagingControlNoKernelModulesOrNode(t *testing.T) {
	s := readRepoFile(t, "packaging", "control", "control")
	if strings.Contains(s, ".ko") {
		t.Fatal("control must not ship kernel modules")
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "nodejs") || strings.Contains(low, "npm") {
		t.Fatal("control must not depend on Node runtime")
	}
	if !strings.Contains(s, "mipsel-3.4_kn") {
		t.Fatal("Architecture must be mipsel-3.4_kn")
	}
	if !strings.Contains(strings.ToLower(s), "softfloat") {
		t.Fatal("control must record MIPSLE softfloat")
	}
}

func TestBuildStagesNDMHook(t *testing.T) {
	s := readRepoFile(t, "build.ps1")
	if !strings.Contains(s, `ndm\netfilter.d`) && !strings.Contains(s, "ndm/netfilter.d") {
		t.Fatal("build.ps1 must stage NDM netfilter hook")
	}
	if !strings.Contains(s, "blacktemple-kn.sh") {
		t.Fatal("build.ps1 must copy blacktemple-kn.sh")
	}
}

func TestPrermCleansCaptureBeforeRemove(t *testing.T) {
	s := readRepoFile(t, "packaging", "control", "prerm")
	idx := strings.Index(s, "netfilter-reconcile stop")
	if idx < 0 {
		t.Fatal("prerm must run netfilter-reconcile stop while manager exists")
	}
	idxInit := strings.Index(s, "S99blacktemple-kn")
	if idxInit >= 0 && idx > idxInit {
		t.Fatal("BTKN cleanup must happen before init stop removes the process")
	}
}

func TestResearchLocalAndLogsGitignored(t *testing.T) {
	s := readRepoFile(t, ".gitignore")
	for _, want := range []string{".research-local/", "*.log"} {
		if !strings.Contains(s, want) {
			t.Fatalf("gitignore missing %q", want)
		}
	}
}

func TestProbeSingleInstanceAlreadyRunning(t *testing.T) {
	s := readProbeScript(t)
	if !strings.Contains(s, "BTKN_PROBE_LOCKDIR") {
		t.Fatal("probe must use a lock directory")
	}
	if !strings.Contains(s, "ALREADY_RUNNING") {
		t.Fatal("second probe must print ALREADY_RUNNING")
	}
	dir := t.TempDir()
	lock := filepath.Join(dir, "btkn-router-probe.lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lock, 0o700); err == nil {
		t.Fatal("second mkdir of the same lock dir must fail")
	}
}

func TestProbeLockMkdirSerializes(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "btkn-router-probe.lock")
	var win int32
	var already int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := os.Mkdir(lock, 0o700); err != nil {
				atomic.AddInt32(&already, 1)
				return
			}
			atomic.AddInt32(&win, 1)
		}()
	}
	wg.Wait()
	if win != 1 {
		t.Fatalf("want 1 winner, got %d", win)
	}
	if already != 7 {
		t.Fatalf("want 7 ALREADY_RUNNING equivalents, got %d", already)
	}
}

func TestProbeStaleLockRecovers(t *testing.T) {
	s := readProbeScript(t)
	if !strings.Contains(s, "FOREIGN_OR_UNKNOWN_PROCESS") {
		t.Fatal("unproven PID must be FOREIGN_OR_UNKNOWN_PROCESS")
	}
	procs := map[int]fakeProc{
		99:  {PID: 99, PPID: 1, Cmd: "/opt/sbin/xray run", Env: nil},
		200: {PID: 200, PPID: 1, Cmd: "/bin/sh", Env: map[string]string{"BTKN_PROBE_RUN_ID": "other"}},
	}
	if killSetContains(ownedTree(10, "run-a", procs), 99) {
		t.Fatal("must not kill xray because a lock PID was reused")
	}
	if killSetContains(ownedTree(200, "run-a", procs), 200) {
		t.Fatal("foreign sh without matching run id must not be owned")
	}
}

func TestProbeHardTimeoutKillsOwnedTree(t *testing.T) {
	s := readProbeScript(t)
	for _, want := range []string{
		"TIMEOUT",
		"kill -TERM",
		"kill -KILL",
		"BTKN_PROBE_MAX_SEC",
		"trap",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("probe missing %q", want)
		}
	}
	procs := map[int]fakeProc{
		50: {PID: 50, PPID: 1, Cmd: "sh /tmp/btkn-router-probe.sh", Env: map[string]string{"BTKN_PROBE_RUN_ID": "r1"}},
		51: {PID: 51, PPID: 50, Cmd: "awk", Env: map[string]string{"BTKN_PROBE_RUN_ID": "r1"}},
		52: {PID: 52, PPID: 51, Cmd: "awk", Env: map[string]string{"BTKN_PROBE_RUN_ID": "r1"}},
		90: {PID: 90, PPID: 1, Cmd: "/opt/sbin/xray", Env: nil},
	}
	got := ownedTree(50, "r1", procs)
	if !killSetContains(got, 50) || !killSetContains(got, 51) || !killSetContains(got, 52) {
		t.Fatalf("owned tree %v missing descendants", got)
	}
	if killSetContains(got, 90) {
		t.Fatal("xray must not be in owned tree")
	}
}

func TestProbeFailureLeavesNoStorm(t *testing.T) {
	s := readProbeScript(t)
	for _, want := range []string{
		"ALREADY_RUNNING",
		"TIMEOUT",
		"kill -TERM",
		"kill -KILL",
		"BTKN_PROBE_MAX_SEC",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("self-protection missing %q", want)
		}
	}
	if strings.Contains(s, "killall") || strings.Contains(s, "pkill") {
		t.Fatal("storm cleanup must not use killall/pkill")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-n", "20", "127.0.0.1")
	cmd.Env = append(os.Environ(), "BTKN_PROBE_RUN_ID=storm-test")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	time.Sleep(200 * time.Millisecond)
	_ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid)).Run()
	_ = cmd.Wait()
	c, err := net.DialTimeout("tcp", "127.0.0.1:9", 50*time.Millisecond)
	if err == nil {
		_ = c.Close()
	}
	if cmd.ProcessState == nil {
		t.Fatal("isolated child must have exited after tree kill")
	}
}

func TestRedactPolicyFixtures(t *testing.T) {
	s := readProbeScript(t)
	if strings.Contains(s, `\[?[0-9A-Fa-f:]+\]?`) {
		t.Fatal("IPv6 matcher must not use unbounded optional-bracket hex-colon class")
	}
	if strings.Contains(s, "| redact_ip") || strings.Contains(s, "| redact_ip6") {
		t.Fatal("must not pipe sed into two extra awk redactors")
	}
	cases := []struct {
		in, want string
	}{
		{"src 8.8.8.8 dst", "src [REDACTED-IP] dst"},
		{"src 192.168.1.1 dst", "src 192.168.1.1 dst"},
		{"2001:db8::1", "[REDACTED-IP6]"},
		{"fe80::", "fe80::"},
		{"time 12:34:56 ok", "time 12:34:56 ok"},
		{"sha256 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "sha256 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
		{"-A xkeen -j TPROXY", "-A xkeen -j TPROXY"},
		{"aa:bb:cc:dd:ee:ff", "[REDACTED-MAC]"},
	}
	for _, tc := range cases {
		got := redactLine(tc.in)
		if got != tc.want {
			t.Fatalf("redact %q: got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestNoNameOnlyOrphanReap(t *testing.T) {
	s := readProbeScript(t)
	if strings.Contains(s, "btkn_reap_other_probe_scripts") {
		t.Fatal("name-only btkn_reap_other_probe_scripts is forbidden")
	}
	if strings.Contains(s, "btkn_kill_script_tree") {
		t.Fatal("name-only btkn_kill_script_tree is forbidden")
	}
	idx := strings.Index(s, "btkn_cmd_cleanup_orphans")
	if idx < 0 {
		t.Fatal("missing btkn_cmd_cleanup_orphans")
	}
	end := idx + 800
	if end > len(s) {
		end = len(s)
	}
	body := s[idx:end]
	if strings.Contains(body, "btkn_is_probe_script") {
		t.Fatal("--cleanup-orphans must not TERM/KILL by cmdline name")
	}
	if !strings.Contains(s, "FOREIGN_OR_UNKNOWN_PROCESS") {
		t.Fatal("unproven ownership must print FOREIGN_OR_UNKNOWN_PROCESS")
	}
}

func TestProbeExecutableProcessSafety(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("executable probe process-safety requires Linux /proc")
	}
	probe := locateProbeScript(t)
	script := locateRepoFile(t, "docs", "hardware", "probe_safety_exec.sh")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", script, probe)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("executable process-safety: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "RESULT: PASS") {
		t.Fatalf("missing RESULT: PASS\n%s", out)
	}
}

func TestProbeNeverKillallOrForeign(t *testing.T) {
	s := readProbeScript(t)
	if strings.Contains(s, "killall") || strings.Contains(s, "pkill") {
		t.Fatal("probe must not use killall/pkill")
	}
	procs := map[int]fakeProc{
		7: {PID: 7, PPID: 1, Cmd: "awk", Env: nil},
		8: {PID: 8, PPID: 1, Cmd: "/opt/sbin/xkeen", Env: nil},
		9: {PID: 9, PPID: 1, Cmd: "sh", Env: nil},
	}
	got := ownedTree(50, "r1", procs)
	if len(got) != 0 {
		t.Fatalf("foreign processes must not be owned: %v", got)
	}
}

type fakeProc struct {
	PID, PPID int
	Cmd       string
	Env       map[string]string
}

func ownedTree(root int, runID string, procs map[int]fakeProc) []int {
	r, ok := procs[root]
	if !ok {
		return nil
	}
	if !strings.Contains(r.Cmd, "btkn-router-probe.sh") {
		return nil
	}
	if r.Env["BTKN_PROBE_RUN_ID"] != runID {
		return nil
	}
	owned := map[int]bool{root: true}
	changed := true
	for changed {
		changed = false
		for pid, p := range procs {
			if owned[pid] {
				continue
			}
			low := strings.ToLower(p.Cmd)
			if strings.Contains(low, "xray") || strings.Contains(low, "xkeen") {
				continue
			}
			if owned[p.PPID] {
				owned[pid] = true
				changed = true
			}
		}
	}
	var out []int
	for pid := range owned {
		out = append(out, pid)
	}
	return out
}

func killSetContains(set []int, pid int) bool {
	for _, p := range set {
		if p == pid {
			return true
		}
	}
	return false
}

var (
	macRe  = regexp.MustCompile(`(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){5}`)
	uuidRe = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	urlRe  = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^ \t"']+`)
	ipv4Re = regexp.MustCompile(`\b[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\b`)
)

func redactLine(s string) string {
	s = macRe.ReplaceAllString(s, "[REDACTED-MAC]")
	s = uuidRe.ReplaceAllString(s, "[REDACTED-UUID]")
	s = urlRe.ReplaceAllString(s, "[REDACTED-URL]")
	s = ipv4Re.ReplaceAllStringFunc(s, func(ip string) string {
		if ipv4Private(ip) {
			return ip
		}
		return "[REDACTED-IP]"
	})
	if strings.Contains(s, "::") || strings.Count(s, ":") >= 3 {
		s = redactIPv6Tokens(s)
	}
	return s
}

func ipv4Private(ip string) bool {
	var a, b int
	n, err := fmtSscanf(ip, &a, &b)
	if err != nil || n < 2 {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			return false
		}
		a = atoi(parts[0])
		b = atoi(parts[1])
	}
	if a == 10 || a == 127 || a == 0 || a == 255 {
		return true
	}
	if a == 192 && b == 168 {
		return true
	}
	if a == 172 && b >= 16 && b <= 31 {
		return true
	}
	if a == 169 && b == 254 {
		return true
	}
	return false
}

func fmtSscanf(ip string, a, b *int) (int, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0, errBadIP
	}
	*a = atoi(parts[0])
	*b = atoi(parts[1])
	return 2, nil
}

var errBadIP = errString("bad ip")

type errString string

func (e errString) Error() string { return string(e) }

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func redactIPv6Tokens(s string) string {
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, ":")
		if i < 0 {
			b.WriteString(rest)
			break
		}
		start := i
		for start > 0 {
			c := rest[start-1]
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' {
				start--
				continue
			}
			break
		}
		end := i + 1
		for end < len(rest) {
			c := rest[end]
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' {
				end++
				continue
			}
			break
		}
		tok := rest[start:end]
		b.WriteString(rest[:start])
		if keepIPv6(tok) {
			b.WriteString(tok)
		} else {
			b.WriteString("[REDACTED-IP6]")
		}
		rest = rest[end:]
	}
	return b.String()
}

func keepIPv6(tok string) bool {
	n := strings.ToLower(strings.Trim(tok, "[]"))
	if strings.Count(tok, ":") < 2 {
		return true
	}
	if strings.Count(tok, ":") == 2 && !strings.Contains(tok, "::") {
		return true
	}
	if n == "::" || n == "::1" || n == "fe80::" || n == "fc00::" || n == "fd00::" || n == "ff00::" {
		return true
	}
	return false
}
