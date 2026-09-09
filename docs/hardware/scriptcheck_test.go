package hardware_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	var starts []string
	if _, file, _, ok := runtime.Caller(0); ok {
		starts = append(starts, filepath.Dir(file))
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	seen := map[string]bool{}
	for _, start := range starts {
		dir := start
		for i := 0; i < 8; i++ {
			if seen[dir] {
				break
			}
			seen[dir] = true
			if _, err := os.Stat(filepath.Join(dir, "scripts", "router-probe.sh")); err == nil {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	t.Fatal("repo root with scripts/router-probe.sh not found")
	return ""
}

func locateRepoFile(t *testing.T, rel ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{repoRoot(t)}, rel...)...)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("missing %s: %v", filepath.Join(rel...), err)
	}
	return p
}

func readRepoFile(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(locateRepoFile(t, rel...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(rel...), err)
	}
	return string(b)
}

func locateProbeScript(t *testing.T) string {
	t.Helper()
	return locateRepoFile(t, "scripts", "router-probe.sh")
}

func readProbeScript(t *testing.T) string {
	t.Helper()
	return readRepoFile(t, "scripts", "router-probe.sh")
}

func TestProbeScriptShebang(t *testing.T) {
	s := readProbeScript(t)
	if !strings.HasPrefix(s, "#!/bin/sh") {
		t.Fatalf("expected script to start with #!/bin/sh, got %q", firstLine(s))
	}
	if strings.Contains(s, "\r") {
		t.Fatal("probe script must be LF-only (no CR)")
	}
}

func TestProbeScriptReadOnly(t *testing.T) {
	s := readProbeScript(t)
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`iptables[^\n]*[[:space:]]-[ADI]([[:space:]]|$)`),
		regexp.MustCompile(`iptables[^\n]*[[:space:]]-F([[:space:]]|$)`),
		regexp.MustCompile(`ip6tables[^\n]*[[:space:]]-[ADI]([[:space:]]|$)`),
		regexp.MustCompile(`ip6tables[^\n]*[[:space:]]-F([[:space:]]|$)`),
		regexp.MustCompile(`ip[[:space:]]+rule[[:space:]]+(add|del)\b`),
		regexp.MustCompile(`ip[[:space:]]+route[[:space:]]+(add|del)\b`),
		regexp.MustCompile(`sysctl[[:space:]]+-w\b`),
		regexp.MustCompile(`echo[[:space:]].*>[[:space:]]*/proc/sys`),
		regexp.MustCompile(`echo[[:space:]].*>[[:space:]]*/sys/fs/cgroup`),
		regexp.MustCompile(`(?m)(^|[[:space:];|&])kill[[:space:]]`),
		regexp.MustCompile(`(?m)(^|[[:space:];|&])killall[[:space:]]`),
		regexp.MustCompile(`\bswapon\b`),
		regexp.MustCompile(`\bswapoff\b`),
		regexp.MustCompile(`opkg[[:space:]]+(install|remove|upgrade|update)\b`),
		regexp.MustCompile(`service[[:space:]]+restart\b`),
		regexp.MustCompile(`/etc/init\.d/\S+[[:space:]]+restart\b`),
		regexp.MustCompile(`xkeen[[:space:]]+-(dns|pbr|pr|ipv6)\b`),
		regexp.MustCompile(`ndmc[^\n]*\b(set|no)[[:space:]]`),
	}
	for _, re := range forbidden {
		if loc := re.FindStringIndex(s); loc != nil {
			t.Errorf("forbidden mutating pattern %s at offset %d: %q", re.String(), loc[0], snippet(s, loc[0]))
		}
	}
	if strings.Contains(s, "sshpass") {
		t.Error("probe must not use sshpass")
	}
}

func TestProbeScriptRedactHelper(t *testing.T) {
	s := readProbeScript(t)
	if !strings.Contains(s, "redact()") {
		t.Fatal("expected redact() helper in probe script")
	}
}

func TestProbeScriptSections(t *testing.T) {
	s := readProbeScript(t)
	sections := []string{
		"SYSTEM", "CPU", "MEMORY", "SWAP", "ZRAM", "CGROUP", "FILESYSTEM", "ENTWARE", "TOOLS",
		"NETWORK", "ROUTING", "FIREWALL", "IPTABLES", "IP6TABLES", "TARGETS", "IPSET",
		"TUN", "KERNEL", "MODULES", "PACKAGE-PROVENANCE", "MODULE-PROVENANCE", "DNS", "XRAY", "XKEEN", "INIT", "LIMITS", "SOCKETS",
		"BASELINE", "SUMMARY",
	}
	if !strings.Contains(s, `echo "===== $1 ====="`) {
		t.Fatal(`section() must print ===== $1 =====`)
	}
	for _, name := range sections {
		want := `section "` + name + `"`
		if !strings.Contains(s, want) {
			t.Errorf("missing section call %q", want)
		}
	}
}

func TestProbeCollectsIPv6Tables(t *testing.T) {
	s := readProbeScript(t)
	for _, want := range []string{
		`ip6tables -t nat -S`,
		`ip6tables -t mangle -S`,
		`ip6tables -t filter -S`,
		`/proc/net/ip6_tables_targets`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("probe must collect %q", want)
		}
	}
	if !strings.Contains(s, "xkeen_ipv6_names_targets") && !strings.Contains(s, "IPv6 XKeen rules") {
		t.Fatal("probe must collect IPv6 XKeen rules (names/targets)")
	}
}

func TestProbeDoesNotMarkTPROXYSupported(t *testing.T) {
	s := readProbeScript(t)
	if !strings.Contains(s, `${_t}: PRESENT`) {
		t.Fatal("target evidence must use PRESENT")
	}
	if !strings.Contains(s, `${_t}: NOT OBSERVED`) {
		t.Fatal("target evidence must use NOT OBSERVED")
	}
	if strings.Contains(s, "TPROXY: SUPPORTED") || strings.Contains(s, "${_t}: SUPPORTED") {
		t.Fatal("must not label TPROXY as SUPPORTED")
	}
}

func TestProbeXkeenSafeFlagsOnly(t *testing.T) {
	s := readProbeScript(t)
	if !strings.Contains(s, `xkeen -v`) || !strings.Contains(s, `xkeen -h`) {
		t.Fatal("expected read-only xkeen -v and xkeen -h")
	}
}

func TestSmokeHarnessRequiresMutationGates(t *testing.T) {
	ps1 := readRepoFile(t, "router-smoke.ps1")
	sh := readRepoFile(t, "scripts", "router-smoke-routing.sh")
	combined := ps1 + "\n" + sh
	if !strings.Contains(combined, "BTKN_ALLOW_ROUTING_MUTATION") {
		t.Fatal("harness must name BTKN_ALLOW_ROUTING_MUTATION")
	}
	if !strings.Contains(combined, "BTKN_ALLOW_XKEEN_STOP") {
		t.Fatal("harness must name BTKN_ALLOW_XKEEN_STOP")
	}
	if !strings.Contains(combined, "LIVE ROUTING SMOKE: NOT RUN") {
		t.Fatal("harness must have LIVE ROUTING SMOKE: NOT RUN path")
	}
	if !strings.Contains(ps1, `$allowMut -ne '1'`) && !strings.Contains(ps1, "BTKN_ALLOW_ROUTING_MUTATION") {
		t.Fatal("PowerShell gate must check mutation env")
	}
	if !strings.Contains(sh, `BTKN_ALLOW_ROUTING_MUTATION`) || !strings.Contains(sh, `BTKN_ALLOW_XKEEN_STOP`) {
		t.Fatal("remote smoke script must re-check both gates")
	}
}

func TestSmokeHarnessXkeenRestoreInFinally(t *testing.T) {
	ps1 := readRepoFile(t, "router-smoke.ps1")
	if !regexp.MustCompile(`(?i)\bfinally\b`).MatchString(ps1) {
		t.Fatal("PowerShell harness must restore XKeen in finally")
	}
	if !strings.Contains(ps1, "restore-xkeen") {
		t.Fatal("finally must invoke restore-xkeen")
	}
	if !strings.Contains(ps1, "cleanup-btkn") {
		t.Fatal("finally must invoke cleanup-btkn")
	}
	if !strings.Contains(ps1, "stop-blacktemple") {
		t.Fatal("finally must stop test BlackTemple")
	}
	sh := readRepoFile(t, "scripts", "router-smoke-routing.sh")
	if !strings.Contains(sh, "cmd_restore_xkeen") && !strings.Contains(sh, "RESTORE XKEEN") {
		t.Fatal("remote script must implement XKeen restore")
	}
}

func TestCredentialsNeverArgvOrLog(t *testing.T) {
	files := [][]string{
		{"router-smoke.ps1"},
		{"scripts", "router-probe.sh"},
		{"scripts", "router-smoke-routing.sh"},
	}
	for _, rel := range files {
		s := readRepoFile(t, rel...)
		name := filepath.Join(rel...)
		if strings.Contains(s, "sshpass") {
			t.Errorf("%s must not use sshpass", name)
		}
		if regexp.MustCompile(`(?i)(ssh\.exe|sshArgs|@sshRun)[^\n]*BTKN_SSH_PASSWORD`).MatchString(s) {
			t.Errorf("%s must not place BTKN_SSH_PASSWORD on ssh argv", name)
		}
		if regexp.MustCompile(`(?i)Write-Host[^\n]*BTKN_SSH_PASSWORD`).MatchString(s) {
			t.Errorf("%s must not print BTKN_SSH_PASSWORD", name)
		}
	}
	ps1 := readRepoFile(t, "router-smoke.ps1")
	if !strings.Contains(ps1, "SSH_ASKPASS") {
		t.Fatal("password auth must use SSH_ASKPASS")
	}
}

func TestBtknOnlyCleanup(t *testing.T) {
	sh := readRepoFile(t, "scripts", "router-smoke-routing.sh")
	if !strings.Contains(sh, "CLEANUP BTKN ONLY") && !strings.Contains(sh, "cleanup_btkn") && !strings.Contains(sh, "cmd_cleanup_btkn") {
		t.Fatal("smoke script must clean BTKN_ only")
	}
	if !strings.Contains(sh, "BTKN_") {
		t.Fatal("smoke script must use BTKN_ chain prefix")
	}
	reFlush := regexp.MustCompile(`(?m)iptables[^\n]*-F[[:space:]]*(\S*)`)
	for _, m := range reFlush.FindAllStringSubmatch(sh, -1) {
		chain := strings.TrimSpace(m[1])
		if chain == "" || strings.HasPrefix(chain, "$") {
			if chain == "" {
				t.Errorf("iptables -F without chain (global flush): %q", m[0])
			}
			continue
		}
		if strings.Contains(chain, `"`) {
			chain = strings.Trim(chain, `"'`)
		}
		if !strings.Contains(chain, "BTKN_") && chain != `"$_ch"` && chain != "$_ch" {
			t.Errorf("iptables -F must target BTKN_ chain, got %q", m[0])
		}
	}
}

func TestNoIptablesGlobalFlush(t *testing.T) {
	files := [][]string{
		{"router-smoke.ps1"},
		{"scripts", "router-probe.sh"},
		{"scripts", "router-smoke-routing.sh"},
	}
	bad := regexp.MustCompile(`(?m)ip6?tables(?:[[:space:]]+-t[[:space:]]+\S+)?[[:space:]]+-F[[:space:]]*$`)
	for _, rel := range files {
		s := readRepoFile(t, rel...)
		if loc := bad.FindStringIndex(s); loc != nil {
			t.Errorf("%s has iptables global flush at %q", filepath.Join(rel...), snippet(s, loc[0]))
		}
		if strings.Contains(s, "iptables -F\n") || strings.Contains(s, "iptables -t nat -F\n") {
			t.Errorf("%s contains table-wide iptables flush", filepath.Join(rel...))
		}
	}
}

func TestSmokeDoesNotChangeIPv6(t *testing.T) {
	sh := readRepoFile(t, "scripts", "router-smoke-routing.sh")
	mut := regexp.MustCompile(`ip6tables[^\n]*[[:space:]]-[ADIFX]([[:space:]]|$)`)
	if loc := mut.FindStringIndex(sh); loc != nil {
		t.Errorf("smoke must not mutate ip6tables: %q", snippet(sh, loc[0]))
	}
	if strings.Contains(sh, "xkeen -ipv6") {
		t.Error("smoke must not run xkeen -ipv6")
	}
}

func TestSmokeRoutingScriptGatedAndLF(t *testing.T) {
	s := readRepoFile(t, "scripts", "router-smoke-routing.sh")
	if !strings.HasPrefix(s, "#!/bin/sh") {
		t.Fatalf("expected #!/bin/sh, got %q", firstLine(s))
	}
	if strings.Contains(s, "\r") {
		t.Fatal("router-smoke-routing.sh must be LF-only (no CR)")
	}
}

func TestHardwareDocsNeverClaimTPROXYSupported(t *testing.T) {
	files := [][]string{
		{"docs", "hardware", "KN-1011.md"},
		{"docs", "hardware", "kn-1011-capabilities.md"},
		{"router-smoke.ps1"},
		{"scripts", "router-probe.sh"},
		{"scripts", "router-smoke-routing.sh"},
	}
	claim := regexp.MustCompile(`(?i)TPROXY[[:space:]]*[:=][[:space:]]*SUPPORTED`)
	for _, rel := range files {
		s := readRepoFile(t, rel...)
		if claim.MatchString(s) {
			t.Errorf("%s must not write TPROXY as SUPPORTED", filepath.Join(rel...))
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

func snippet(s string, at int) string {
	start := at - 20
	if start < 0 {
		start = 0
	}
	end := at + 40
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
