package hardware_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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
		regexp.MustCompile(`(?m)(^|[[:space:];|&])killall[[:space:]]`),
		regexp.MustCompile(`(?m)(^|[[:space:];|&])pkill[[:space:]]`),
		regexp.MustCompile(`\bswapon\b`),
		regexp.MustCompile(`\bswapoff\b`),
		regexp.MustCompile(`opkg[[:space:]]+(install|remove|upgrade|update)\b`),
		regexp.MustCompile(`(?m)(^|[[:space:];|&])insmod[[:space:]]`),
		regexp.MustCompile(`(?m)(^|[[:space:];|&])rmmod[[:space:]]`),
		regexp.MustCompile(`(?m)(^|[[:space:];|&])modprobe[[:space:]]+[A-Za-z]`),
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
	app := readRepoFile(t, "scripts", "router-smoke-app.sh")
	combined := ps1 + "\n" + sh + "\n" + app
	if !strings.Contains(combined, "BTKN_ALLOW_ROUTING_MUTATION") {
		t.Fatal("harness must name BTKN_ALLOW_ROUTING_MUTATION")
	}
	if !strings.Contains(combined, "BTKN_ALLOW_XKEEN_STOP") {
		t.Fatal("harness must name BTKN_ALLOW_XKEEN_STOP")
	}
	if !strings.Contains(combined, "LIVE ROUTING SMOKE: NOT RUN") {
		t.Fatal("harness must have LIVE ROUTING SMOKE: NOT RUN path")
	}
	if !strings.Contains(ps1, `$allowMut -ne '1'`) {
		t.Fatal("PowerShell gate must check $allowMut -ne '1'")
	}
	if !strings.Contains(sh, `BTKN_ALLOW_ROUTING_MUTATION`) || !strings.Contains(sh, `BTKN_ALLOW_XKEEN_STOP`) {
		t.Fatal("remote smoke script must re-check both gates")
	}
	if !strings.Contains(app, `BTKN_ALLOW_ROUTING_MUTATION`) || !strings.Contains(app, `BTKN_ALLOW_XKEEN_STOP`) {
		t.Fatal("app smoke script must re-check both gates")
	}
}

func TestSmokeRequiresProductionRouterMutationAck(t *testing.T) {
	ps1 := readRepoFile(t, "router-smoke.ps1")
	sh := readRepoFile(t, "scripts", "router-smoke-routing.sh")
	app := readRepoFile(t, "scripts", "router-smoke-app.sh")
	for _, s := range []string{ps1, sh, app} {
		if !strings.Contains(s, "BTKN_PRODUCTION_ROUTER_MUTATION_ACK") {
			t.Fatal("mutation smoke must require BTKN_PRODUCTION_ROUTER_MUTATION_ACK")
		}
		if !strings.Contains(s, "I_ACCEPT_NETWORK_LOSS") {
			t.Fatal("ACK value must be I_ACCEPT_NETWORK_LOSS")
		}
	}
	if strings.Contains(ps1, `$cmd = "BTKN_ALLOW_ROUTING_MUTATION=1`) {
		t.Fatal("PowerShell must not hardcode mutation=1 onto the remote command")
	}
	if strings.Contains(ps1, "BTKN_ALLOW_ROUTING_MUTATION=1 BTKN_ALLOW_XKEEN_STOP=1 BTKN_RESCUE_SCRIPT") {
		t.Fatal("PowerShell must not inject mutation gates")
	}
	if !strings.Contains(ps1, `$ack -ne 'I_ACCEPT_NETWORK_LOSS'`) {
		t.Fatal("PowerShell must refuse Smoke without the production-router ACK")
	}
}

func TestXKeenRestoreFailureFailsGate(t *testing.T) {
	ps1 := readRepoFile(t, "router-smoke.ps1")
	sh := readRepoFile(t, "scripts", "router-smoke-app.sh")
	if !strings.Contains(sh, "RESTORE_XKEEN: FAIL") {
		t.Fatal("app smoke must print RESTORE_XKEEN: FAIL")
	}
	if !strings.Contains(ps1, "RESTORE_XKEEN") {
		t.Fatal("PowerShell must surface RESTORE_XKEEN failure")
	}
}

func TestAppSmokeScriptNoFirewallMutation(t *testing.T) {
	s := readRepoFile(t, "scripts", "router-smoke-app.sh")
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`iptables[^\n]*[[:space:]]-[ADI]([[:space:]]|$)`),
		regexp.MustCompile(`ip[[:space:]]+rule[[:space:]]+(add|del)\b`),
		regexp.MustCompile(`ip[[:space:]]+route[[:space:]]+(add|del)\b`),
	}
	for _, re := range forbidden {
		if loc := re.FindStringIndex(s); loc != nil {
			t.Errorf("app smoke must not mutate firewall directly: %s", re.String())
		}
	}
	if !strings.Contains(s, "netfilter-reconcile") {
		t.Fatal("app smoke must call blacktempled netfilter-reconcile")
	}
	if strings.Contains(s, "REDIRECT --to-ports 1181") {
		t.Fatal("app smoke must not install XKeen port 1181")
	}
}

func TestAppSmokeDetectsXKeenHybridAsActive(t *testing.T) {
	s := readRepoFile(t, "scripts", "router-smoke-app.sh")
	if !strings.Contains(s, "FAIL: expected XKeen ACTIVE before mutation") {
		t.Fatal("snapshot must still refuse to mutate when XKeen is truly absent")
	}
	low := strings.ToLower(s)
	if !strings.Contains(low, "hybrid") {
		t.Fatal("snapshot must treat Hybrid status as XKeen active")
	}
	if !strings.Contains(s, "foreign_xray_pid") {
		t.Fatal("snapshot must record foreign Xray pid")
	}
	if !strings.Contains(s, "listen_1181_tcp") {
		t.Fatal("snapshot must record 1181")
	}
	if strings.Contains(s, `grep -qi -e run -e start && _running=1`) && !strings.Contains(low, "hybrid") {
		t.Fatal("must not require English run|start as the only liveness signal")
	}
	if !strings.Contains(s, "listen_1181_tcp=PRESENT") {
		t.Fatal("1181 PRESENT must count as XKeen capture still active")
	}
}

func TestAppSmokeManagerRestartPath(t *testing.T) {
	s := readRepoFile(t, "scripts", "router-smoke-app.sh")
	if !strings.Contains(s, "cmd_restart_manager") {
		t.Fatal("app smoke must implement manager restart")
	}
	if !strings.Contains(s, "netfilter-reconcile") {
		t.Fatal("restart path must go through netfilter-reconcile")
	}
	if !strings.Contains(s, "duplicate") && !strings.Contains(s, "nat_prerouting_btkn_jumps") {
		t.Fatal("restart path must check for duplicate jumps")
	}
}

func TestAppSmokeFailOpenPath(t *testing.T) {
	s := readRepoFile(t, "scripts", "router-smoke-app.sh")
	if !strings.Contains(s, "cmd_fail_open") {
		t.Fatal("app smoke must implement fail-open")
	}
	idxStop := strings.Index(s, `xray-stop`)
	idxFail := strings.Index(s, "cmd_fail_open")
	if idxStop < 0 || idxFail < 0 {
		t.Fatal("fail-open must stop OUR Xray through manager CLI")
	}
	if !strings.Contains(s, "FAIL_OPEN") {
		t.Fatal("fail-open must report FAIL_OPEN")
	}
}

func TestAppSmokeDoesNotMutateDNS(t *testing.T) {
	s := readRepoFile(t, "scripts", "router-smoke-app.sh")
	if strings.Contains(s, "xkeen -dns") || strings.Contains(s, "ndnproxy -") {
		t.Fatal("app smoke must not mutate Keenetic DNS")
	}
	if !strings.Contains(s, "DNS=KEENETIC_DIRECT") {
		t.Fatal("app smoke must report DNS=KEENETIC_DIRECT")
	}
	if !strings.Contains(s, "DNS_LEAK_FREE=NOT CLAIMED") {
		t.Fatal("app smoke must not claim DNS leak-free")
	}
}

func TestAppSmokeRestorePolls1181(t *testing.T) {
	s := readRepoFile(t, "scripts", "router-smoke-app.sh")
	idx := strings.Index(s, "cmd_restore_xkeen()")
	if idx < 0 {
		t.Fatal("cmd_restore_xkeen missing")
	}
	body := s[idx:]
	if end := strings.Index(body, "\ncmd_"); end > 0 {
		body = body[:end]
	}
	if strings.Contains(body, "sleep 2") && !strings.Contains(body, "while") {
		t.Fatal("restore must poll 1181, not a single sleep 2")
	}
	if !strings.Contains(body, "while") || !strings.Contains(body, "1181") {
		t.Fatal("restore must bounded-poll TCP/UDP 1181")
	}
}

func TestAppSmokeRequiresArmedRescue(t *testing.T) {
	s := readRepoFile(t, "scripts", "router-smoke-app.sh")
	if !strings.Contains(s, "require_rescue") {
		t.Fatal("app smoke must require_rescue before mutating XKeen/BTKN")
	}
	if !strings.Contains(s, "cmd_stop_xkeen") || !strings.Contains(s, "cmd_apply") {
		t.Fatal("stop-xkeen/apply must exist")
	}
	stopIdx := strings.Index(s, "cmd_stop_xkeen()")
	applyIdx := strings.Index(s, "cmd_apply()")
	if stopIdx < 0 || applyIdx < 0 {
		t.Fatal("missing stop/apply")
	}
	if !strings.Contains(s[stopIdx:stopIdx+400], "require_rescue") {
		t.Fatal("stop-xkeen must call require_rescue")
	}
	if !strings.Contains(s[applyIdx:applyIdx+400], "require_rescue") {
		t.Fatal("apply must call require_rescue")
	}
	ps1 := readRepoFile(t, "router-smoke.ps1")
	if !strings.Contains(ps1, "btkn-rescue.sh") {
		t.Fatal("PowerShell must copy/arm btkn-rescue.sh")
	}
}

func TestAppSmokeRefusesControllerClient(t *testing.T) {
	s := readRepoFile(t, "scripts", "router-smoke-app.sh")
	resolve := s
	idx := strings.Index(s, "cmd_resolve_client()")
	if idx >= 0 {
		resolve = s[idx:]
		if end := strings.Index(resolve[1:], "\ncmd_"); end > 0 {
			resolve = resolve[:end+1]
		}
	}
	if strings.Contains(resolve, `_src="SSH_CONNECTION"`) {
		t.Fatal("SSH_CONNECTION must not be a capture-client fallback")
	}
	if !strings.Contains(s, "BTKN_ALLOW_CONTROLLER_CLIENT") {
		t.Fatal("controller client must require BTKN_ALLOW_CONTROLLER_CLIENT=1")
	}
	if !strings.Contains(s, "CLIENT_REQUIRED") {
		t.Fatal("missing CLIENT_REQUIRED")
	}
}

func TestDaemonSourcesNeverStopXKeen(t *testing.T) {
	files := [][]string{
		{"src", "cmd", "blacktempled", "main.go"},
		{"src", "internal", "platform", "nfcmd.go"},
		{"src", "internal", "platform", "reconcile.go"},
		{"src", "internal", "platform", "capturecfg.go"},
		{"packaging", "keenetic", "netfilter.d", "blacktemple-kn.sh"},
		{"packaging", "init", "S99blacktemple-kn"},
	}
	for _, rel := range files {
		s := readRepoFile(t, rel...)
		if strings.Contains(s, "S05xkeen") || strings.Contains(s, "xkeen stop") {
			t.Errorf("%s must not stop XKeen", filepath.Join(rel...))
		}
		if strings.Contains(s, "killall") || strings.Contains(s, "pkill") {
			t.Errorf("%s must not killall/pkill", filepath.Join(rel...))
		}
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
		{"scripts", "router-smoke-app.sh"},
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
		{"scripts", "router-smoke-app.sh"},
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
	for _, name := range []string{"router-smoke-routing.sh", "router-smoke-app.sh"} {
		sh := readRepoFile(t, "scripts", name)
		mut := regexp.MustCompile(`ip6tables[^\n]*[[:space:]]-[ADIFX]([[:space:]]|$)`)
		if loc := mut.FindStringIndex(sh); loc != nil {
			t.Errorf("%s must not mutate ip6tables: %q", name, snippet(sh, loc[0]))
		}
		if strings.Contains(sh, "xkeen -ipv6") {
			t.Errorf("%s must not run xkeen -ipv6", name)
		}
	}
}

func TestSmokeRoutingScriptGatedAndLF(t *testing.T) {
	for _, name := range []string{"router-smoke-routing.sh", "router-smoke-app.sh"} {
		s := readRepoFile(t, "scripts", name)
		if !strings.HasPrefix(s, "#!/bin/sh") {
			t.Fatalf("%s expected #!/bin/sh, got %q", name, firstLine(s))
		}
		if strings.Contains(s, "\r") {
			t.Fatalf("%s must be LF-only (no CR)", name)
		}
	}
}

func TestHardwareDocsNeverClaimTPROXYSupported(t *testing.T) {
	files := [][]string{
		{"docs", "hardware", "KN-1011.md"},
		{"docs", "hardware", "kn-1011-capabilities.md"},
		{"router-smoke.ps1"},
		{"scripts", "router-probe.sh"},
		{"scripts", "router-smoke-routing.sh"},
		{"scripts", "router-smoke-app.sh"},
	}
	claim := regexp.MustCompile(`(?i)TPROXY[[:space:]]*[:=][[:space:]]*SUPPORTED`)
	for _, rel := range files {
		s := readRepoFile(t, rel...)
		if claim.MatchString(s) {
			t.Errorf("%s must not write TPROXY as SUPPORTED", filepath.Join(rel...))
		}
	}
}

func TestCopyScriptViaSshCatClosesStdin(t *testing.T) {
	ps1 := readRepoFile(t, "router-smoke.ps1")
	if !strings.Contains(ps1, "function Copy-ScriptViaSshCat") {
		t.Fatal("Copy-ScriptViaSshCat not found")
	}
	if strings.Contains(ps1, "BeginWrite") {
		if !strings.Contains(ps1, "EndWrite") {
			t.Fatal("BeginWrite without EndWrite is forbidden")
		}
		if strings.Index(ps1, "EndWrite") < strings.Index(ps1, "BeginWrite") {
			t.Fatal("EndWrite must follow BeginWrite")
		}
		if !strings.Contains(ps1, "StandardInput.Close") {
			t.Fatal("BeginWrite path must Close StandardInput so remote cat receives EOF")
		}
	} else if !strings.Contains(ps1, " < ") && !strings.Contains(ps1, "StandardInput.Close") {
		t.Fatal("upload must close stdin so remote cat receives EOF")
	}
	if !strings.Contains(ps1, "RedirectStandardOutput = $false") && !strings.Contains(ps1, "RedirectStandardOutput=$false") {
		t.Fatal("upload must not redirect stdout into an unread pipe")
	}
	if !strings.Contains(ps1, "RedirectStandardError = $false") && !strings.Contains(ps1, "RedirectStandardError=$false") {
		t.Fatal("upload must not redirect stderr into an unread pipe")
	}
	if !strings.Contains(ps1, "taskkill /F /T") {
		t.Fatal("timeout must terminate ssh process tree")
	}
	if !strings.Contains(ps1, "Remove-Item") {
		t.Fatal("must delete local temporary upload file")
	}
	for _, want := range []string{
		"TIMEOUT_CLEANED",
		"TIMEOUT_CLEANUP_FAILED",
		"REMOTE_PROCESS_NOT_FOUND",
		"REMOTE_PROCESS_FOREIGN",
		"--cleanup-run-id",
		"--cleanup-orphans",
		"BTKN_PROBE_RUN_ID",
	} {
		if !strings.Contains(ps1, want) {
			t.Fatalf("ssh timeout cleanup missing %q", want)
		}
	}
}

func TestProbeDumpBudgetFitsDeadline(t *testing.T) {
	s := readProbeScript(t)
	if !strings.Contains(s, "===== END =====") {
		t.Fatal("probe must print ===== END =====")
	}
	maxSec := probeShellDefaultInt(t, s, "BTKN_PROBE_MAX_SEC")
	cmdSec := probeShellDefaultInt(t, s, "BTKN_PROBE_CMD_SEC")
	if maxSec > 180 {
		t.Fatalf("must not raise global deadline above 180s, got %d", maxSec)
	}
	idx := strings.Index(s, `# ----- NETWORK -----`)
	if idx < 0 {
		t.Fatal("missing NETWORK section")
	}
	worker := s[idx:]
	n := strings.Count(worker, `try_net "`)
	loopExtra := 0
	if strings.Contains(worker, `try_net "ip route show table ${_tbl}"`) {
		re := regexp.MustCompile(`head -n ([0-9]+)`)
		m := re.FindStringSubmatch(worker)
		if len(m) != 2 {
			t.Fatal("policy-table loop must cap with head -n N")
		}
		capN, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		if capN > 0 {
			loopExtra = capN - 1
		}
	}
	const supervisorOverheadSec = 20
	worst := (n+loopExtra)*cmdSec + supervisorOverheadSec
	if worst >= maxSec {
		t.Fatalf("read-only dump cannot reach END: try_net=%d loop_extra=%d cmd_sec=%d overhead=%d worst=%ds >= max_sec=%d", n, loopExtra, cmdSec, supervisorOverheadSec, worst, maxSec)
	}
}

func probeShellDefaultInt(t *testing.T, script, name string) int {
	t.Helper()
	re := regexp.MustCompile(name + `="\$\{` + name + `:-([0-9]+)\}"`)
	m := re.FindStringSubmatch(script)
	if len(m) != 2 {
		t.Fatalf("missing %s default", name)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestProbeRecordsModprobePresence(t *testing.T) {
	s := readProbeScript(t)
	if !strings.Contains(s, `command -v modprobe`) {
		t.Fatal("probe must record command -v modprobe")
	}
	if !strings.Contains(s, "MODPROBE: PRESENT") || !strings.Contains(s, "MODPROBE: NOT AVAILABLE") {
		t.Fatal("probe must print MODPROBE: PRESENT or NOT AVAILABLE")
	}
	if !strings.Contains(s, "xt_mark.ko") || !strings.Contains(s, "xt_MARK.ko") {
		t.Fatal("probe must look up both MARK filename cases")
	}
	if !strings.Contains(s, "xt_connmark.ko") || !strings.Contains(s, "xt_CONNMARK.ko") {
		t.Fatal("probe must look up both CONNMARK filename cases")
	}
	if !strings.Contains(s, "nf_tproxy_ipv4") {
		t.Fatal("probe must look up nf_tproxy_ipv4")
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
