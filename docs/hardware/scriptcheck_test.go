package hardware_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func locateProbeScript(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "scripts", "router-probe.sh")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("scripts/router-probe.sh not found by walking to repo root")
	return ""
}

func readProbeScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(locateProbeScript(t))
	if err != nil {
		t.Fatalf("read probe script: %v", err)
	}
	return string(b)
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
		regexp.MustCompile(`ip[[:space:]]+rule[[:space:]]+add\b`),
		regexp.MustCompile(`ip[[:space:]]+route[[:space:]]+add\b`),
		regexp.MustCompile(`sysctl[[:space:]]+-w\b`),
		regexp.MustCompile(`(?m)(^|[[:space:];|&])kill[[:space:]]`),
		regexp.MustCompile(`opkg[[:space:]]+install\b`),
		regexp.MustCompile(`service[[:space:]]+restart\b`),
	}
	for _, re := range forbidden {
		if loc := re.FindStringIndex(s); loc != nil {
			t.Errorf("forbidden mutating pattern %s at offset %d: %q", re.String(), loc[0], snippet(s, loc[0]))
		}
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
		"SYSTEM", "CPU", "MEMORY", "FILESYSTEM", "ENTWARE", "TOOLS",
		"NETWORK", "ROUTING", "FIREWALL", "IPTABLES", "TARGETS", "IPSET",
		"TUN", "KERNEL", "MODULES", "DNS", "XRAY", "XKEEN", "INIT", "LIMITS", "SOCKETS",
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
