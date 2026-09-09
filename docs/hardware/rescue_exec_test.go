package hardware_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func requireSh(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	return sh
}

func copyRescue(t *testing.T, dir string) string {
	t.Helper()
	src := readRepoFile(t, "scripts", "btkn-rescue.sh")
	dst := filepath.Join(dir, "btkn-rescue.sh")
	if err := os.WriteFile(dst, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

func runRescue(t *testing.T, sh, dir, script string, args ...string) string {
	t.Helper()
	cmd := exec.Command(sh, append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), "BTKN_RESCUE_DIR="+dir, "BTKN_XKEEN_INIT="+filepath.Join(dir, "S05xkeen"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestRescueExecStaleRecoverIsHarmless(t *testing.T) {
	sh := requireSh(t)
	dir := t.TempDir()
	script := copyRescue(t, dir)
	_ = runRescue(t, sh, dir, script, "arm", "runA", "90")
	_ = runRescue(t, sh, dir, script, "arm", "runB", "90")
	out := runRescue(t, sh, dir, script, "recover", "runA")
	if !strings.Contains(out, "rescue_stale") {
		t.Fatalf("stale recover: %s", out)
	}
	if strings.Contains(out, "rescue_btkn=REMOVED") {
		t.Fatalf("stale watcher must not recover: %s", out)
	}
}

func TestRescueExecDisarmBLeavesA(t *testing.T) {
	sh := requireSh(t)
	dir := t.TempDir()
	script := copyRescue(t, dir)
	_ = runRescue(t, sh, dir, script, "arm", "runA", "90")
	_ = runRescue(t, sh, dir, script, "arm", "runB", "90")
	_ = runRescue(t, sh, dir, script, "disarm", "runB")
	if _, err := os.Stat(filepath.Join(dir, "btkn-rescue.runA.armed")); err != nil {
		t.Fatalf("run A armed file must remain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "btkn-rescue.runA.disarm")); err == nil {
		t.Fatal("disarm B must not write run A disarm file")
	}
	out := runRescue(t, sh, dir, script, "recover", "runB")
	if !strings.Contains(out, "rescue_stale") {
		t.Fatalf("disarmed B recover: %s", out)
	}
}

func TestRescueExecHealthySkipsXKeenStart(t *testing.T) {
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("/proc required for foreign Xray identity")
	}
	sh := requireSh(t)
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	dir := t.TempDir()
	script := copyRescue(t, dir)
	initLog := filepath.Join(dir, "xkeen-start.log")
	init := filepath.Join(dir, "S05xkeen")
	body := "#!/bin/sh\necho START >> \"" + filepath.ToSlash(initLog) + "\"\n"
	if err := os.WriteFile(init, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sleepBin)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "foreign-xray")
	if err := os.WriteFile(bin, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	proc := exec.Command(bin, "30")
	if err := proc.Start(); err != nil {
		t.Fatalf("start foreign stand-in: %v", err)
	}
	defer func() { _ = proc.Process.Kill() }()

	ss := filepath.Join(dir, "ss")
	ssBody := "#!/bin/sh\necho 'tcp LISTEN 0 0 *:1181 0.0.0.0:*'\necho 'udp UNCONN 0 0 *:1181 0.0.0.0:*'\n"
	if err := os.WriteFile(ss, []byte(ssBody), 0o755); err != nil {
		t.Fatal(err)
	}

	env := append(os.Environ(),
		"BTKN_RESCUE_DIR="+dir,
		"BTKN_XKEEN_INIT="+init,
		"BTKN_FOREIGN_XRAY="+bin,
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	cmd := exec.Command(sh, script, "arm", "healthy-run", "90")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("arm: %v %s", err, out)
	}
	cmd = exec.Command(sh, script, "recover", "healthy-run")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("recover: %v %s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "rescue_xkeen=ALREADY_HEALTHY") {
		t.Fatalf("want ALREADY_HEALTHY, got %s", text)
	}
	if _, err := os.Stat(initLog); err == nil {
		t.Fatal("S05xkeen start must not run when XKeen is already healthy")
	}
}
