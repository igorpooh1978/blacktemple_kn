package lab

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("QEMULAB_HELPER"); mode != "" {
		runFakeQEMU(mode, os.Args[1:])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestLockValid(t *testing.T) {
	lock, err := LoadLock("openwrt.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if lock.Version != "24.10.8" {
		t.Fatalf("version %s", lock.Version)
	}
	if lock.Kernel.SHA256 != "78407e58231a82de3d8b0ef0f1ae52209487548bb3fdd2e37559681b08951553" {
		t.Fatalf("kernel sha256 %s", lock.Kernel.SHA256)
	}
	if lock.Machine != "malta" || lock.Architecture != "mipsel" {
		t.Fatalf("machine/arch %s %s", lock.Machine, lock.Architecture)
	}
	if strings.Contains(strings.ToLower(lock.Kernel.URL), "mt7621") {
		t.Fatal("must not pin MT7621")
	}
	if !lock.Experimental {
		t.Fatal("lock must mark qemu lab experimental")
	}
}

func TestLockIncomplete(t *testing.T) {
	_, err := LoadLock(filepath.Join("testdata", "lock-incomplete.json"))
	if err == nil {
		t.Fatal("expected incomplete lock error")
	}
	if !Incomplete(err) {
		t.Fatalf("want incomplete, got %v", err)
	}
}

func TestLockRejectsLatest(t *testing.T) {
	l := Lock{
		SchemaVersion:   1,
		Version:         "latest",
		Target:          "malta/le",
		Machine:         "malta",
		Architecture:    "mipsel",
		Endian:          "little",
		PinnedNotLatest: true,
		Kernel: Asset{
			Filename: "x.elf",
			URL:      "https://downloads.openwrt.org/x.elf",
			SHA256:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
	if err := l.Validate(); err == nil {
		t.Fatal("latest must be rejected")
	}
}

func TestSHAMismatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blob")
	if err := os.WriteFile(p, []byte("not-the-openwrt-image"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := VerifySHA256(p, "78407e58231a82de3d8b0ef0f1ae52209487548bb3fdd2e37559681b08951553")
	if err == nil {
		t.Fatal("expected sha256 mismatch")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestPrepareMissingQEMU(t *testing.T) {
	t.Setenv("QEMU_SYSTEM_MIPSEL", filepath.Join(t.TempDir(), "qemu-system-mipsel-missing"))
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	cfg := LabConfig{
		Root:     root,
		LockPath: "openwrt.lock.json",
		CacheDir: t.TempDir(),
		Stdout:   discardWriter{},
	}
	_, _, _, r := Prepare(&cfg)
	if r.ExitCode != ExitQEMUNotInstalled {
		t.Fatalf("exit %d status %s detail %s", r.ExitCode, r.Status, r.Detail)
	}
	if r.Status != QEMUNotInstalled {
		t.Fatalf("status %s", r.Status)
	}
}

func TestMissingQEMU(t *testing.T) {
	t.Setenv("QEMU_SYSTEM_MIPSEL", filepath.Join(t.TempDir(), "qemu-system-mipsel-missing"))
	_, err := FindQEMU()
	if err == nil {
		t.Fatal("expected QEMU_NOT_INSTALLED")
	}
	if !strings.Contains(err.Error(), QEMUNotInstalled) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(InstallHint(), "SoftwareFreedomConservancy.QEMU") {
		t.Fatal("install hint must name verified winget id")
	}
	if !strings.Contains(InstallHint(), "qemu.weilnetz.de") {
		t.Fatal("install hint must name official Windows builds")
	}
}

func TestQEMUArgsIsolated(t *testing.T) {
	lock, err := LoadLock("openwrt.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	qa, err := BuildQEMUArgs("qemu-system-mipsel", "/tmp/kernel.elf", "", lock, NetPlan{
		SSHHostPort: 2200,
		HealthPort:  7480,
		SerialPort:  4400,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(qa.Args, " ")
	if !strings.Contains(joined, "-machine malta") {
		t.Fatalf("want malta, got %s", joined)
	}
	if strings.Contains(strings.ToLower(joined), "mt7621") {
		t.Fatal("must not mention mt7621")
	}
	if ContainsForbiddenNet(qa.Args) {
		t.Fatal("default args must not use tap/bridge")
	}
	if !strings.Contains(joined, "restrict=on") {
		t.Fatal("LAN must be isolated with restrict=on")
	}
	if !strings.Contains(joined, "hostfwd=tcp:127.0.0.1:") {
		t.Fatal("hostfwd must bind 127.0.0.1")
	}
	if !strings.Contains(joined, "id=wan") {
		t.Fatal("WAN user NAT missing")
	}
}

func TestBootTimeout(t *testing.T) {
	cfg := fakeLab(t)
	t.Setenv("QEMULAB_HELPER", "silent")
	r := Smoke(cfg)
	if r.ExitCode != ExitBootTimeout {
		t.Fatalf("exit %d status %s detail %s", r.ExitCode, r.Status, r.Detail)
	}
	if r.Status != "BOOT_TIMEOUT" {
		t.Fatalf("status %s", r.Status)
	}
}

func TestSSHTimeout(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Fatalf("ssh-keygen required for SSH timeout test: %v", err)
	}
	cfg := fakeLab(t)
	cfg.BootTimeout = 8 * time.Second
	cfg.SSHTimeout = 3 * time.Second
	t.Setenv("QEMULAB_HELPER", "serial-login")
	r := Smoke(cfg)
	if r.ExitCode != ExitSSHTimeout {
		t.Fatalf("exit %d status %s detail %s", r.ExitCode, r.Status, r.Detail)
	}
	if r.Status != "SSH_TIMEOUT" {
		t.Fatalf("status %s", r.Status)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func fakeLab(t *testing.T) LabConfig {
	t.Helper()
	lock, err := LoadLock("openwrt.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	kernel := filepath.Join(dir, "kernel.elf")
	if err := os.WriteFile(kernel, []byte("fake-kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := FileSHA256(kernel)
	if err != nil {
		t.Fatal(err)
	}
	lock.Kernel.Filename = "kernel.elf"
	lock.Kernel.SHA256 = sum
	lock.OverlayBase = Asset{}
	lockPath := filepath.Join(dir, "openwrt.lock.json")
	raw, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return LabConfig{
		Root:        root,
		LockPath:    lockPath,
		CacheDir:    dir,
		WorkDir:     filepath.Join(dir, "work"),
		QEMUPath:    os.Args[0],
		BootTimeout: 2 * time.Second,
		SSHTimeout:  time.Second,
		Stdout:      discardWriter{},
	}
}
