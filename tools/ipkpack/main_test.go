package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackRoundTrip(t *testing.T) {
	root := t.TempDir()
	control := filepath.Join(root, "control")
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(control, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(data, "opt", "blacktemple-kn", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(control, "control"), []byte("Package: blacktemple-kn\nArchitecture: mipsel-3.4_kn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "opt", "blacktemple-kn", "bin", "hello"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "pkg.ipk")
	if err := pack(data, control, out, 0); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "!<arch>\n") {
		t.Fatalf("not ar: %q", b[:8])
	}
	if !strings.Contains(string(b), "debian-binary") {
		t.Fatal("missing debian-binary")
	}
	if !strings.Contains(string(b), "control.tar.gz") {
		t.Fatal("missing control.tar.gz")
	}
	if !strings.Contains(string(b), "data.tar.gz") {
		t.Fatal("missing data.tar.gz")
	}
}
