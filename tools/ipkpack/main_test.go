package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEntwareIpkIsGzipTar(t *testing.T) {
	root := t.TempDir()
	control, data := makePkgDirs(t, root, "mipsel-3.4_kn")
	out := filepath.Join(root, "pkg.ipk")
	if err := pack(data, control, out, 0); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Fatalf("Entware opkg requires gzip outer, magic=%q", raw[:min(8, len(raw))])
	}
	if bytes.HasPrefix(raw, []byte("!<arch>\n")) {
		t.Fatal("raw ar is rejected by Entware opkg as malformed")
	}
	members := readOuterIpk(t, raw)
	for _, name := range []string{"./debian-binary", "./data.tar.gz", "./control.tar.gz"} {
		if len(members[name]) == 0 {
			t.Fatalf("missing %s (have %v)", name, outerKeys(members))
		}
	}
	if string(members["./debian-binary"]) != "2.0\n" {
		t.Fatalf("debian-binary=%q", members["./debian-binary"])
	}
}

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
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Fatalf("not gzip: %q", b[:min(8, len(b))])
	}
	members := readOuterIpk(t, b)
	if len(members["./debian-binary"]) == 0 || len(members["./control.tar.gz"]) == 0 || len(members["./data.tar.gz"]) == 0 {
		t.Fatalf("missing outer members: %v", outerKeys(members))
	}
}

func TestArchitectureFieldPacked(t *testing.T) {
	root := t.TempDir()
	control, data := makePkgDirs(t, root, "mipsel-3.4")
	out := filepath.Join(root, "pkg.ipk")
	if err := pack(data, control, out, 0); err != nil {
		t.Fatal(err)
	}
	arch, err := readControlArchitecture(control)
	if err != nil {
		t.Fatal(err)
	}
	if arch != "mipsel-3.4" {
		t.Fatalf("control dir Architecture=%q", arch)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	members := readOuterIpk(t, raw)
	ctrlTar := members["./control.tar.gz"]
	if len(ctrlTar) == 0 {
		t.Fatal("missing control.tar.gz member")
	}
	files := tarGzMap(t, ctrlTar)
	ctrl, ok := files["./control"]
	if !ok {
		ctrl, ok = files["control"]
	}
	if !ok {
		t.Fatalf("control file missing in tar, have %v", keys(files))
	}
	if !strings.Contains(string(ctrl.body), "Architecture: mipsel-3.4\n") {
		t.Fatalf("packed control:\n%s", ctrl.body)
	}
}

func TestFileModesShebangELFAndOverride(t *testing.T) {
	root := t.TempDir()
	control, data := makePkgDirs(t, root, "mips-3.4")
	binDir := filepath.Join(data, "opt", "blacktemple-kn", "bin")
	initDir := filepath.Join(data, "opt", "etc", "init.d")
	if err := os.MkdirAll(initDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "blacktempled"), []byte{0x7f, 'E', 'L', 'F', 1, 2, 3, 4}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(initDir, "S99blacktemple-kn"), []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(data, "opt", "blacktemple-kn", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "opt", "blacktemple-kn", "config", "notes.txt"), []byte("plain"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(control, "postinst"), []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(root, "pkg.ipk")
	chmod := map[string]int64{"opt/blacktemple-kn/config/notes.txt": 0o600}
	if err := packWith(data, control, out, 0, chmod); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	members := readOuterIpk(t, raw)
	dataFiles := tarGzMap(t, members["./data.tar.gz"])
	ctrlFiles := tarGzMap(t, members["./control.tar.gz"])

	assertMode(t, dataFiles, "./opt/blacktemple-kn/bin/blacktempled", 0o755)
	assertMode(t, dataFiles, "./opt/etc/init.d/S99blacktemple-kn", 0o755)
	assertMode(t, dataFiles, "./opt/blacktemple-kn/config/notes.txt", 0o600)
	assertMode(t, ctrlFiles, "./postinst", 0o755)
}

func TestShebangCRLFNormalizedInIpk(t *testing.T) {
	root := t.TempDir()
	control, data := makePkgDirs(t, root, "mipsel-3.4_kn")
	crlf := []byte("#!/bin/sh\r\nexit 0\r\n")
	if err := os.WriteFile(filepath.Join(control, "prerm"), crlf, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "pkg.ipk")
	if err := pack(data, control, out, 0); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	ctrlFiles := tarGzMap(t, readOuterIpk(t, raw)["./control.tar.gz"])
	body := ctrlFiles["./prerm"].body
	if bytes.Contains(body, []byte{'\r'}) {
		t.Fatalf("packed shebang still has CR: %q", body[:min(32, len(body))])
	}
	if !bytes.HasPrefix(body, []byte("#!/bin/sh\n")) {
		t.Fatalf("packed shebang=%q", body[:min(16, len(body))])
	}
}

func TestChecksumStableSameEpoch(t *testing.T) {
	root := t.TempDir()
	control, data := makePkgDirs(t, root, "mipsel-3.4_kn")
	if err := os.WriteFile(filepath.Join(data, "opt", "blacktemple-kn", "bin", "blacktempled"), []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatal(err)
	}
	out1 := filepath.Join(root, "a.ipk")
	out2 := filepath.Join(root, "b.ipk")
	if err := pack(data, control, out1, 0); err != nil {
		t.Fatal(err)
	}
	if err := pack(data, control, out2, 0); err != nil {
		t.Fatal(err)
	}
	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("packs with same epoch must be byte-identical")
	}
	sum1 := sha256.Sum256(b1)
	sum2 := sha256.Sum256(b2)
	if hex.EncodeToString(sum1[:]) != hex.EncodeToString(sum2[:]) {
		t.Fatal("sha256 mismatch")
	}
}

func TestReadControlArchitectureMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "control"), []byte("Package: blacktemple-kn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readControlArchitecture(dir); err == nil {
		t.Fatal("expected missing Architecture")
	}
}

func makePkgDirs(t *testing.T, root, arch string) (control, data string) {
	t.Helper()
	control = filepath.Join(root, "control")
	data = filepath.Join(root, "data")
	if err := os.MkdirAll(control, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(data, "opt", "blacktemple-kn", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctrl := "Package: blacktemple-kn\nVersion: 0.1.0-dev\nArchitecture: " + arch + "\n"
	if err := os.WriteFile(filepath.Join(control, "control"), []byte(ctrl), 0o644); err != nil {
		t.Fatal(err)
	}
	return control, data
}

type tarEnt struct {
	mode int64
	body []byte
}

func tarGzMap(t *testing.T, gz []byte) map[string]tarEnt {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	out := map[string]tarEnt{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = tarEnt{mode: hdr.Mode & 0o777, body: body}
	}
	return out
}

func assertMode(t *testing.T, files map[string]tarEnt, name string, want int64) {
	t.Helper()
	ent, ok := files[name]
	if !ok {
		t.Fatalf("missing %s in tar (have %v)", name, keys(files))
	}
	if ent.mode != want {
		t.Fatalf("%s mode %04o want %04o", name, ent.mode, want)
	}
}

func keys(m map[string]tarEnt) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func readOuterIpk(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Fatal("missing gzip magic")
	}
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = body
	}
	return out
}

func outerKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
