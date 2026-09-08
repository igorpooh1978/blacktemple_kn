package xray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLockPinCandidate(t *testing.T) {
	path := filepath.Join("..", "..", "..", "third_party", "xray.lock.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pin Pin
	if err := json.Unmarshal(raw, &pin); err != nil {
		t.Fatal(err)
	}
	if pin.Version != "v26.7.28" || pin.Tag != "v26.7.28" {
		t.Fatalf("pin version/tag = %s/%s want v26.7.28", pin.Version, pin.Tag)
	}
	if pin.HardwareVerification.KN1011 != "NOT RUN" {
		t.Fatalf("kn-1011 must stay NOT RUN, got %q", pin.HardwareVerification.KN1011)
	}
	if pin.HardwareVerification.QEMU != "NOT RUN" {
		t.Fatalf("qemu must stay NOT RUN, got %q", pin.HardwareVerification.QEMU)
	}
	if pin.StableAutoUpdate {
		t.Fatal("stableAutoUpdate must be false (do not follow latest)")
	}
	le, ok := pin.Targets["linux-mipsle-softfloat"]
	if !ok {
		t.Fatal("missing linux-mipsle-softfloat")
	}
	if !strings.Contains(le.ZipURL, "/v26.7.28/Xray-linux-mips32le.zip") {
		t.Fatalf("unexpected mips32le url %s", le.ZipURL)
	}
	if le.ZipSHA256 != "4779e1afba7dea12c64a72380f1d9737a12359f354014625a7f9d96f8d31e3fa" {
		t.Fatalf("unexpected mips32le sha256 %s", le.ZipSHA256)
	}
	if le.BinaryInZip != "xray_softfloat" {
		t.Fatalf("binaryInZip=%s", le.BinaryInZip)
	}
	be, ok := pin.Targets["linux-mips-softfloat"]
	if !ok {
		t.Fatal("missing linux-mips-softfloat")
	}
	if !strings.Contains(be.ZipURL, "/v26.7.28/Xray-linux-mips32.zip") {
		t.Fatalf("unexpected mips32 url %s", be.ZipURL)
	}
	if be.ZipSHA256 != "aec600118fd1e7ee42e8d5e8d5c82cc5e8139e82ff1da029e9b81b7170fc028c" {
		t.Fatalf("unexpected mips32 sha256 %s", be.ZipSHA256)
	}
	if be.BinaryInZip != "xray_softfloat" {
		t.Fatalf("be binaryInZip=%s", be.BinaryInZip)
	}
	win, ok := pin.Targets["windows-amd64-test"]
	if !ok {
		t.Fatal("missing windows-amd64-test")
	}
	if !strings.Contains(win.ZipURL, "/v26.7.28/Xray-windows-64.zip") {
		t.Fatalf("unexpected windows url %s", win.ZipURL)
	}
	if win.ZipSHA256 != "c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1" {
		t.Fatalf("unexpected windows sha256 %s", win.ZipSHA256)
	}
	if win.BinaryInZip != "xray.exe" {
		t.Fatalf("windows binaryInZip=%s", win.BinaryInZip)
	}
	if win.IPKArch != "" {
		t.Fatal("windows-amd64-test must not ship in IPK")
	}
	lin, ok := pin.Targets["linux-amd64-test"]
	if !ok {
		t.Fatal("missing linux-amd64-test")
	}
	if lin.ZipSHA256 != "8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40" {
		t.Fatalf("unexpected linux-amd64 sha256 %s", lin.ZipSHA256)
	}
	if lin.IPKArch != "" {
		t.Fatal("linux-amd64-test must not ship in IPK")
	}
}
