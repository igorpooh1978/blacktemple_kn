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
}
