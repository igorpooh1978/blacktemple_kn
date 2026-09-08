package xray

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMIPSLESoftfloatELF(t *testing.T) {
	path := os.Getenv("XRAY_MIPSLE_SOFTFLOAT")
	if path == "" {
		t.Skip("XRAY_MIPSLE_SOFTFLOAT not set; MIPS ELF check NOT RUN in this go test invocation")
	}
	if err := CheckMIPSLESoftfloatELF(path); err != nil {
		t.Fatal(err)
	}
}

func TestMips32leZipSoftfloat(t *testing.T) {
	zipPath := os.Getenv("XRAY_MIPS32LE_ZIP")
	if zipPath == "" {
		t.Skip("XRAY_MIPS32LE_ZIP not set; zip listing NOT RUN in this go test invocation")
	}
	ok, err := ZipContainsSoftfloat(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("zip does not contain xray_softfloat")
	}
	dest := filepath.Join(t.TempDir(), "xray_softfloat")
	if err := ExtractZipFile(zipPath, "xray_softfloat", dest); err != nil {
		t.Fatal(err)
	}
	if err := CheckMIPSLESoftfloatELF(dest); err != nil {
		t.Fatal(err)
	}
}
