package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectPE(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.exe")
	pe := make([]byte, 64)
	binary.LittleEndian.PutUint16(pe[0:2], 0x5A4D)
	if err := os.WriteFile(path, pe, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := check(path, "32", "le", "mips"); err == nil {
		t.Fatal("expected PE rejection")
	}
}
