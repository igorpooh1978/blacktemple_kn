package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceExisting(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "state.json")
	if err := os.WriteFile(dest, []byte("working"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(dest, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "candidate" {
		t.Fatalf("got %q", got)
	}
	tmps, _ := filepath.Glob(filepath.Join(dir, ".atomic-*.tmp"))
	if len(tmps) != 0 {
		t.Fatalf("tmp leftovers %v", tmps)
	}
}

func TestFailedReplaceLeavesOld(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "state.json")
	if err := os.WriteFile(dest, []byte("working"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected replace failure")
	w := &Writer{Replace: func(tmp, dest string) error {
		return injected
	}}
	err := w.WriteFile(dest, []byte("candidate"), 0o600)
	if !errors.Is(err, injected) {
		t.Fatalf("got %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "working" {
		t.Fatalf("old destination lost: %q", got)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("old destination missing: %v", err)
	}
}

func TestWriteFileCreatesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "nested", "pointer.json")
	if err := WriteFile(dest, []byte(`{"active":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != `{"active":"a"}` {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestFailedReplaceCleansTempOnly(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "state.json")
	if err := os.WriteFile(dest, []byte("working"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &Writer{Replace: func(tmp, dest string) error {
		if _, err := os.Stat(tmp); err != nil {
			t.Errorf("tmp missing at replace: %v", err)
		}
		return errors.New("fail")
	}}
	_ = w.WriteFile(dest, []byte("candidate"), 0o600)
	matches, _ := filepath.Glob(filepath.Join(dir, ".atomic-*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("tmp must be removed after failed replace: %v", matches)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "working" {
		t.Fatalf("got %q", got)
	}
}

func TestTempLivesOnSameDir(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "p")
	var seen string
	w := &Writer{Replace: func(tmp, destPath string) error {
		seen = tmp
		return platformReplace(tmp, destPath)
	}}
	if err := w.WriteFile(dest, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(seen) != dir {
		t.Fatalf("tmp dir %q want %q", filepath.Dir(seen), dir)
	}
	if !strings.Contains(filepath.Base(seen), ".atomic-") {
		t.Fatalf("tmp name %q", seen)
	}
}
