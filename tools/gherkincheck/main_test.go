package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsDuplicateScenarioID(t *testing.T) {
	root := t.TempDir()
	feat := filepath.Join(root, "features")
	if err := os.Mkdir(feat, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `Feature: dup
  @BTKN-DUP-001 @P0
  Scenario: one
    Then x

  @BTKN-DUP-001 @P0
  Scenario: two
    Then y
`
	if err := os.WriteFile(filepath.Join(feat, "dup.feature"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(feat, "scenario-map.json"), []byte(`{"schemaVersion":1,"scenarios":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run(root)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("got %v", err)
	}
}

func TestRunRejectsP0WithoutTestFunc(t *testing.T) {
	root := t.TempDir()
	feat := filepath.Join(root, "features")
	if err := os.MkdirAll(feat, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `Feature: map
  @BTKN-MAP-001 @P0
  Scenario: one
    Then x
`
	if err := os.WriteFile(filepath.Join(feat, "map.feature"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	mp := `{
  "schemaVersion": 1,
  "scenarios": {
    "BTKN-MAP-001": {"priority":"P0","tests":["missing_test.go"]}
  }
}`
	if err := os.WriteFile(filepath.Join(feat, "scenario-map.json"), []byte(mp), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run(root)
	if err == nil || !strings.Contains(err.Error(), "path::TestName") {
		t.Fatalf("got %v", err)
	}
}

func TestRunRejectsUnknownMapID(t *testing.T) {
	root := t.TempDir()
	feat := filepath.Join(root, "features")
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(feat, 0o755); err != nil {
		t.Fatal(err)
	}
	tf := filepath.Join(root, "src", "ok_test.go")
	if err := os.WriteFile(tf, []byte("package src\nfunc TestOK(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := `Feature: map
  @BTKN-MAP-001 @P0
  Scenario: one
    Then x
`
	if err := os.WriteFile(filepath.Join(feat, "map.feature"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	mp := `{
  "schemaVersion": 1,
  "scenarios": {
    "BTKN-MAP-001": {"priority":"P0","tests":["src/ok_test.go::TestOK"]},
    "BTKN-MAP-999": {"priority":"P0","tests":["src/ok_test.go::TestOK"]}
  }
}`
	if err := os.WriteFile(filepath.Join(feat, "scenario-map.json"), []byte(mp), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run(root)
	if err == nil || !strings.Contains(err.Error(), "extra id") {
		t.Fatalf("got %v", err)
	}
}
