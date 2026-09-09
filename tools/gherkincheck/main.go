// Command gherkincheck verifies Gherkin scenarios map to existing tests.
// Stdlib only. No Godog/Cucumber.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type scenarioMap struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Scenarios     map[string]mapEntry `json:"scenarios"`
}

type mapEntry struct {
	Priority string   `json:"priority"`
	Tests    []string `json:"tests"`
	REDProof string   `json:"redProof,omitempty"`
}

type parsedScenario struct {
	ID       string
	Name     string
	Priority string
	File     string
	Line     int
}

var idTag = regexp.MustCompile(`@BTKN-[A-Z]+-[0-9]{3}`)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	if err := run(root); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS gherkincheck")
}

func run(root string) error {
	featDir := filepath.Join(root, "features")
	mapPath := filepath.Join(featDir, "scenario-map.json")
	raw, err := os.ReadFile(mapPath)
	if err != nil {
		return fmt.Errorf("read scenario-map: %w", err)
	}
	var sm scenarioMap
	if err := json.Unmarshal(raw, &sm); err != nil {
		return err
	}
	if sm.SchemaVersion != 1 {
		return fmt.Errorf("scenario-map schemaVersion want 1 got %d", sm.SchemaVersion)
	}
	var features []string
	err = filepath.Walk(featDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".feature") {
			features = append(features, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(features) == 0 {
		return fmt.Errorf("no .feature files under %s", featDir)
	}
	seen := map[string]parsedScenario{}
	var p0 int
	for _, f := range features {
		ss, err := parseFeature(f)
		if err != nil {
			return err
		}
		for _, s := range ss {
			if prev, ok := seen[s.ID]; ok {
				return fmt.Errorf("duplicate %s in %s:%d and %s:%d", s.ID, prev.File, prev.Line, s.File, s.Line)
			}
			seen[s.ID] = s
			if s.Priority == "P0" {
				p0++
			}
		}
	}
	if p0 == 0 {
		return fmt.Errorf("no @P0 scenarios")
	}
	for id, s := range seen {
		ent, ok := sm.Scenarios[id]
		if !ok {
			return fmt.Errorf("%s (%s:%d) missing from scenario-map.json", id, s.File, s.Line)
		}
		if s.Priority == "P0" && len(ent.Tests) == 0 {
			return fmt.Errorf("%s is P0 but has no tests mapping", id)
		}
		if s.Priority != "" && ent.Priority != "" && s.Priority != ent.Priority {
			return fmt.Errorf("%s feature tag %s != map priority %s", id, s.Priority, ent.Priority)
		}
		if s.Priority == "P0" && ent.Priority != "P0" {
			return fmt.Errorf("%s is P0 but scenario-map priority is %q", id, ent.Priority)
		}
		seenRefs := map[string]bool{}
		for _, rel := range ent.Tests {
			if seenRefs[rel] {
				return fmt.Errorf("%s duplicate mapping %q", id, rel)
			}
			seenRefs[rel] = true
			testPath, fn, ok := splitTestRef(rel)
			if !ok {
				return fmt.Errorf("%s: invalid test ref %q (want path::Func)", id, rel)
			}
			if s.Priority == "P0" && (fn == "" || !strings.HasPrefix(fn, "Test")) {
				return fmt.Errorf("%s P0 mapping %q must be path::TestName", id, rel)
			}
			abs := filepath.Join(root, filepath.FromSlash(testPath))
			b, err := os.ReadFile(abs)
			if err != nil {
				return fmt.Errorf("%s: missing test file %s: %v", id, testPath, err)
			}
			if fn != "" && !strings.Contains(string(b), "func "+fn) {
				return fmt.Errorf("%s: %s does not contain func %s", id, testPath, fn)
			}
		}
	}
	for id := range sm.Scenarios {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("scenario-map extra id %s not in any .feature", id)
		}
	}
	fmt.Printf("scenarios=%d p0=%d features=%d mapped=%d\n", len(seen), p0, len(features), len(sm.Scenarios))
	return nil
}

func splitTestRef(rel string) (path, fn string, ok bool) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return "", "", false
	}
	if i := strings.Index(rel, "::"); i >= 0 {
		return rel[:i], rel[i+2:], true
	}
	return rel, "", true
}

func parseFeature(path string) ([]parsedScenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	var pending []string
	var out []parsedScenario
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "@") {
			pending = append(pending, strings.Fields(trim)...)
			continue
		}
		if strings.HasPrefix(trim, "Scenario:") || strings.HasPrefix(trim, "Scenario Outline:") {
			name := trim
			id := ""
			prio := ""
			for _, t := range pending {
				if idTag.MatchString(t) {
					id = t[1:]
				}
				switch t {
				case "@P0":
					prio = "P0"
				case "@P1":
					prio = "P1"
				case "@P2":
					prio = "P2"
				}
			}
			if id == "" {
				return nil, fmt.Errorf("%s:%d scenario without @BTKN-… tag: %s", path, i+1, name)
			}
			if prio == "" {
				return nil, fmt.Errorf("%s:%d %s missing @P0/@P1/@P2", path, i+1, id)
			}
			out = append(out, parsedScenario{ID: id, Name: name, Priority: prio, File: path, Line: i + 1})
			pending = nil
			continue
		}
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "Feature:") {
			if strings.HasPrefix(trim, "Feature:") {
				pending = nil
			}
			continue
		}
		if !strings.HasPrefix(trim, "@") {
			pending = nil
		}
	}
	return out, nil
}
