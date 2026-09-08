package remotelists

import (
	"os"
	"path/filepath"
	"strings"
)

func recoverListDir(dir string, removeAll func(string) error) error {
	_ = removeGlobs(
		filepath.Join(dir, "*.tmp"),
		filepath.Join(dir, ".atomic-*.tmp"),
		filepath.Join(revisionsDir(dir), "*", "*.tmp"),
		filepath.Join(revisionsDir(dir), "*", ".atomic-*.tmp"),
	)
	st, err := loadPointer(dir)
	keep := map[string]struct{}{}
	if err == nil {
		if st.Active != "" {
			keep[st.Active] = struct{}{}
		}
		if st.Previous != "" {
			keep[st.Previous] = struct{}{}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	gcRevisions(dir, keep, removeAll)
	if err == nil && st.Active != "" && !revisionComplete(dir, st.Active) {
		if revisionComplete(dir, st.Previous) {
			return ErrMissingRevision
		}
		return ErrMissingRevision
	}
	return nil
}

func recoverAllLists(root string, removeAll func(string) error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		_ = recoverListDir(filepath.Join(root, e.Name()), removeAll)
	}
}

func removeGlobs(patterns ...string) error {
	for _, p := range patterns {
		matches, err := filepath.Glob(p)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if !strings.HasSuffix(match, ".tmp") {
				continue
			}
			_ = os.Remove(match)
		}
	}
	return nil
}
