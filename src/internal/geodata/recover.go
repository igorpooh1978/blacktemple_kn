package geodata

import (
	"os"
	"path/filepath"
	"strings"
)

// Recover scans for crash leftovers. The state.json pointer remains source of
// truth: orphans and *.tmp are never auto-activated.
func (m *Manager) Recover() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recoverLocked()
}

func (m *Manager) recoverLocked() error {
	m.removeGlobs(
		filepath.Join(m.root, "*.tmp"),
		filepath.Join(m.root, ".atomic-*.tmp"),
		filepath.Join(m.setsDir(), "*", ".atomic-*.tmp"),
		filepath.Join(m.setsDir(), "*", "*.tmp"),
	)

	st, err := m.loadState()
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

	entries, rdErr := os.ReadDir(m.setsDir())
	if rdErr != nil && !os.IsNotExist(rdErr) {
		return rdErr
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, ok := keep[e.Name()]; ok {
			continue
		}
		_ = m.removeAll(m.setDir(e.Name()))
	}

	if err == nil && st.Active != "" && !m.setComplete(st.Active) {
		if m.setComplete(st.Previous) {
			return ErrMissingActiveSet
		}
		return ErrMissingActiveSet
	}
	return nil
}

func (m *Manager) removeGlobs(patterns ...string) {
	for _, p := range patterns {
		matches, err := filepath.Glob(p)
		if err != nil {
			continue
		}
		for _, match := range matches {
			base := filepath.Base(match)
			if !strings.HasSuffix(base, ".tmp") {
				continue
			}
			_ = os.Remove(match)
		}
	}
}
