//go:build unix

package platform

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FindOurXrayProcess locates a live process whose /proc/pid/exe is want.
func FindOurXrayProcess(want string) (pid int, exe string, ok bool) {
	want = strings.TrimSpace(want)
	if want == "" {
		return 0, "", false
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", false
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		id, err := strconv.Atoi(e.Name())
		if err != nil || id <= 0 {
			continue
		}
		link, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue
		}
		if IsOurXrayExecutable(link, want) {
			return id, link, true
		}
	}
	return 0, "", false
}
