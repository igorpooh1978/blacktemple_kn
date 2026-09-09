package platform

import (
	"path/filepath"
	"strings"
)

// ForeignXrayExecutable is XKeen's Xray. It must never be treated as OUR binary.
const ForeignXrayExecutable = "/opt/sbin/xray"

// IsOurXrayExecutable reports whether exe is the BlackTemple-owned Xray.
func IsOurXrayExecutable(exe, want string) bool {
	exe = strings.TrimSpace(exe)
	want = strings.TrimSpace(want)
	if exe == "" || want == "" {
		return false
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	cleanExe := filepath.ToSlash(filepath.Clean(exe))
	cleanWant := filepath.ToSlash(filepath.Clean(want))
	if cleanExe == ForeignXrayExecutable || strings.HasSuffix(cleanExe, "/opt/sbin/xray") {
		return false
	}
	if want == DefaultXrayPath && (cleanExe == ForeignXrayExecutable || strings.Contains(cleanExe, "/opt/sbin/xray")) {
		return false
	}
	return cleanExe == cleanWant
}
