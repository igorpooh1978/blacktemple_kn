//go:build unix

package platform

import (
	"fmt"
	"os"
	"syscall"
)

// InspectPID reports liveness and, on Linux, /proc/pid/exe identity.
func InspectPID(pid int) ProcessInfo {
	info := ProcessInfo{PID: pid}
	if pid <= 0 {
		return info
	}
	err := syscall.Kill(pid, 0)
	if err != nil && err != syscall.EPERM {
		return info
	}
	info.Alive = true
	if p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		info.Executable = p
	}
	return info
}
