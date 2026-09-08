//go:build !unix && !windows

package platform

func InspectPID(pid int) ProcessInfo {
	return ProcessInfo{PID: pid, Alive: false}
}
