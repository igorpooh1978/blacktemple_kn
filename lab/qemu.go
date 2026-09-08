package lab

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	defaultMemMiB   = 256
	guestSSHPort    = 22
	guestHealthPort = 7480
	qemuMachine     = "malta"
	qemuCPU         = "24Kc"
)

// NetPlan is the isolated QEMU user-mode network layout.
type NetPlan struct {
	AllowHostLAN bool
	SSHHostPort  int
	HealthPort   int
	SerialPort   int
}

// QEMUArgs is a complete qemu-system-mipsel command.
type QEMUArgs struct {
	Path    string
	Args    []string
	WorkDir string
}

// FindQEMU locates qemu-system-mipsel. It never installs QEMU.
func FindQEMU() (string, error) {
	if p := strings.TrimSpace(os.Getenv("QEMU_SYSTEM_MIPSEL")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("%s: %s is set but not a file", QEMUNotInstalled, p)
	}
	names := []string{"qemu-system-mipsel"}
	if runtime.GOOS == "windows" {
		names = []string{"qemu-system-mipsel.exe", "qemu-system-mipsel"}
	}
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	if runtime.GOOS == "windows" {
		for _, dir := range []string{
			filepath.Join(os.Getenv("ProgramFiles"), "qemu"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "qemu"),
		} {
			p := filepath.Join(dir, "qemu-system-mipsel.exe")
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("%s: qemu-system-mipsel not found on PATH", QEMUNotInstalled)
}

// FindQEMUImg locates qemu-img for overlay creation. Missing is not fatal.
func FindQEMUImg(qemuPath string) string {
	if p, err := exec.LookPath("qemu-img"); err == nil {
		return p
	}
	if p, err := exec.LookPath("qemu-img.exe"); err == nil {
		return p
	}
	if qemuPath != "" {
		p := filepath.Join(filepath.Dir(qemuPath), "qemu-img.exe")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
		p = filepath.Join(filepath.Dir(qemuPath), "qemu-img")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// InstallHint is a verified install path when QEMU is missing.
func InstallHint() string {
	return strings.Join([]string{
		"QEMU is not installed. This lab does not install QEMU automatically.",
		"Windows (official installer): https://www.qemu.org/download/#windows → https://qemu.weilnetz.de/w64/",
		"Windows (winget, verified in microsoft/winget-pkgs): winget install --id SoftwareFreedomConservancy.QEMU",
		"Ubuntu/Debian CI/host: apt-get install qemu-system-mips qemu-utils",
		"Need qemu-system-mipsel. QEMU Malta is not an MT7621 emulator and is not KN-1011.",
	}, "\n")
}

// FreeLocalPort binds 127.0.0.1:0 and returns the port.
func FreeLocalPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// BuildQEMUArgs builds an isolated Malta mipsel command.
// WAN = user NAT. LAN = isolated user net with hostfwd to 127.0.0.1.
// No tap/bridge. Not MT7621.
func BuildQEMUArgs(qemuPath, kernelPath, overlayQcow string, lock *Lock, net NetPlan) (*QEMUArgs, error) {
	if qemuPath == "" {
		return nil, fmt.Errorf("%s", QEMUNotInstalled)
	}
	if kernelPath == "" {
		return nil, fmt.Errorf("kernel path is empty")
	}
	mem := defaultMemMiB
	if lock != nil && lock.MemoryMiB > 0 {
		mem = lock.MemoryMiB
	}
	if net.SSHHostPort <= 0 || net.SerialPort <= 0 {
		return nil, fmt.Errorf("ssh and serial host ports are required")
	}
	health := net.HealthPort
	if health <= 0 {
		health = guestHealthPort
	}
	hostfwdBind := "127.0.0.1"
	lanNetdev := "user,id=lan,net=192.168.1.0/24,host=192.168.1.2,restrict=on"
	if net.AllowHostLAN {
		// Explicit opt-in: still user-mode (no tap/bridge to production LAN).
		lanNetdev = "user,id=lan,net=192.168.1.0/24,host=192.168.1.2"
	}
	lanNetdev += ",hostfwd=tcp:" + hostfwdBind + ":" + strconv.Itoa(net.SSHHostPort) + "-192.168.1.1:" + strconv.Itoa(guestSSHPort)
	lanNetdev += ",hostfwd=tcp:" + hostfwdBind + ":" + strconv.Itoa(health) + "-192.168.1.1:" + strconv.Itoa(guestHealthPort)

	args := []string{
		"-machine", qemuMachine,
		"-cpu", qemuCPU,
		"-m", strconv.Itoa(mem),
		"-display", "none",
		"-monitor", "none",
		"-no-reboot",
		"-kernel", kernelPath,
		"-append", "console=ttyS0,115200n8",
		"-serial", fmt.Sprintf("tcp:127.0.0.1:%d,server,nowait", net.SerialPort),
		"-netdev", lanNetdev,
		"-device", "pcnet,id=devlan,netdev=lan",
		"-netdev", "user,id=wan",
		"-device", "pcnet,id=devwan,netdev=wan",
	}
	if overlayQcow != "" {
		args = append(args, "-drive", "file="+overlayQcow+",format=qcow2,if=ide")
	}
	return &QEMUArgs{Path: qemuPath, Args: args}, nil
}

// ContainsForbiddenNet reports tap/bridge in the command (must not be default).
func ContainsForbiddenNet(args []string) bool {
	joined := strings.ToLower(strings.Join(args, " "))
	return strings.Contains(joined, "tap") || strings.Contains(joined, "bridge")
}
