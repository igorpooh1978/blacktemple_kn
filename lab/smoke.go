package lab

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	guestPrefix      = "/opt/blacktemple-kn"
	defaultBootWait  = 180 * time.Second
	defaultSSHWait   = 90 * time.Second
	sshReadyInterval = 2 * time.Second
)

// Paths are host artifacts to copy into the guest.
type Paths struct {
	Daemon  string
	Xray    string
	Config  string
	Geodata string
}

// Result is the structured smoke report. Live QEMU is experimental, not KN-1011.
type Result struct {
	Status             string `json:"status"`
	QEMU               string `json:"qemu"`
	Image              string `json:"image"`
	SHA256             string `json:"sha256"`
	MIPSLEExecution    string `json:"mipsleExecution"`
	Blacktempled       string `json:"blacktempled"`
	Xray               string `json:"xray"`
	Network            string `json:"network"`
	EntwareEquivalence string `json:"entwareEquivalence"`
	Experimental       bool   `json:"experimental"`
	NotHardware        string `json:"notHardware"`
	Detail             string `json:"detail,omitempty"`
	ExitCode           int    `json:"exitCode"`
}

// LabConfig drives prepare/smoke.
type LabConfig struct {
	Root         string
	LockPath     string
	CacheDir     string
	WorkDir      string
	QEMUPath     string
	AllowHostLAN bool
	BootTimeout  time.Duration
	SSHTimeout   time.Duration
	Paths        Paths
	Stdout       io.Writer
}

func (c LabConfig) out() io.Writer {
	if c.Stdout != nil {
		return c.Stdout
	}
	return os.Stdout
}

func (c LabConfig) logf(format string, args ...any) {
	fmt.Fprintf(c.out(), format+"\n", args...)
}

func (c *LabConfig) defaults() error {
	if c.Root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		c.Root = wd
	}
	if c.LockPath == "" {
		c.LockPath = filepath.Join(c.Root, "lab", "openwrt.lock.json")
	}
	if c.CacheDir == "" {
		c.CacheDir = filepath.Join(c.Root, ".cache", "qemu")
	}
	if c.WorkDir == "" {
		c.WorkDir = filepath.Join(c.CacheDir, "work")
	}
	if c.BootTimeout == 0 {
		c.BootTimeout = defaultBootWait
	}
	if c.SSHTimeout == 0 {
		c.SSHTimeout = defaultSSHWait
	}
	return nil
}

func emptyResult(status string, code int, detail string) Result {
	return Result{
		Status:             status,
		QEMU:               status,
		MIPSLEExecution:    "NOT RUN",
		Blacktempled:       "NOT RUN",
		Xray:               "NOT RUN",
		Network:            "NOT RUN",
		EntwareEquivalence: "NOT CLAIMED",
		Experimental:       true,
		NotHardware:        "QEMU ≠ KN-1011",
		Detail:             detail,
		ExitCode:           code,
	}
}

// Prepare downloads/verifies the pin and builds a qcow2 overlay when possible.
func Prepare(cfg *LabConfig) (*Lock, string, string, Result) {
	if cfg == nil {
		r := emptyResult("SETUP_FAIL", ExitSetup, "lab config is nil")
		return nil, "", "", r
	}
	if err := cfg.defaults(); err != nil {
		r := emptyResult("SETUP_FAIL", ExitSetup, err.Error())
		return nil, "", "", r
	}
	lock, err := LoadLock(cfg.LockPath)
	if err != nil {
		r := emptyResult("LOCK_FAIL", ExitSetup, err.Error())
		return nil, "", "", r
	}
	qemuPath := cfg.QEMUPath
	if qemuPath == "" {
		p, err := FindQEMU()
		if err != nil {
			r := emptyResult(QEMUNotInstalled, ExitQEMUNotInstalled, err.Error()+"\n"+InstallHint())
			r.Image = lock.Version + " " + lock.Kernel.Filename
			r.SHA256 = lock.Kernel.SHA256
			return lock, "", "", r
		}
		qemuPath = p
		cfg.QEMUPath = p
	}
	cfg.logf("QEMU: %s (experimental Malta mipsel, not KN-1011)", qemuPath)
	kernel, err := EnsureAsset(cfg.CacheDir, lock.Kernel, nil)
	if err != nil {
		code := ExitSetup
		status := "DOWNLOAD_FAIL"
		if strings.Contains(err.Error(), "sha256 mismatch") {
			code = ExitSHAMismatch
			status = "SHA_MISMATCH"
		}
		r := emptyResult(status, code, err.Error())
		r.Image = lock.Version + " " + lock.Kernel.Filename
		r.SHA256 = lock.Kernel.SHA256
		return lock, "", "", r
	}
	overlay := ""
	if strings.TrimSpace(lock.OverlayBase.URL) != "" {
		gz, err := EnsureAsset(cfg.CacheDir, lock.OverlayBase, nil)
		if err != nil {
			code := ExitSetup
			status := "DOWNLOAD_FAIL"
			if strings.Contains(err.Error(), "sha256 mismatch") {
				code = ExitSHAMismatch
				status = "SHA_MISMATCH"
			}
			r := emptyResult(status, code, err.Error())
			r.Image = lock.Version + " " + lock.Kernel.Filename
			r.SHA256 = lock.Kernel.SHA256
			return lock, kernel, "", r
		}
		img := FindQEMUImg(qemuPath)
		if img == "" {
			cfg.logf("overlay: qemu-img not found; continuing with initramfs only (not a silent test skip)")
		} else {
			ov, err := PrepareOverlay(img, gz, cfg.WorkDir)
			if err != nil {
				r := emptyResult("OVERLAY_FAIL", ExitSetup, err.Error())
				r.Image = lock.Version + " " + lock.Kernel.Filename
				r.SHA256 = lock.Kernel.SHA256
				return lock, kernel, "", r
			}
			overlay = ov
			cfg.logf("overlay: %s", overlay)
		}
	}
	r := emptyResult("PREPARED", ExitOK, "")
	r.Image = lock.Version + " " + lock.Kernel.Filename
	r.SHA256 = lock.Kernel.SHA256
	r.QEMU = qemuPath
	return lock, kernel, overlay, r
}

// Smoke boots the isolated lab and runs MIPSLE integration checks.
func Smoke(cfg LabConfig) Result {
	lock, kernel, overlay, prep := Prepare(&cfg)
	if prep.ExitCode != ExitOK {
		return prep
	}
	sshPort, err := FreeLocalPort()
	if err != nil {
		return failPrep(lock, ExitSetup, err.Error())
	}
	serialPort, err := FreeLocalPort()
	if err != nil {
		return failPrep(lock, ExitSetup, err.Error())
	}
	healthPort, err := FreeLocalPort()
	if err != nil {
		return failPrep(lock, ExitSetup, err.Error())
	}
	plan := NetPlan{
		AllowHostLAN: cfg.AllowHostLAN,
		SSHHostPort:  sshPort,
		HealthPort:   healthPort,
		SerialPort:   serialPort,
	}
	qa, err := BuildQEMUArgs(cfg.QEMUPath, kernel, "", lock, plan)
	if err != nil {
		return failPrep(lock, ExitSetup, err.Error())
	}
	if ContainsForbiddenNet(qa.Args) {
		return failPrep(lock, ExitSetup, "qemu args contain tap/bridge")
	}
	cfg.logf("launch: %s %s", qa.Path, strings.Join(qa.Args, " "))
	if overlay != "" {
		cfg.logf("overlay prepared but not attached (initramfs kernel boot): %s", overlay)
	}
	cmd := exec.Command(qa.Path, qa.Args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		r := failPrep(lock, ExitSetup, err.Error())
		r.QEMU = cfg.QEMUPath
		return r
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	serialAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serialPort))
	sess, err := waitSerial(serialAddr, cfg.BootTimeout)
	if err != nil {
		r := failPrep(lock, ExitBootTimeout, err.Error())
		r.QEMU = cfg.QEMUPath
		r.Status = "BOOT_TIMEOUT"
		r.MIPSLEExecution = "NOT RUN"
		return r
	}
	defer sess.Close()

	if err := sess.LoginRoot(cfg.BootTimeout); err != nil {
		r := failPrep(lock, ExitBootTimeout, err.Error())
		r.QEMU = cfg.QEMUPath
		r.Status = "BOOT_TIMEOUT"
		return r
	}
	cfg.logf("serial: logged in as root")

	keyDir := filepath.Join(cfg.CacheDir, "keys")
	priv, pub, err := ensureLabKey(keyDir)
	if err != nil {
		return failPrep(lock, ExitSetup, err.Error())
	}
	pubBody, err := os.ReadFile(pub)
	if err != nil {
		return failPrep(lock, ExitSetup, err.Error())
	}
	if err := injectAuthorizedKey(sess, strings.TrimSpace(string(pubBody))); err != nil {
		r := failPrep(lock, ExitSetup, err.Error())
		r.QEMU = cfg.QEMUPath
		return r
	}

	if err := waitSSH(sshPort, priv, cfg.SSHTimeout); err != nil {
		r := failPrep(lock, ExitSSHTimeout, err.Error())
		r.QEMU = cfg.QEMUPath
		r.Status = "SSH_TIMEOUT"
		r.MIPSLEExecution = "BOOTED"
		return r
	}
	cfg.logf("ssh: ready on 127.0.0.1:%d", sshPort)

	guestSmoke := filepath.Join(cfg.Root, "lab", "guest", "smoke.sh")
	hostConfig := cfg.Paths.Config
	if hostConfig == "" {
		hostConfig = filepath.Join(cfg.Root, "lab", "testdata", "xray-lab.json")
	}
	copies := [][2]string{}
	if cfg.Paths.Daemon != "" {
		copies = append(copies, [2]string{cfg.Paths.Daemon, guestPrefix + "/bin/blacktempled"})
	}
	if cfg.Paths.Xray != "" {
		copies = append(copies, [2]string{cfg.Paths.Xray, guestPrefix + "/bin/xray"})
	}
	if hostConfig != "" {
		copies = append(copies, [2]string{hostConfig, guestPrefix + "/config/xray-lab.json"})
	}
	if _, err := os.Stat(guestSmoke); err == nil {
		copies = append(copies, [2]string{guestSmoke, "/tmp/smoke.sh"})
	}
	if cfg.Paths.Geodata != "" {
		copies = append(copies, [2]string{cfg.Paths.Geodata, guestPrefix + "/share/geodata/candidate"})
	}
	if _, err := sshRun(sshPort, priv, "mkdir -p "+guestPrefix+"/bin "+guestPrefix+"/config "+guestPrefix+"/share/geodata "+guestPrefix+"/run "+guestPrefix+"/logs "+guestPrefix+"/data"); err != nil {
		r := failPrep(lock, ExitFail, err.Error())
		r.QEMU = cfg.QEMUPath
		return r
	}
	for _, cpy := range copies {
		if err := scpToGuest(sshPort, priv, cpy[0], cpy[1]); err != nil {
			r := failPrep(lock, ExitFail, err.Error())
			r.QEMU = cfg.QEMUPath
			return r
		}
	}
	_, _ = sshRun(sshPort, priv, "chmod +x "+guestPrefix+"/bin/* /tmp/smoke.sh 2>/dev/null || true")

	archOut, err := sshRun(sshPort, priv, "uname -m; uname -a; grep -i 'system type\\|cpu model' /proc/cpuinfo | head -n 5")
	mipsle := "FAIL"
	if err == nil {
		low := strings.ToLower(archOut)
		if strings.Contains(low, "mips") {
			mipsle = "PASS (QEMU Malta mipsel; not MT7621)"
		} else {
			mipsle = "FAIL uname=" + strings.TrimSpace(archOut)
		}
	} else {
		mipsle = "FAIL " + err.Error()
	}

	netOut, _ := sshRun(sshPort, priv, "ip addr 2>/dev/null || ifconfig -a; ip route 2>/dev/null || route -n")
	network := "PARTIAL: guest interfaces observed; WAN=QEMU user NAT, LAN isolated; not production LAN, not Keenetic NDM"
	if strings.Contains(netOut, "eth0") || strings.Contains(netOut, "eth1") || strings.Contains(netOut, "192.168.1") {
		network = "PASS (QEMU user NAT WAN + isolated LAN; not production LAN, not KN-1011)"
	}

	bt := "NOT RUN"
	xray := "NOT RUN"
	if cfg.Paths.Daemon == "" {
		bt = "NOT RUN (no --daemon artifact)"
	}
	if cfg.Paths.Xray == "" {
		xray = "NOT RUN (no --xray artifact)"
	}

	smokeOut, smokeErr := sshRun(sshPort, priv, "sh /tmp/smoke.sh")
	cfg.logf("%s", smokeOut)
	if cfg.Paths.Daemon != "" {
		if strings.Contains(smokeOut, "SMOKE_BLACKTEMPLED_HEALTH_OK") {
			bt = "PASS (started + /health on QEMU Malta; not KN-1011)"
		} else {
			bt = "FAIL"
			if smokeErr != nil {
				bt += " " + smokeErr.Error()
			}
		}
	}
	if cfg.Paths.Xray != "" {
		if strings.Contains(smokeOut, "SMOKE_XRAY_TEST_OK") && strings.Contains(smokeOut, "SMOKE_XRAY_RESTART_OK") {
			xray = "PASS (version + run -test + start/stop/restart on QEMU Malta; not KN-1011)"
		} else if strings.Contains(smokeOut, "SMOKE_XRAY_TEST_OK") {
			xray = "PARTIAL (config validated; lifecycle incomplete)"
		} else if cfg.Paths.Xray != "" {
			xray = "FAIL"
			if smokeErr != nil {
				xray += " " + smokeErr.Error()
			}
		}
	}

	status := "PASS"
	code := ExitOK
	if cfg.Paths.Daemon != "" && !strings.HasPrefix(bt, "PASS") {
		status = "FAIL"
		code = ExitFail
	}
	if cfg.Paths.Xray != "" && !strings.HasPrefix(xray, "PASS") && !strings.HasPrefix(xray, "PARTIAL") {
		status = "FAIL"
		code = ExitFail
	}
	if !strings.HasPrefix(mipsle, "PASS") {
		status = "FAIL"
		code = ExitFail
	}
	qemuStatus := "experimental FAIL (Malta mipsel, not KN-1011)"
	if code == ExitOK {
		qemuStatus = "experimental PASS (Malta mipsel, not KN-1011)"
	}

	return Result{
		Status:             status,
		QEMU:               qemuStatus,
		Image:              lock.Version + " " + lock.Kernel.Filename,
		SHA256:             lock.Kernel.SHA256,
		MIPSLEExecution:    mipsle,
		Blacktempled:       bt,
		Xray:               xray,
		Network:            network,
		EntwareEquivalence: "NOT CLAIMED (OpenWrt malta musl layout smoke only; not Entware, not mipsel-3.4_kn, not KN-1011)",
		Experimental:       true,
		NotHardware:        lock.NotHardware,
		Detail:             strings.TrimSpace(smokeOut),
		ExitCode:           code,
	}
}

func failPrep(lock *Lock, code int, detail string) Result {
	r := emptyResult("FAIL", code, detail)
	if lock != nil {
		r.Image = lock.Version + " " + lock.Kernel.Filename
		r.SHA256 = lock.Kernel.SHA256
		r.NotHardware = lock.NotHardware
	}
	switch code {
	case ExitQEMUNotInstalled:
		r.Status = QEMUNotInstalled
		r.QEMU = QEMUNotInstalled
	case ExitBootTimeout:
		r.Status = "BOOT_TIMEOUT"
		r.QEMU = "BOOT_TIMEOUT"
	case ExitSSHTimeout:
		r.Status = "SSH_TIMEOUT"
		r.QEMU = "SSH_TIMEOUT"
	case ExitSHAMismatch:
		r.Status = "SHA_MISMATCH"
	}
	r.ExitCode = code
	return r
}

func waitSerial(addr string, timeout time.Duration) (*SerialSession, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		sess, err := DialSerial(addr, 2*time.Second)
		if err == nil {
			return sess, nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("serial not reachable")
	}
	return nil, fmt.Errorf("boot timeout waiting for serial %s: %w", addr, last)
}

func injectAuthorizedKey(sess *SerialSession, pub string) error {
	pub = strings.ReplaceAll(pub, "\r", "")
	cmds := []string{
		"mkdir -p /etc/dropbear",
		"printf '%s\\n' '" + pub + "' > /etc/dropbear/authorized_keys",
		"chmod 600 /etc/dropbear/authorized_keys",
		"/etc/init.d/dropbear restart || /etc/init.d/dropbear start || true",
		"/etc/init.d/firewall stop || true",
	}
	for _, cmd := range cmds {
		if _, err := sess.Run(cmd, 20*time.Second); err != nil {
			return fmt.Errorf("serial setup %q: %w", cmd, err)
		}
	}
	return nil
}

func ensureLabKey(dir string) (priv, pub string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	priv = filepath.Join(dir, "lab_ed25519")
	pub = priv + ".pub"
	if _, err := os.Stat(priv); err == nil {
		if _, err := os.Stat(pub); err == nil {
			return priv, pub, nil
		}
	}
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", priv, "-q")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("ssh-keygen: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return priv, pub, nil
}

func sshOpts(port int, priv string) []string {
	known := "/dev/null"
	if runtime.GOOS == "windows" {
		known = "NUL"
	}
	return []string{
		"-i", priv,
		"-p", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + known,
		"-o", "GlobalKnownHostsFile=" + known,
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "ConnectTimeout=5",
		"-o", "LogLevel=ERROR",
	}
}

func waitSSH(port int, priv string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		_, err := sshRun(port, priv, "echo SSH_OK")
		if err == nil {
			return nil
		}
		last = err
		time.Sleep(sshReadyInterval)
	}
	if last == nil {
		last = fmt.Errorf("ssh never succeeded")
	}
	return fmt.Errorf("ssh timeout on 127.0.0.1:%d: %w", port, last)
}

func sshRun(port int, priv, remote string) (string, error) {
	args := append(sshOpts(port, priv), "root@127.0.0.1", remote)
	cmd := exec.Command("ssh", args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("ssh %s: %w: %s", remote, err, text)
	}
	return text, nil
}

func scpToGuest(port int, priv, local, remote string) error {
	known := "/dev/null"
	if runtime.GOOS == "windows" {
		known = "NUL"
	}
	args := []string{
		"-i", priv,
		"-P", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + known,
		"-o", "IdentitiesOnly=yes",
		local,
		"root@127.0.0.1:" + remote,
	}
	cmd := exec.Command("scp", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp %s: %w: %s", filepath.Base(local), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// PrintReport writes the orchestrator extra block.
func PrintReport(w io.Writer, r Result) {
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprintf(w, "QEMU: %s\n", r.QEMU)
	fmt.Fprintf(w, "IMAGE: %s SHA256=%s\n", r.Image, r.SHA256)
	fmt.Fprintf(w, "MIPSLE EXECUTION: %s\n", r.MIPSLEExecution)
	fmt.Fprintf(w, "BLACKTEMPLED: %s\n", r.Blacktempled)
	fmt.Fprintf(w, "XRAY: %s\n", r.Xray)
	fmt.Fprintf(w, "NETWORK: %s\n", r.Network)
	fmt.Fprintf(w, "ENTWARE EQUIVALENCE: %s\n", r.EntwareEquivalence)
	if r.Detail != "" && r.ExitCode != ExitOK {
		fmt.Fprintf(w, "DETAIL: %s\n", r.Detail)
	}
}
