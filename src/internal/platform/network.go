package platform

import (
	"bufio"
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"
)

// ErrNetworkNotReady is returned when WaitNetworkReady's context ends first.
var ErrNetworkNotReady = errors.New("platform: network not ready")

// NetworkStatus is the R6 start/capture readiness snapshot.
// XrayExecutable here means our binary exists; liveness is a separate check.
type NetworkStatus struct {
	OptMounted     bool
	DefaultRoute   bool
	LANAvailable   bool
	XrayExecutable bool
}

// Ready is true only when all four conditions hold. Not a fixed sleep.
func (s NetworkStatus) Ready() bool {
	return s.OptMounted && s.DefaultRoute && s.LANAvailable && s.XrayExecutable
}

// Backoff is the wait loop schedule. Initial/Max of 30s with no condition
// checks is forbidden: callers must probe between sleeps.
type Backoff struct {
	Initial time.Duration
	Max     time.Duration
	Factor  float64
}

// NetworkReadyTimeout is the recommended WaitNetworkReady context budget.
// It is not a single sleep 30.
const NetworkReadyTimeout = 30 * time.Second

// DefaultBackoff is a short exponential wait, capped well below a blind 30s sleep.
func DefaultBackoff() Backoff {
	return Backoff{
		Initial: 200 * time.Millisecond,
		Max:     2 * time.Second,
		Factor:  2,
	}
}

func (b Backoff) normalized() Backoff {
	if b.Initial <= 0 {
		b.Initial = 200 * time.Millisecond
	}
	if b.Max <= 0 {
		b.Max = 2 * time.Second
	}
	if b.Factor < 1 {
		b.Factor = 2
	}
	if b.Max < b.Initial {
		b.Max = b.Initial
	}
	return b
}

func (b Backoff) next(cur time.Duration) time.Duration {
	next := time.Duration(float64(cur) * b.Factor)
	if next > b.Max || next < cur {
		return b.Max
	}
	return next
}

// WaitNetworkReady probes until status.Ready or ctx is done.
// probe may be nil (uses ProbeNetwork). This is not `sleep 30`.
func WaitNetworkReady(ctx context.Context, probe func() NetworkStatus, b Backoff) error {
	if ctx == nil {
		return errors.New("platform: nil context")
	}
	if probe == nil {
		probe = ProbeNetwork
	}
	b = b.normalized()
	delay := b.Initial
	for {
		if probe().Ready() {
			return nil
		}
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return ErrNetworkNotReady
			}
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrNetworkNotReady
		case <-timer.C:
		}
		delay = b.next(delay)
	}
}

// ProbeNetwork reads Keenetic/Linux evidence points. On non-Linux it returns
// all-false (tests inject a fake probe).
func ProbeNetwork() NetworkStatus {
	return NetworkStatus{
		OptMounted:     optMounted(),
		DefaultRoute:   defaultRouteExists(),
		LANAvailable:   lanAvailable(),
		XrayExecutable: fileExecutable(DefaultXrayPath),
	}
}

func optMounted() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[1] == EntwareRoot {
			_, err := os.Stat(EntwareRoot + "/etc")
			return err == nil
		}
	}
	return false
}

func defaultRouteExists() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[1] == "00000000" {
			return true
		}
	}
	return false
}

func lanAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// KN-1011 probe: LAN bridges br0/br1 present. Do not invent NDM ifaces.
	if dirExists("/sys/class/net/br0") || dirExists("/sys/class/net/br1") {
		return true
	}
	return false
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func fileExecutable(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return fi.Mode()&0o111 != 0
}
