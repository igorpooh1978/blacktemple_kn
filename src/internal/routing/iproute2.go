package routing

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
)

// Entware ip-full ships the real binary as ip-full. iproute2 uses basename(argv0)
// as the object family, so invoking the file as "ip-full" fails with
// `Object "-full" is unknown`. Production exec must keep argv0 "ip".
const (
	IPRoute2FullBinary        = "/opt/libexec/ip-full"
	UDPCaptureSupported       = "SUPPORTED"
	UDPCaptureUnsupported     = "UNSUPPORTED"
	ClassIPRoute2FullRequired = "IPROUTE2_FULL_REQUIRED"
)

var ErrIPRoute2FullRequired = errors.New("routing: IPROUTE2_FULL_REQUIRED")

// defaultIPRoute2Candidates is the Entware-proven order. PATH "ip" is not
// listed: on KN-1011 it is BusyBox until ip-full replaces the symlink.
func defaultIPRoute2Candidates() []string {
	return []string{
		IPRoute2FullBinary,
		"/opt/sbin/ip",
	}
}

func argv0For(name string) string {
	if filepath.Base(name) == "ip-full" {
		return "ip"
	}
	return name
}

func isBusyBoxIPVersion(out string) bool {
	return strings.Contains(strings.ToLower(out), "busybox")
}

func policyRoutingCapable(out string, err error) bool {
	msg := strings.ToLower(strings.TrimSpace(out))
	if err != nil {
		msg = strings.ToLower(err.Error() + " " + msg)
	}
	if isBusyBoxIPVersion(msg) {
		return false
	}
	if strings.Contains(msg, "invalid argument") && strings.Contains(msg, strconv.Itoa(RouteTable)) {
		return false
	}
	if strings.Contains(msg, "object") && strings.Contains(msg, "-full") {
		return false
	}
	for _, tok := range []string{
		"executable file not found",
		"no such file",
		"not found",
		"permission denied",
	} {
		if strings.Contains(msg, tok) {
			return false
		}
	}
	return true
}

// ResolveIPRoute2 picks a full iproute2 binary that can address table 4254.
// configured, if non-empty, is tried first. BusyBox is never selected.
// Missing full iproute2 is fail-closed for UDP (ok=false), not an error.
func ResolveIPRoute2(ctx context.Context, exec Executor, configured string) (path string, ok bool) {
	if exec == nil {
		return "", false
	}
	var cands []string
	if strings.TrimSpace(configured) != "" {
		cands = append(cands, strings.TrimSpace(configured))
	}
	cands = append(cands, defaultIPRoute2Candidates()...)
	seen := map[string]bool{}
	for _, p := range cands {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if ipRoute2Capable(ctx, exec, p) {
			return p, true
		}
	}
	return "", false
}

func ipRoute2Capable(ctx context.Context, exec Executor, path string) bool {
	ver, _ := exec.Run(ctx, path, "-V")
	if isBusyBoxIPVersion(ver) {
		return false
	}
	out, err := exec.Run(ctx, path, "-4", "route", "show", "table", strconv.Itoa(RouteTable))
	if isBusyBoxIPVersion(out) {
		return false
	}
	return policyRoutingCapable(out, err)
}
