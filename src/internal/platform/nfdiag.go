package platform

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// ReconcileOrigin is manual unless the NDM hook exported BTKN_NDM_HOOK=1.
func ReconcileOrigin() string {
	if getenv(NDMHookEnv) == "1" {
		return "ndm"
	}
	return "manual"
}

func clientDiag(raw string, addr netip.Addr, err error) string {
	if err == nil && addr.IsValid() {
		return addr.String()
	}
	if strings.TrimSpace(raw) == "" {
		return "MISSING"
	}
	return "INVALID"
}

func formatReconcileDiag(origin, decision, reason, client, action, result string, desired, alive, captureEnabled bool) string {
	return fmt.Sprintf(
		"origin=%s capture_enabled=%t decision=%s reason=%s desired=%t client=%s our_xray_alive=%t action=%s result=%s",
		origin, captureEnabled, decision, reason, desired, client, alive, action, result,
	)
}

func writeLockFailedDiag(cmd NFCommand) {
	fmt.Fprintln(os.Stderr, formatReconcileDiag(
		ReconcileOrigin(),
		string(DecisionDesiredAbsent),
		ReasonLockFailed,
		"MISSING",
		"none",
		"failure",
		false,
		false,
		resolveCaptureEnabled(cmd),
	))
}
