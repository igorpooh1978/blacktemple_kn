package keenetic

import "testing"

func TestPolicyGuardNeverGrantsKeeneticDeniedInternet(t *testing.T) {
	var g PolicyGuard
	if g.CaptureMayGrantDeniedInternet() {
		t.Fatal("stub must not report that capture may grant Keenetic-denied internet")
	}
	if !g.HonorDeny() {
		t.Fatal("stub must honor Keenetic deny")
	}
	if DenyFwmark != "0xffffaaa" {
		t.Fatalf("DenyFwmark %q (want observed 0xffffaaa)", DenyFwmark)
	}
}
