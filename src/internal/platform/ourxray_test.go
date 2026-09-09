package platform

import "testing"

func TestForeignXrayIsNeverOurs(t *testing.T) {
	if IsOurXrayExecutable(ForeignXrayExecutable, DefaultXrayPath) {
		t.Fatal("/opt/sbin/xray must not be OUR Xray")
	}
	if IsOurXrayExecutable("/opt/sbin/xray", DefaultXrayPath) {
		t.Fatal("foreign path")
	}
	if !IsOurXrayExecutable(DefaultXrayPath, DefaultXrayPath) {
		t.Fatal("OUR path must match")
	}
}
