package protocols

import (
	"strings"
	"testing"
)

func TestHybridTransparentInboundNotSupported(t *testing.T) {
	row := HybridTransparentInbound()
	if !row.Generated {
		t.Fatal("hybrid inbound must be generated")
	}
	if row.Protocol != "tunnel" {
		t.Fatalf("protocol=%s", row.Protocol)
	}
	if row.Transport != "tcp+udp" {
		t.Fatalf("transport=%s", row.Transport)
	}
	if row.Hardware == "SUPPORTED" || row.XrayTest == "SUPPORTED" || row.QEMU == "SUPPORTED" {
		t.Fatalf("must not mark SUPPORTED without KN-1011 hardware PASS: %+v", row)
	}
	if row.Hardware != StatusNotRun {
		t.Fatalf("hardware must be NOT RUN: %+v", row)
	}
	if strings.Contains(row.Notes, "1181") && !strings.Contains(row.Notes, "never 1181") {
		t.Fatal("notes must forbid live XKeen port 1181")
	}
}

func TestP0MatrixNotSupported(t *testing.T) {
	rows := P0Matrix()
	if len(rows) == 0 {
		t.Fatal("empty matrix")
	}
	seenVLESS := false
	for _, row := range rows {
		if row.Protocol == "vless" {
			seenVLESS = true
		}
		if row.XrayTest == "SUPPORTED" || row.Hardware == "SUPPORTED" || row.QEMU == "SUPPORTED" {
			t.Fatalf("must not mark SUPPORTED without KN-1011 hardware PASS: %+v", row)
		}
		if row.Hardware != StatusNotRun {
			t.Fatalf("hardware must be NOT RUN: %+v", row)
		}
		if !row.Generated {
			t.Fatalf("P0 row should be generated: %+v", row)
		}
	}
	if !seenVLESS {
		t.Fatal("expected vless P0 rows")
	}
}
