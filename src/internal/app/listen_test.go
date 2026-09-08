package app

import (
	"net"
	"strings"
	"testing"
)

type fakeLAN struct {
	host string
	err  error
}

func (f fakeLAN) LANHost() (string, error) { return f.host, f.err }

func TestAutoLANWithoutResolverBindsLoopback(t *testing.T) {
	addr, err := ResolveListen("auto-lan", "127.0.0.1:7480", nil)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7480" {
		t.Fatalf("got %s", addr)
	}
	if strings.Contains(addr, "0.0.0.0") {
		t.Fatal("must never bind 0.0.0.0")
	}
}

func TestAutoLANUnspecifiedResolverFailsClosed(t *testing.T) {
	addr, err := ResolveListen("auto-lan", "192.168.1.1:7480", fakeLAN{host: "0.0.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("expected loopback, got %s", addr)
	}
	if strings.Contains(addr, "0.0.0.0") {
		t.Fatal("must never bind 0.0.0.0")
	}
}

func TestLoopbackIgnoresNonLocalHost(t *testing.T) {
	addr, err := ResolveListen("loopback", "192.168.1.50:7480", nil)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7480" {
		t.Fatalf("got %s", addr)
	}
}

func TestExplicitRefusesUnspecified(t *testing.T) {
	if _, err := ResolveListen("explicit", "0.0.0.0:7480", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestAutoLANSafeHost(t *testing.T) {
	addr, err := ResolveListen("auto-lan", "127.0.0.1:7480", fakeLAN{host: "192.168.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if addr != "192.168.1.1:7480" {
		t.Fatalf("got %s", addr)
	}
}
