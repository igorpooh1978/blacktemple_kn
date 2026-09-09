package xray

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestStartTransparentPortInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	r := &Runner{Executable: "xray.exe"}
	err = r.StartTransparent(context.Background(), "config.json", port)
	if !errors.Is(err, ErrTransparentPortInUse) {
		t.Fatalf("got %v want ErrTransparentPortInUse", err)
	}

	c, dialErr := net.Dial("tcp", ln.Addr().String())
	if dialErr != nil {
		t.Fatalf("occupying listener was disrupted: %v", dialErr)
	}
	c.Close()
}

func TestStartTransparentRejectsXKeenPort(t *testing.T) {
	r := &Runner{Executable: "xray.exe"}
	err := r.StartTransparent(context.Background(), "config.json", 1181)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrTransparentPortInUse) {
		t.Fatal("1181 must fail as reserved, not occupancy")
	}
	if !strings.Contains(err.Error(), "1181") {
		t.Fatalf("error %q does not mention 1181", err)
	}
}

func TestTransparentPortInUseUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if !transparentPortInUse("127.0.0.1", port) {
		t.Fatal("expected UDP occupancy to be detected")
	}
}
