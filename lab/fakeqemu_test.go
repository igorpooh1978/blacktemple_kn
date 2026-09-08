package lab

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func parseSerialListenAddr(args []string) string {
	for i, a := range args {
		if a == "-serial" && i+1 < len(args) {
			spec := args[i+1]
			if strings.HasPrefix(spec, "tcp:") {
				spec = strings.TrimPrefix(spec, "tcp:")
				if idx := strings.Index(spec, ","); idx >= 0 {
					spec = spec[:idx]
				}
				return spec
			}
		}
	}
	return ""
}

func runFakeQEMU(mode string, args []string) {
	switch mode {
	case "silent":
		time.Sleep(2 * time.Minute)
		return
	case "serial-login":
		addr := parseSerialListenAddr(args)
		if addr == "" {
			fmt.Fprintln(os.Stderr, "fakeqemu: no -serial tcp addr")
			os.Exit(2)
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("Please press Enter to activate this console\n\nlogin: "))
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if line == "root" || line == "" {
				_, _ = conn.Write([]byte("\nroot@OpenWrt:~# "))
				continue
			}
			_, _ = conn.Write([]byte("ok\nroot@OpenWrt:~# "))
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown QEMULAB_HELPER", mode)
		os.Exit(2)
	}
}
