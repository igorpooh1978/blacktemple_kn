package lab

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLoginRootPressEnter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("Please press Enter to activate this console\n")); err != nil {
			done <- err
			return
		}
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			switch strings.TrimSpace(line) {
			case "":
				if _, err := conn.Write([]byte("\nlogin: ")); err != nil {
					done <- err
					return
				}
			case "root":
				if _, err := conn.Write([]byte("\nroot@OpenWrt:~# ")); err != nil {
					done <- err
					return
				}
				done <- nil
				return
			}
		}
	}()
	sess, err := DialSerial(ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.LoginRoot(8 * time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("console helper did not finish")
	}
}
