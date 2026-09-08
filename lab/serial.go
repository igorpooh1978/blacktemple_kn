package lab

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// SerialSession is a QEMU TCP serial console.
type SerialSession struct {
	conn   net.Conn
	reader *bufio.Reader
	buf    strings.Builder
}

// DialSerial connects to QEMU serial TCP.
func DialSerial(addr string, timeout time.Duration) (*SerialSession, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &SerialSession{conn: conn, reader: bufio.NewReader(conn)}, nil
}

// Close closes the serial socket.
func (s *SerialSession) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// WaitFor reads until needle appears or timeout.
func (s *SerialSession) WaitFor(needle string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	_ = s.conn.SetReadDeadline(deadline)
	for {
		if strings.Contains(s.buf.String(), needle) {
			return s.buf.String(), nil
		}
		if time.Now().After(deadline) {
			snippet := s.buf.String()
			if len(snippet) > 800 {
				snippet = snippet[len(snippet)-800:]
			}
			return snippet, fmt.Errorf("serial timeout waiting for %q", needle)
		}
		b := make([]byte, 512)
		n, err := s.reader.Read(b)
		if n > 0 {
			s.buf.Write(b[:n])
			continue
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				snippet := s.buf.String()
				if len(snippet) > 800 {
					snippet = snippet[len(snippet)-800:]
				}
				return snippet, fmt.Errorf("serial timeout waiting for %q", needle)
			}
			return s.buf.String(), err
		}
	}
}

// SendLine writes line plus newline.
func (s *SerialSession) SendLine(line string) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := s.conn.Write([]byte(line + "\n"))
	return err
}

// LoginRoot waits for the OpenWrt console and logs in as root.
// OpenWrt's ash console prints "Please press Enter to activate this console"
// and does not show "login:" until a newline is sent.
func (s *SerialSession) LoginRoot(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	remain := func() time.Duration {
		r := time.Until(deadline)
		if r < time.Second {
			return time.Second
		}
		return r
	}
	for time.Now().Before(deadline) {
		chunk := 2 * time.Second
		if r := time.Until(deadline); r < chunk {
			if r <= 0 {
				break
			}
			chunk = r
		}
		got, err := s.WaitFor("login:", chunk)
		if err == nil && strings.Contains(got, "login:") {
			break
		}
		_ = s.SendLine("")
	}
	if !strings.Contains(s.buf.String(), "login:") {
		snippet := s.buf.String()
		if len(snippet) > 1200 {
			snippet = snippet[len(snippet)-1200:]
		}
		return fmt.Errorf("boot console: serial timeout waiting for %q; last output: %q", "login:", snippet)
	}
	if err := s.SendLine("root"); err != nil {
		return err
	}
	_, err := s.WaitFor("#", remain())
	return err
}

// Run runs cmd and waits for a shell prompt.
func (s *SerialSession) Run(cmd string, timeout time.Duration) (string, error) {
	before := s.buf.Len()
	if err := s.SendLine(cmd); err != nil {
		return "", err
	}
	out, err := s.WaitFor("#", timeout)
	if err != nil {
		return out, err
	}
	if before < len(out) {
		return out[before:], nil
	}
	return out, nil
}
