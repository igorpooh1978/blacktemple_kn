package connection

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	healthHost           = "www.gstatic.com"
	healthPath           = "/generate_204"
	maxCandidateAttempts = 16
)

// TunnelProbe waits for SOCKS and checks tunnel health. Nil probe skips checks (tests).
type TunnelProbe interface {
	WaitListener(ctx context.Context, host string, port int) error
	Check(ctx context.Context, host string, port int) error
}

type nopProbe struct{}

func (nopProbe) WaitListener(context.Context, string, int) error { return nil }
func (nopProbe) Check(context.Context, string, int) error        { return nil }

// RealProbe waits for 127.0.0.1:11080 and issues HTTPS generate_204 through SOCKS5.
type RealProbe struct {
	Timeout time.Duration
}

func NewRealProbe() RealProbe {
	return RealProbe{Timeout: 12 * time.Second}
}

func (p RealProbe) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 12 * time.Second
}

func (p RealProbe) WaitListener(ctx context.Context, host string, port int) error {
	deadline := time.Now().Add(5 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return fmt.Errorf("socks listener not ready")
}

func (p RealProbe) Check(ctx context.Context, host string, port int) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	raw, err := dialSOCKS5NoAuth(ctx, socksProxyAddr(host, port), healthHost, 443)
	if err != nil {
		return err
	}
	defer raw.Close()
	tlsConn := tls.Client(raw, &tls.Config{ServerName: healthHost, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	defer tlsConn.Close()
	req := "GET " + healthPath + " HTTP/1.1\r\nHost: " + healthHost + "\r\nConnection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return err
	}
	br := bufio.NewReader(tlsConn)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	var proto string
	var code int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%s %d", &proto, &code); err != nil {
		return err
	}
	if code != 204 && code != 200 {
		return fmt.Errorf("health status %d", code)
	}
	return nil
}
