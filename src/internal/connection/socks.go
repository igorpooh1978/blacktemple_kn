package connection

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// dialSOCKS5NoAuth opens destHost:destPort through a SOCKS5 no-auth proxy.
func dialSOCKS5NoAuth(ctx context.Context, proxyAddr, destHost string, destPort int) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	if t, ok := ctx.Deadline(); ok {
		deadline = t
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var greet [2]byte
	if _, err := io.ReadFull(conn, greet[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: method 0x%02x", greet[1])
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}
	req = append(req, destHost...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(destPort))
	req = append(req, port[:]...)
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: connect status 0x%02x", hdr[1])
	}
	switch hdr[3] {
	case 0x01:
		if _, err := io.CopyN(io.Discard, conn, 4+2); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, err := io.CopyN(io.Discard, conn, int64(n[0])+2); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case 0x04:
		if _, err := io.CopyN(io.Discard, conn, 16+2); err != nil {
			_ = conn.Close()
			return nil, err
		}
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: atyp 0x%02x", hdr[3])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socksProxyAddr(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
