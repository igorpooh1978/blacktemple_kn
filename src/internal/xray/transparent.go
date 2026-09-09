package xray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// DefaultTransparentPort is the hybrid tunnel listen port for iptables
// REDIRECT (TCP) and TPROXY (UDP). It is not 1181 (live XKeen).
const DefaultTransparentPort = 11820

// ErrTransparentPortInUse is returned when the transparent inbound port is
// already bound. The occupying process is left running.
var ErrTransparentPortInUse = errors.New("transparent inbound port is already in use")

func validateTransparent(opts Options) error {
	if !opts.Transparent {
		return nil
	}
	port := opts.TransparentPort
	if port == xkeenLivePort {
		return fmt.Errorf("transparent port %d is reserved for live XKeen", xkeenLivePort)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("transparent listen port must be 1-65535")
	}
	if !opts.EphemeralPort && port == opts.ListenPort {
		return fmt.Errorf("transparent listen port collides with socks inbound port")
	}
	return nil
}

func transparentPortInUse(host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return true
	}
	_ = ln.Close()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return true
	}
	_ = pc.Close()
	return false
}

// StartTransparent is Start for hybrid transparent mode. It refuses to bind if
// the dokodemo port is occupied and does not kill the other process.
func (r *Runner) StartTransparent(ctx context.Context, configPath string, port int) error {
	if port == 0 {
		port = DefaultTransparentPort
	}
	if port == xkeenLivePort {
		return fmt.Errorf("transparent port %d is reserved for live XKeen", xkeenLivePort)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("transparent listen port must be 1-65535")
	}
	if transparentPortInUse(transparentListen, port) {
		return ErrTransparentPortInUse
	}
	return r.Start(ctx, configPath)
}
