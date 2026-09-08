package app

import (
	"fmt"
	"net"
	"strings"
)

const (
	defaultListenHost = "127.0.0.1"
	defaultListenPort = "7480"
)

// ResolveListen maps listenMode to a bind address.
// auto-lan without a safe LAN host fails closed to loopback and never 0.0.0.0.
func ResolveListen(mode, listen string, lan LANResolver) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		mode = "loopback"
	}
	_, port, err := splitListen(listen)
	if err != nil {
		return "", err
	}
	switch mode {
	case "loopback":
		return net.JoinHostPort(defaultListenHost, port), nil
	case "auto-lan":
		host := lanHostOrEmpty(lan)
		if !safeBindHost(host) {
			return net.JoinHostPort(defaultListenHost, port), nil
		}
		return net.JoinHostPort(host, port), nil
	case "explicit":
		host, port, err := splitListen(listen)
		if err != nil {
			return "", err
		}
		if host == "" {
			host = defaultListenHost
		}
		if isUnspecifiedHost(host) {
			return "", fmt.Errorf("refusing unspecified bind address")
		}
		return net.JoinHostPort(host, port), nil
	default:
		return "", fmt.Errorf("unknown listen-mode %q", mode)
	}
}

func splitListen(listen string) (host, port string, err error) {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return defaultListenHost, defaultListenPort, nil
	}
	host, port, err = net.SplitHostPort(listen)
	if err != nil {
		return "", "", fmt.Errorf("invalid listen address")
	}
	if port == "" {
		port = defaultListenPort
	}
	return host, port, nil
}

func lanHostOrEmpty(lan LANResolver) string {
	if lan == nil {
		return ""
	}
	h, err := lan.LANHost()
	if err != nil || h == "" {
		return ""
	}
	h = strings.TrimSpace(h)
	if h2, _, err := net.SplitHostPort(h); err == nil {
		h = h2
	}
	return h
}

func safeBindHost(host string) bool {
	if host == "" || isUnspecifiedHost(host) {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	return ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func isUnspecifiedHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "0.0.0.0", "::", "[::]", "*":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
