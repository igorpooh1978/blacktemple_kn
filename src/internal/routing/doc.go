// Package routing is the deterministic routing domain model and planner.
//
// This package does not apply rules to a router, does not execute iptables /
// ip rule / ip route / ipset, and does not import src/internal/xray.
// geoip/geosite references are preserved as opaque tags; .dat files are not
// resolved here.
package routing
