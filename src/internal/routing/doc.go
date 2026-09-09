// Package routing is the deterministic routing domain model, planner, and
// IPv4 hybrid iptables traffic capture engine.
//
// The planner (Build) does not execute iptables / ip rule / ip route / ipset.
// HybridIptablesEngine applies BlackTemple-owned BTKN_ hooks through an
// Executor using fixed argv (never a shell). This package must not import
// src/internal/xray. geoip/geosite references are preserved as opaque tags;
// .dat files are not resolved here. IPv6 capture is UNVERIFIED; R6 is IPv4 only.
package routing
