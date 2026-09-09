// Package dns is the DNS policy/model only.
//
// It does not start a DNS daemon, does not intercept system resolvers, and
// does not change router DNS settings. Proxy DNS is a planned Xray resolver
// target, not a process spawned here. DNSCaptureEngine is an empty seam:
// :53 intercept is not implemented in this wave.
package dns
