// Package xray generates a deterministic Xray-core JSON config and runs a
// pinned external executable. Xray is not imported as a Go library.
//
// Default Generate emits a SOCKS inbound on 127.0.0.1:11080. Options.Transparent
// adds two tunnel inbounds on 0.0.0.0:11820: redirect-in (TCP, followRedirect,
// no tproxy sockopt) and tproxy-in (UDP, followRedirect, sockopt.tproxy=tproxy).
// SOCKS is not replaced. Direct LAN connect to :11820 is not a SOCKS/HTTP proxy.
//
// Process policy (backoff, restart) belongs to the supervisor package, not here.
package xray
