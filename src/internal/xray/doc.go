// Package xray generates a deterministic Xray-core JSON config and runs a
// pinned external executable. Xray is not imported as a Go library.
//
// Default Generate emits a SOCKS inbound on 127.0.0.1:11080. Options.Transparent
// adds a hybrid dokodemo-door inbound (followRedirect + sockopt.tproxy=tproxy)
// on 127.0.0.1:11820 for iptables REDIRECT and TPROXY. It does not replace SOCKS.
//
// Process policy (backoff, restart) belongs to the supervisor package, not here.
package xray
