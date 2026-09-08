// Package xray generates a deterministic Xray-core JSON config and runs a
// pinned external executable. Xray is not imported as a Go library.
//
// Process policy (backoff, restart) belongs to the supervisor package, not here.
package xray
