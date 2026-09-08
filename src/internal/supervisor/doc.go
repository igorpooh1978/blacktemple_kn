package supervisor

// Package supervisor owns Xray child process lifecycle.
// Frozen states: STOPPED, STARTING, RUNNING, RELOADING, FAILED, BACKOFF.
//
// This package must not import internal/xray. Package C implements ProcessRunner
// with matching method set so the types are structurally compatible.
//
// Routing FAIL OPEN (iptables) is out of scope here.
