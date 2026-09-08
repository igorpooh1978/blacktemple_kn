// Package remotepolicy parses and stores typed remote settings.
//
// Remote policy is not a remote shell. Output is typed Settings only.
// Known x-* keys from APK evidence are parsed; unknown keys are ignored and
// reported; invalid values on known keys reject the document.
//
// Precedence: built-in default < provider remote default < local user override
// < temporary session override. Remote cannot silently overwrite an explicit
// local or session override.
//
// Origin must be an explicitly trusted provider origin or a user-configured
// trusted source. Integrity is honest: TLS_ONLY, CHECKSUM_PINNED, or
// SIGNATURE_VERIFIED. HTTPS is not a content signature.
//
// This package never execs, opens a shell, writes or deletes arbitrary files,
// changes iptables, installs packages, changes an admin password, enables
// WAN UI, restarts a Linux service, or downloads and runs an executable.
// blockQUIC is stored as a boolean field; no firewall rules are emitted.
package remotepolicy
