// Package remotelists downloads, validates, and caches typed remote lists.
//
// Supported list types: domains, CIDRs, countries, servers, telegram-ips,
// whatsapp-ips, provider-routing, geosite-catalog. Entries keep metadata
// (line, canonical value); callers must not treat a list as a bare []string.
//
// Update workflow: read cache → conditional GET (If-None-Match /
// If-Modified-Since) → size-capped read (io.LimitReader) → validate →
// checksum if pinned → write candidate → fsync → atomic replace.
// HTTP 304 reuses the cache. Network failure returns last-known-good when
// present. Ordinary refresh/backoff intervals are hours or days, not seconds.
//
// SSRF: default HTTPS only; dial and redirect check the resolved destination
// (not a hostname allowlist). Loopback, link-local, multicast, unspecified,
// RFC1918, unique-local, and router-local addresses are blocked unless the
// descriptor sets TrustedOrigin (trusted-local). file://, ftp://, data:,
// unix, and other arbitrary schemes are denied.
//
// Telegram/WhatsApp list IDs are typed names only. IP/CIDR values come from
// the remote body and are never hardcoded from the reference APK.
//
// Countries, servers, provider-routing, and geosite-catalog have cache
// infrastructure. Their provider payload parsers are absent until a format
// is proven: Parse returns "PROVIDER FORMAT: NOT IMPLEMENTED".
//
// This package does not apply iptables, execute list contents, download
// executables, or call a proprietary BlackTemple provider API.
package remotelists
