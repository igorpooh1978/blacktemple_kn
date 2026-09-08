package api

import (
	"net/http"
	"net/url"
	"strings"
)

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		return originMatchesHost(origin, r.Host)
	}
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref != "" {
		return originMatchesHost(ref, r.Host)
	}
	return true
}

func originMatchesHost(raw, host string) bool {
	if raw == "null" || host == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}
