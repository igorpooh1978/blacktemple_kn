package main

import (
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

var version = "0.1.0-dev"

func main() {
	listen := flag.String("listen", "127.0.0.1:7480", "HTTP listen address (LAN only in production)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/v1/version", handleVersion)
	mux.HandleFunc("/api/v1/status", handleStatus)
	mux.HandleFunc("/api/v1/connection", handleNotImplemented)
	mux.HandleFunc("/api/v1/profiles", handleNotImplemented)
	mux.HandleFunc("/api/v1/auth/setup", handleNotImplemented)
	mux.HandleFunc("/api/v1/auth/login", handleNotImplemented)
	mux.HandleFunc("/api/v1/auth/logout", handleNotImplemented)
	mux.Handle("/", http.FileServer(http.FS(uiFS())))

	srv := &http.Server{
		Addr:              *listen,
		Handler:           withSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("blacktempled %s listening on %s goos=%s goarch=%s cgo=%s", version, ln.Addr(), runtime.GOOS, runtime.GOARCH, cgoValue())
	log.Fatal(srv.Serve(ln))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"version": version,
		"goos":    runtime.GOOS,
		"goarch":  runtime.GOARCH,
		"gomips":  os.Getenv("GOMIPS"),
		"cgo":     cgoValue(),
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"connection": "disconnected",
		"country":    "",
		"latencyMs":  nil,
		"routing":    "smart",
		"serverMode": "auto",
		"key":        "missing",
		"geodata":    "missing",
		"xray": map[string]any{
			"state":        "STOPPED",
			"pid":          nil,
			"version":      "",
			"restartCount": 0,
		},
	})
}

func handleNotImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "not implemented in hello-service",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func uiFS() fs.FS {
	sub, err := fs.Sub(embeddedUI, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}

func cgoValue() string {
	if strings.TrimSpace(os.Getenv("CGO_ENABLED")) == "1" {
		return "1"
	}
	return "0"
}
