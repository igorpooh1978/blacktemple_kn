package main

import (
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/app"
)

var version = "0.1.0-dev"

func main() {
	listen := flag.String("listen", "127.0.0.1:7480", "HTTP listen address (host used in explicit mode; port used in all modes)")
	listenMode := flag.String("listen-mode", "loopback", "listen mode: loopback | auto-lan | explicit")
	dataDir := flag.String("data-dir", "data", "local data directory for auth hash and runtime files")
	flag.Parse()

	a, err := app.New(app.Config{
		Listen:     *listen,
		ListenMode: *listenMode,
		DataDir:    *dataDir,
		Version:    version,
		UI:         uiFS(),
		// Connection and Profiles are wired in app.New (profiles + Xray + supervisor).
		// LAN resolver stays nil until platform wiring (auto-lan → loopback).
	})
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              a.Addr(),
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", a.Addr())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("blacktempled %s listening on %s", version, ln.Addr())
	log.Fatal(srv.Serve(ln))
}

func uiFS() fs.FS {
	sub, err := fs.Sub(embeddedUI, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}
