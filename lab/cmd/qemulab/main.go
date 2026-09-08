package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/igorpooh1978/blacktemple_kn/lab"
)

func main() {
	action := flag.String("action", "test", "test | prepare | smoke")
	root := flag.String("root", "", "repository root (default: cwd)")
	lockPath := flag.String("lock", "", "lock json path")
	cacheDir := flag.String("cache", "", "image cache directory")
	allowHostLAN := flag.Bool("allow-host-lan", false, "explicit opt-in; still no tap/bridge to production LAN")
	daemon := flag.String("daemon", "", "host path to blacktempled mipsle")
	xray := flag.String("xray", "", "host path to xray_softfloat / xray mipsle")
	config := flag.String("config", "", "host path to xray JSON for run -test")
	geodata := flag.String("geodata", "", "optional geodata candidate path (never downloaded by CI)")
	flag.Parse()

	cfg := lab.LabConfig{
		Root:         *root,
		LockPath:     *lockPath,
		CacheDir:     *cacheDir,
		AllowHostLAN: *allowHostLAN,
		Paths: lab.Paths{
			Daemon:  *daemon,
			Xray:    *xray,
			Config:  *config,
			Geodata: *geodata,
		},
		Stdout: os.Stdout,
	}

	os.Setenv("CGO_ENABLED", "0")

	switch *action {
	case "test":
		fmt.Fprintln(os.Stderr, "qemulab -action=test: run: go test ./lab/... from the repo root")
		os.Exit(lab.ExitSetup)
	case "prepare":
		_, _, _, r := lab.Prepare(&cfg)
		lab.PrintReport(os.Stdout, r)
		os.Exit(r.ExitCode)
	case "smoke":
		r := lab.Smoke(cfg)
		lab.PrintReport(os.Stdout, r)
		os.Exit(r.ExitCode)
	default:
		fmt.Fprintf(os.Stderr, "unknown action %s\n", *action)
		os.Exit(lab.ExitSetup)
	}
}
