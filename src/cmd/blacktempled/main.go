package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/app"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/platform"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

var version = "0.1.0-dev"

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func dispatch(args []string) error {
	if len(args) > 0 && args[0] == platform.NetfilterReconcileArg {
		stop := len(args) > 1 && args[1] == platform.NetfilterReconcileStopArg
		ctx, cancel := context.WithTimeout(context.Background(), platform.NetfilterReconcileTimeout)
		defer cancel()
		return platform.ExecuteNetfilterReconcile(ctx, platform.NFCommand{Stop: stop})
	}
	if len(args) > 0 && args[0] == "xray-start" {
		return runXrayStart(args[1:])
	}
	if len(args) > 0 && args[0] == "xray-stop" {
		return runXrayStop()
	}

	fs := flag.NewFlagSet("blacktempled", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:7480", "HTTP listen address (host used in explicit mode; port used in all modes)")
	listenMode := fs.String("listen-mode", "auto-lan", "listen mode: loopback | auto-lan | explicit")
	dataDir := fs.String("data-dir", "data", "local data directory for auth hash and runtime files")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_ = platform.EnsureCaptureConfig(platform.CaptureConfigPath(platform.PrefixDir))

	a, err := app.New(app.Config{
		Listen:     *listen,
		ListenMode: *listenMode,
		DataDir:    *dataDir,
		Version:    version,
		UI:         uiFS(),
		LAN:        platform.BridgeLAN{},
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              a.Addr(),
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", a.Addr())
	if err != nil {
		return err
	}
	log.Printf("blacktempled %s listening on %s", version, ln.Addr())
	return srv.Serve(ln)
}

func runXrayStart(args []string) error {
	fs := flag.NewFlagSet("xray-start", flag.ContinueOnError)
	cfg := fs.String("c", platform.PrefixDir+"/data/run/xray.json", "Xray JSON config")
	exe := fs.String("exe", platform.DefaultXrayPath, "OUR Xray executable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !platform.IsOurXrayExecutable(*exe, platform.DefaultXrayPath) {
		return fmt.Errorf("refusing foreign Xray %s", *exe)
	}
	r := &xray.Runner{Executable: *exe, Detach: true}
	if err := r.StartTransparent(context.Background(), *cfg, xray.DefaultTransparentPort); err != nil {
		return err
	}
	pid := r.PID()
	if err := os.MkdirAll(platform.PrefixDir+"/run", 0o755); err != nil {
		return err
	}
	return os.WriteFile(platform.PrefixDir+"/run/our-xray.pid", []byte(fmt.Sprintf("%d\n", pid)), 0o644)
}

func runXrayStop() error {
	b, err := os.ReadFile(platform.PrefixDir + "/run/our-xray.pid")
	if err != nil {
		return nil
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid); err != nil || pid <= 0 {
		return nil
	}
	info := platform.InspectPID(pid)
	if !info.Alive {
		_ = os.Remove(platform.PrefixDir + "/run/our-xray.pid")
		return nil
	}
	if !platform.IsOurXrayExecutable(info.Executable, platform.DefaultXrayPath) {
		return fmt.Errorf("refusing to stop foreign pid %d exe=%s", pid, info.Executable)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = proc.Kill()
	_ = os.Remove(platform.PrefixDir + "/run/our-xray.pid")
	return nil
}

func uiFS() fs.FS {
	sub, err := fs.Sub(embeddedUI, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}
