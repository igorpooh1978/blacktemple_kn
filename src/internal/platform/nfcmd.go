package platform

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/routing"
)

// NFCommand is the blacktempled netfilter-reconcile invocation.
// Production never stops XKeen from this path.
type NFCommand struct {
	Stop        bool
	Prefix      string
	Client      string
	ClientFile  string
	ManagerPath string
	XrayPath    string
	ConfigPath  string
	StateJSON   []byte
	Network     *NetworkStatus
	Alive       func() bool
	Exec        routing.Executor
	NewEngine   func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error)
	RouterAddrs []netip.Addr
}

// ExecuteNetfilterReconcile is the manager entrypoint for NDM hook and stop/uninstall.
func ExecuteNetfilterReconcile(ctx context.Context, cmd NFCommand) error {
	if cmd.Prefix == "" {
		cmd.Prefix = PrefixDir
	}
	if cmd.ManagerPath == "" {
		cmd.ManagerPath = DefaultManagerPath
	}
	if cmd.XrayPath == "" {
		cmd.XrayPath = DefaultXrayPath
	}
	if cmd.ClientFile == "" {
		cmd.ClientFile = filepath.Join(cmd.Prefix, "data", "selected-client")
	}
	if cmd.ConfigPath == "" {
		cmd.ConfigPath = filepath.Join(cmd.Prefix, "data", "run", "xray.json")
	}
	if cmd.Exec == nil {
		cmd.Exec = routing.CommandExecutor{}
	}
	if cmd.NewEngine == nil {
		cmd.NewEngine = func(client netip.Addr, exec routing.Executor) (routing.TrafficCaptureEngine, error) {
			return routing.NewHybridIptablesEngine(client, exec, routing.PermitAllGuard{})
		}
	}

	alive := cmd.Alive
	if alive == nil {
		alive = func() bool {
			_, _, ok := FindOurXrayProcess(cmd.XrayPath)
			return ok
		}
	}

	netStatus := NetworkStatus{
		OptMounted:     true,
		DefaultRoute:   true,
		LANAvailable:   true,
		XrayExecutable: fileExecutable(cmd.XrayPath),
	}
	if cmd.Network != nil {
		netStatus = *cmd.Network
	}

	stateJSON := cmd.StateJSON
	if len(stateJSON) == 0 && alive() {
		stateJSON = []byte(`{"state":"RUNNING"}`)
	}

	dec := Reconcile(ReconcileInput{
		Stop:        cmd.Stop,
		ManagerPath: cmd.ManagerPath,
		XrayPath:    cmd.XrayPath,
		ConfigPath:  cmd.ConfigPath,
		StateJSON:   stateJSON,
		Network:     netStatus,
		Alive:       alive,
	})

	if cmd.RouterAddrs == nil && runtime.GOOS == "linux" {
		cmd.RouterAddrs = ListRouterIPv4()
	}

	client, clientErr := ParseSelectedClient(loadClientString(cmd))
	if clientErr == nil && len(cmd.RouterAddrs) > 0 {
		clientErr = RejectRouterAddress(client, cmd.RouterAddrs)
	}

	desired := !cmd.Stop && dec.Decision == DecisionDesiredPresent && clientErr == nil
	engClient := client
	if !engClient.IsValid() {
		engClient = netip.MustParseAddr("10.0.0.2")
	}
	eng, err := cmd.NewEngine(engClient, cmd.Exec)
	if err != nil {
		return err
	}
	if setter, ok := eng.(interface {
		SetExpectedListener(routing.ExpectedListener)
	}); ok {
		setter.SetExpectedListener(routing.ExpectedListener{Executable: cmd.XrayPath})
	}

	if err := eng.Reconcile(ctx, desired); err != nil {
		return err
	}
	if cmd.Stop {
		return nil
	}
	if dec.Decision == DecisionDesiredPresent && clientErr != nil {
		return clientErr
	}
	return nil
}

// WriteSelectedClient stores the /32 client used by netfilter-reconcile.
func WriteSelectedClient(path string, addr netip.Addr) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(addr.String()+"\n"), 0o644)
}
