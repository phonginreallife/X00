// KernelSeal - Kubernetes agent for secret protection using eBPF and BPF-LSM
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"kernelseal/internal"
	"kernelseal/internal/bpf"
	"kernelseal/internal/logging"
	"kernelseal/internal/metrics"
	"kernelseal/internal/protocol"
	"kernelseal/internal/reconcile"
	"kernelseal/internal/secrets"
	"kernelseal/internal/server"
	"kernelseal/internal/types"
)

const (
	defaultExecMonitorPath = "bpf/exec_monitor.bpf.o"
	defaultLSMPath         = "bpf/lsm_file_protect.bpf.o"
	defaultConfigPath      = "/etc/kernelseal/config.yaml"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	configPath := flag.String("config", defaultConfigPath, "Path to KernelSeal configuration file")
	execMonitorPath := flag.String("exec-monitor", defaultExecMonitorPath, "Path to exec monitor BPF object")
	lsmPath := flag.String("lsm", defaultLSMPath, "Path to LSM BPF object")
	socketPath := flag.String("socket", protocol.DefaultSocketPath, "Path to the secret delivery socket")
	socketMode := flag.Uint("socket-mode", 0o660, "File mode for the secret delivery socket")
	socketGroup := flag.String("socket-group", "",
		"Group (name or GID) to own the secret delivery socket, so unprivileged callers can reach it")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("kernelseal %s\n", Version)
		return
	}

	log.Println("[START] Starting KernelSeal - Secret Protection System")
	log.Printf("   Version: %s", Version)
	log.Printf("   Config: %s", *configPath)

	registry := secrets.NewRegistry()
	policyManager := internal.NewPolicyManager(registry)
	bpfManager := bpf.NewManager()
	collector := metrics.NewCollector()

	if _, err := os.Stat(*configPath); err == nil {
		if err := policyManager.LoadConfig(*configPath); err != nil {
			log.Printf("[WARN] Failed to load config: %v (using defaults)", err)
		}
	} else {
		log.Printf("[INFO] Config file not found, using defaults")
	}

	applyLogLevel(policyManager)

	policyManager.SetPolicyUpdateCallback(func(policy types.PolicyConfig) {
		if err := bpfManager.ConfigurePolicy(policy); err != nil {
			log.Printf("[WARN] Failed to update BPF policy: %v", err)
		}
	})

	if err := bpfManager.LoadExecMonitor(*execMonitorPath); err != nil {
		log.Fatalf("[ERROR] Failed to load exec monitor: %v", err)
	}

	configureBinaryFilter(policyManager, bpfManager)

	// BPF-LSM is unavailable on some kernels; that is a warning rather than a
	// hard failure, but it downgrades what KernelSeal can promise.
	if err := bpfManager.LoadLSM(*lsmPath); err != nil {
		log.Printf("[WARN] LSM not loaded: %v", err)
	}

	// #nosec G115 - a PID is always positive and fits in uint32
	ownPID := uint32(os.Getpid()) //nolint:gosec
	if err := bpfManager.AllowPID(ownPID); err != nil {
		log.Printf("[WARN] Failed to allow own PID: %v", err)
	}

	policy := policyManager.GetBPFPolicy()
	if err := bpfManager.ConfigurePolicy(policy); err != nil {
		log.Printf("[WARN] Failed to configure policy: %v", err)
	}

	bpfManager.SetExecHandler(func(event *types.ExecEvent) {
		handleExecEvent(event, bpfManager, collector)
	})
	bpfManager.SetLSMHandler(func(event *types.LSMEvent) {
		handleLSMEvent(event, collector)
	})
	bpfManager.Start()

	// Secrets are only released once the caller is marked protected, so refuse
	// to hand them out at all when enforcement was requested but is unavailable.
	requireProtection := policy.EnforceMode == types.ModeEnforce
	secretServer := server.New(server.Config{
		SocketPath:        *socketPath,
		SocketMode:        os.FileMode(*socketMode),
		SocketGroup:       *socketGroup,
		RequireProtection: requireProtection,
	}, registry, bpfManager)

	secretServer.SetIssuedCallback(func(_ uint32, names []string) {
		collector.RecordSecretsIssued(len(names))
	})
	secretServer.SetDeniedCallback(func(_ uint32, _ string) {
		collector.RecordSecretsDenied()
	})

	if err := secretServer.Listen(); err != nil {
		log.Fatalf("[ERROR] Failed to open secret socket: %v", err)
	}
	secretServer.Serve()

	reconciler := reconcile.New(bpfManager, 0)
	reconciler.Start()

	collector.SetGauge("kernelseal_lsm_loaded", func() float64 {
		if bpfManager.IsLSMLoaded() {
			return 1
		}
		return 0
	})
	collector.SetGauge("kernelseal_protected_pids", func() float64 {
		pids, err := bpfManager.ListProtectedPIDs()
		if err != nil {
			return -1
		}
		return float64(len(pids))
	})

	metricsServer := startMetrics(policyManager, collector, bpfManager, requireProtection)

	if requireProtection && !bpfManager.IsLSMLoaded() {
		log.Println("[WARN] Policy mode is enforce but BPF-LSM is not loaded:")
		log.Println("[WARN]   secret requests will be REFUSED until protection is available.")
		log.Println("[WARN]   Check that the kernel was booted with bpf in its lsm= list.")
	}

	log.Printf("[OK] KernelSeal running - secrets available via %s", *socketPath)
	log.Println("   Press Ctrl+C to stop")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("[STOP] Shutting down KernelSeal...")
	if metricsServer != nil {
		metricsServer.Stop()
	}
	reconciler.Stop()
	secretServer.Close()
	bpfManager.Stop()
	log.Println("[DONE] KernelSeal stopped")
}

// applyLogLevel honors monitoring.logLevel from the configuration.
func applyLogLevel(pm *internal.PolicyManager) {
	configured := pm.GetConfig().Monitoring.LogLevel

	level, err := logging.Parse(configured)
	if err != nil {
		log.Printf("[WARN] %v; defaulting to info", err)
	}
	logging.SetLevel(level)

	log.Printf("[CONFIG] Log level: %s", level)
	if level > logging.LevelDebug {
		log.Printf("[CONFIG] Per-exec tracing is suppressed; set logLevel: debug to see it")
	}
}

// configureBinaryFilter programs the kernel-side exec filter so that, in
// production, unrelated processes never generate ring buffer traffic.
func configureBinaryFilter(pm *internal.PolicyManager, bpfMgr *bpf.Manager) {
	targetBinaries := pm.GetTargetBinaries()

	if !pm.IsKernelBinaryFilterEnabled() {
		log.Println("[FILTER] Kernel-side binary filtering disabled by config - observing all processes")
		return
	}

	if len(targetBinaries) == 0 {
		log.Println("[WARN] Kernel-side filtering is enabled but no binaries are configured;")
		log.Println("[WARN]   observing all processes, which is not recommended in production.")
		return
	}

	for _, binary := range targetBinaries {
		if err := bpfMgr.AddTargetBinary(binary); err != nil {
			log.Printf("[WARN] Failed to add target binary %s: %v", binary, err)
		}
	}
	if err := bpfMgr.EnableBinaryFilter(true); err != nil {
		log.Printf("[WARN] Failed to enable binary filter: %v", err)
		return
	}

	log.Printf("[FILTER] Kernel-side filtering enabled for %d binaries: %v",
		len(targetBinaries), targetBinaries)
}

// startMetrics brings up the observability endpoints, returning nil when they are
// disabled by config.
func startMetrics(pm *internal.PolicyManager, collector *metrics.Collector,
	bpfMgr *bpf.Manager, requireProtection bool) *metrics.Server {

	cfg := pm.GetConfig().Monitoring
	if !cfg.Enabled {
		log.Println("[METRICS] Disabled by config")
		return nil
	}

	ready := func() error {
		if requireProtection && !bpfMgr.IsLSMLoaded() {
			return errors.New("BPF-LSM required by policy but not loaded")
		}
		return nil
	}

	srv := metrics.NewServer(cfg.MetricsPort, collector, ready)
	if err := srv.Start(); err != nil {
		log.Printf("[WARN] Metrics server not started: %v", err)
		return nil
	}
	return srv
}

// handleExecEvent records process lifecycle events. Secret delivery is driven by
// the shim connecting to the socket, not by this path; exec events are here for
// audit visibility and to clean up when a protected process exits.
func handleExecEvent(event *types.ExecEvent, bpfMgr *bpf.Manager, collector *metrics.Collector) {
	switch event.EventType {
	case types.EventExec:
		collector.RecordExecEvent()
		// One line per exec is far too noisy for normal operation: a host that
		// runs a target binary in a loop produces a steady stream that buries
		// everything else. The counter above is the signal; this is tracing.
		logging.Debugf("[EXEC] PID=%d PPID=%d Comm=%s File=%s CgroupID=%d",
			event.PID, event.PPID, event.GetComm(), event.GetFilename(), event.CgroupID)

	case types.EventExit:
		// Never take a reported exit at face value: dropping protection for a
		// process that is still running silently exposes its secrets, whereas
		// keeping a stale entry is caught by the periodic reconcile sweep. The
		// kernel side already filters out non-final thread exits; this is the
		// backstop for any exit report that is wrong anyway.
		if reconcile.ProcessAlive(event.PID) {
			logging.Warnf("[WARN] Ignoring exit event for PID %d: process is still running", event.PID)
			return
		}
		if err := bpfMgr.UnprotectPID(event.PID); err != nil {
			logging.Warnf("[WARN] Failed to release protection for PID %d: %v", event.PID, err)
		}
	}
}

// handleLSMEvent reports access attempts against protected processes. These are
// security events, so they stay visible at the default level.
func handleLSMEvent(event *types.LSMEvent, collector *metrics.Collector) {
	blocked := event.EventType == types.EventBlocked
	if blocked {
		collector.RecordAccessBlocked()
	} else {
		collector.RecordAccessAudited()
	}

	verb := "AUDIT"
	logAt := logging.Infof
	if blocked {
		verb = "BLOCKED"
		logAt = logging.Warnf
	}

	logAt("[LSM %s] PID=%d (%s) uid=%d attempted %s access to PID=%d",
		verb, event.PID, event.GetComm(), event.UID,
		event.AccessType.String(), event.TargetPID)
}
