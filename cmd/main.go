// KernelSeal - Kubernetes agent for secret protection using eBPF and BPF-LSM
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/phonginreallife/kernelseal/internal"
	"github.com/phonginreallife/kernelseal/internal/bpf"
	"github.com/phonginreallife/kernelseal/internal/cgroup"
	"github.com/phonginreallife/kernelseal/internal/identity"
	"github.com/phonginreallife/kernelseal/internal/kube"
	"github.com/phonginreallife/kernelseal/internal/logging"
	"github.com/phonginreallife/kernelseal/internal/metrics"
	"github.com/phonginreallife/kernelseal/internal/protocol"
	"github.com/phonginreallife/kernelseal/internal/reconcile"
	"github.com/phonginreallife/kernelseal/internal/secrets"
	"github.com/phonginreallife/kernelseal/internal/server"
	"github.com/phonginreallife/kernelseal/internal/types"
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
	procRoot := flag.String("proc-root", cgroup.DefaultProcRoot,
		"Procfs mount used to read a caller's cgroup membership; set to /host/proc when procfs is bind-mounted")
	cgroupRoot := flag.String("cgroup-root", cgroup.DefaultRoot,
		"Unified cgroup hierarchy mount, used to resolve a caller's cgroup id")
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

	identityMode := policyManager.PodIdentityMode()
	identifier, podWatcher := startIdentity(identityMode, *procRoot, *cgroupRoot)
	if podWatcher != nil {
		defer podWatcher.Stop()
	}

	// Secrets are only released once the caller is marked protected, so refuse
	// to hand them out at all when enforcement was requested but is unavailable.
	requireProtection := policy.EnforceMode == types.ModeEnforce
	secretServer := server.New(server.Config{
		SocketPath:         *socketPath,
		SocketMode:         os.FileMode(*socketMode),
		SocketGroup:        *socketGroup,
		RequireProtection:  requireProtection,
		IdentifyCallers:    identityMode != internal.PodIdentityDisabled,
		RequirePodIdentity: identityMode == internal.PodIdentityRequired,
	}, registry, bpfManager, identifier)

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
	// In required mode a cold or empty pod cache means every request is refused,
	// so this is the gauge that explains an agent that looks healthy while nothing
	// it guards can start.
	if podWatcher != nil {
		collector.SetGauge("kernelseal_pods_watched", func() float64 {
			return float64(podWatcher.Len())
		})
	}
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

// startIdentity brings up caller identification for the active mode.
//
// The pod watcher is what turns a cgroup into a namespace and a set of labels, so
// without it only cgroupPath selectors can match. In required mode that is not a
// degraded state worth continuing from: every request would be refused, and an
// agent that refuses everything is better as a startup failure than as a pod that
// looks healthy while nothing it guards can start.
func startIdentity(mode internal.PodIdentityMode, procRoot, cgroupRoot string) (*identity.Resolver, *kube.Watcher) {
	if mode == internal.PodIdentityDisabled {
		log.Println("[IDENTITY] Disabled: bindings are selected by the binary name the caller claims.")
		log.Println("[IDENTITY]   Any process that can reach the socket can request any binding by naming it.")
		return nil, nil
	}

	cgroups := cgroup.NewResolver(procRoot, cgroupRoot)
	warnIfOwnCgroupNamespaced(cgroups)

	if !kube.InCluster() {
		if mode == internal.PodIdentityRequired {
			log.Fatalln("[ERROR] policy.podIdentity is required but this agent is not running in a " +
				"cluster, so no caller can be attributed to a pod and every request would be refused.")
		}
		log.Println("[IDENTITY] Not running in a cluster; callers are identified by cgroup only.")
		log.Println("[IDENTITY]   Bindings that select on namespace, labels or container will match nothing.")
		return identity.New(cgroups, nil), nil
	}

	watcher, err := kube.NewWatcher(kube.Config{NodeName: os.Getenv("NODE_NAME")})
	if err != nil {
		if mode == internal.PodIdentityRequired {
			log.Fatalf("[ERROR] policy.podIdentity is required but the pod watcher could not "+
				"be created: %v", err)
		}
		log.Printf("[WARN] Pod watcher unavailable, callers are identified by cgroup only: %v", err)
		return identity.New(cgroups, nil), nil
	}

	if err := watcher.Start(context.Background()); err != nil {
		if mode == internal.PodIdentityRequired {
			log.Fatalf("[ERROR] policy.podIdentity is required but the initial pod list failed: %v", err)
		}
		log.Printf("[WARN] Pod watcher did not start, callers are identified by cgroup only: %v", err)
		return identity.New(cgroups, nil), nil
	}

	log.Printf("[IDENTITY] Mode %s: callers are attributed to a pod before any binding matches", mode)
	return identity.New(cgroups, watcher), watcher
}

// warnIfOwnCgroupNamespaced reports a cgroup namespace that will make cgroupPath
// selectors unusable.
//
// The kernel renders /proc/<pid>/cgroup relative to the *reading* process's
// cgroup namespace. An agent with its own namespace therefore sees other pods as
// "/../kubepods.slice/...", which cannot be compared against a configured path.
// Pod attribution still works, because the pod UID is parsed from a path segment,
// so this is a warning rather than a refusal. It is checked at startup because
// the alternative is discovering it as a stream of unexplained denials.
func warnIfOwnCgroupNamespaced(cgroups *cgroup.Resolver) {
	// #nosec G115 - a PID is always positive and fits in uint32
	own, err := cgroups.Resolve(uint32(os.Getpid())) //nolint:gosec
	if err != nil && !errors.Is(err, cgroup.ErrNoID) {
		log.Printf("[WARN] Could not read this agent's own cgroup: %v", err)
		return
	}

	log.Printf("[IDENTITY] Agent cgroup: %s", own.Path)

	if own.Path != "/" {
		return
	}

	// A root cgroup path is either a host with no cgroup delegation, which is
	// fine, or a container in its own cgroup namespace, which is not.
	if !kube.InCluster() {
		return
	}

	log.Println("[WARN] This agent sees its own cgroup as \"/\", which means it has its own cgroup")
	log.Println("[WARN]   namespace. Callers' cgroup paths will be rendered relative to it, so")
	log.Println("[WARN]   cgroupPath selectors cannot match and will refuse.")
	log.Println("[WARN]   Pod attribution is unaffected: select on namespace and labels instead,")
	log.Println("[WARN]   or run the agent in the host's cgroup namespace.")
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
		// This must stay an unconditional release. Sanity-checking the PID
		// against /proc here does not work: sched_process_exit fires from inside
		// do_exit(), so the task still has a /proc entry when the event arrives
		// and every real exit would look like a live process. Correctness relies
		// on the kernel side reporting only the final thread of a group, with the
		// reconcile sweep as the net for exits that are never reported at all.
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
