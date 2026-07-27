// kernelseal-exec fetches secrets from the KernelSeal agent and exec's a target
// binary with them present in its environment.
//
// Usage:
//
//	kernelseal-exec [flags] -- /usr/bin/myapp --myapp-flag
//
// It is meant to be the container's entrypoint, wrapping the original one. The
// agent marks this process as protected before returning any secrets, and execve
// preserves the PID, so the application inherits that protection along with the
// environment.
//
// This binary is deliberately dependency-free: it links only the standard
// library so it can be dropped into any image via a shared volume.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"kernelseal/internal/protocol"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "dev"

const (
	exitUsage   = 2
	exitFailure = 1
)

func main() {
	socketPath := flag.String("socket", protocol.DefaultSocketPath,
		"Path to the KernelSeal agent socket")
	timeout := flag.Duration("timeout", 15*time.Second,
		"How long to wait for the agent to become reachable")
	retryInterval := flag.Duration("retry-interval", 250*time.Millisecond,
		"Delay between connection attempts while waiting for the agent")
	onError := flag.String("on-error", "fail",
		"Behavior when secrets cannot be retrieved: fail (refuse to start) or continue (exec without them)")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("kernelseal-exec %s\n", Version)
		return
	}

	argv := flag.Args()
	if len(argv) == 0 {
		warnf("kernelseal-exec: no command given\n")
		usage()
		os.Exit(exitUsage)
	}

	failClosed, err := parseOnError(*onError)
	if err != nil {
		warnf("kernelseal-exec: %v\n", err)
		os.Exit(exitUsage)
	}

	// Resolve before talking to the agent so a typo in the command fails fast
	// and identically whether or not KernelSeal is running.
	binaryPath, err := exec.LookPath(argv[0])
	if err != nil {
		warnf("kernelseal-exec: %v\n", err)
		os.Exit(exitFailure)
	}

	resp, err := fetchSecrets(*socketPath, binaryPath, *timeout, *retryInterval)
	if err != nil {
		if failClosed {
			warnf("kernelseal-exec: refusing to start %s without secrets: %v\n", binaryPath, err)
			warnf("kernelseal-exec: pass -on-error=continue to exec anyway\n")
			os.Exit(exitFailure)
		}
		warnf("kernelseal-exec: continuing without secrets: %v\n", err)
		resp = &protocol.Response{OK: true}
	}

	env := mergeEnv(os.Environ(), resp.Env)

	if len(resp.Env) > 0 && !resp.Protected {
		// Worth saying out loud: the secrets are in the environment but the
		// kernel is not refusing reads of /proc/<pid>/environ.
		warnf("kernelseal-exec: warning: %d secrets applied without kernel protection\n",
			len(resp.Env))
	}

	if err := syscall.Exec(binaryPath, argv, env); err != nil {
		warnf("kernelseal-exec: exec %s: %v\n", binaryPath, err)
		os.Exit(exitFailure)
	}
}

// warnf reports a diagnostic on stderr. A failure to write it cannot be handled
// in any useful way, since stderr is the only channel available.
func warnf(format string, args ...any) {
	//nolint:errcheck // nothing to fall back to if stderr is unavailable
	fmt.Fprintf(os.Stderr, format, args...)
}

func usage() {
	warnf(`kernelseal-exec %s - run a command with KernelSeal-managed secrets

Usage:
  kernelseal-exec [flags] -- COMMAND [ARGS...]

Flags:
`, Version)
	flag.PrintDefaults()
}

func parseOnError(v string) (failClosed bool, err error) {
	switch v {
	case "fail":
		return true, nil
	case "continue":
		return false, nil
	default:
		return false, fmt.Errorf("invalid -on-error %q: want \"fail\" or \"continue\"", v)
	}
}

// fetchSecrets asks the agent for the environment to apply. It retries until the
// deadline because in a pod the shim can easily start before the agent is
// listening.
func fetchSecrets(socketPath, binaryPath string, timeout, retryInterval time.Duration) (*protocol.Response, error) {
	deadline := time.Now().Add(timeout)

	var lastErr error
	for {
		resp, err := requestOnce(socketPath, binaryPath, time.Until(deadline))
		if err == nil {
			return resp, nil
		}
		lastErr = err

		// Only a connection failure is worth retrying; a refusal from the agent
		// is final.
		if !isConnectError(err) {
			return nil, err
		}
		if !time.Now().Add(retryInterval).Before(deadline) {
			return nil, fmt.Errorf("agent unreachable at %s after %s: %w", socketPath, timeout, lastErr)
		}
		time.Sleep(retryInterval)
	}
}

func requestOnce(socketPath, binaryPath string, remaining time.Duration) (*protocol.Response, error) {
	if remaining <= 0 {
		return nil, fmt.Errorf("timed out connecting to %s", socketPath)
	}

	conn, err := net.DialTimeout("unix", socketPath, remaining)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(remaining)); err != nil {
		return nil, err
	}

	req := protocol.Request{Binary: binaryPath}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	var resp protocol.Response
	if err := json.NewDecoder(io.LimitReader(conn, protocol.MaxMessageSize)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if !resp.OK {
		msg := resp.Error
		if msg == "" {
			msg = "agent refused the request"
		}
		return nil, errors.New(msg)
	}

	return &resp, nil
}

// isConnectError reports whether the failure was in reaching the socket, as
// opposed to a response from the agent.
func isConnectError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}

// mergeEnv overlays secrets onto the inherited environment, replacing any
// existing variable of the same name.
func mergeEnv(base []string, overlay map[string]string) []string {
	if len(overlay) == 0 {
		return base
	}

	out := make([]string, 0, len(base)+len(overlay))
	for _, kv := range base {
		name, _, found := strings.Cut(kv, "=")
		if found {
			if _, shadowed := overlay[name]; shadowed {
				continue
			}
		}
		out = append(out, kv)
	}

	for name, value := range overlay {
		out = append(out, name+"="+value)
	}
	return out
}
