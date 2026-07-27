// Package metrics exposes KernelSeal's counters plus liveness and readiness
// endpoints over HTTP.
//
// The Prometheus text format is written directly rather than pulling in a client
// library. KernelSeal runs privileged, so its dependency tree is kept as small as
// the job allows; these are plain counters and gauges with no need for histograms
// or exemplars.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const shutdownTimeout = 5 * time.Second

// Collector holds KernelSeal's counters. It is safe for concurrent use.
type Collector struct {
	execEvents    atomic.Uint64
	secretsIssued atomic.Uint64
	secretsDenied atomic.Uint64
	accessBlocked atomic.Uint64
	accessAudited atomic.Uint64

	mu     sync.RWMutex
	gauges map[string]func() float64
}

// NewCollector creates an empty collector.
func NewCollector() *Collector {
	return &Collector{gauges: make(map[string]func() float64)}
}

// RecordExecEvent counts one process execution observed via BPF.
func (c *Collector) RecordExecEvent() { c.execEvents.Add(1) }

// RecordSecretsIssued counts one successful release of secrets to a process.
func (c *Collector) RecordSecretsIssued(n int) {
	if n > 0 {
		c.secretsIssued.Add(uint64(n))
	}
}

// RecordSecretsDenied counts one refused secret request.
func (c *Collector) RecordSecretsDenied() { c.secretsDenied.Add(1) }

// RecordAccessBlocked counts one access the LSM refused.
func (c *Collector) RecordAccessBlocked() { c.accessBlocked.Add(1) }

// RecordAccessAudited counts one access the LSM logged without refusing.
func (c *Collector) RecordAccessAudited() { c.accessAudited.Add(1) }

// SetGauge registers a named gauge sampled at scrape time. Passing a nil fn
// removes the gauge.
func (c *Collector) SetGauge(name string, fn func() float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fn == nil {
		delete(c.gauges, name)
		return
	}
	c.gauges[name] = fn
}

type metric struct {
	name  string
	help  string
	kind  string
	value float64
}

func (c *Collector) snapshot() []metric {
	out := []metric{
		{"kernelseal_exec_events_total", "Total process execution events processed.", "counter", float64(c.execEvents.Load())},
		{"kernelseal_secrets_issued_total", "Total secrets released to target processes.", "counter", float64(c.secretsIssued.Load())},
		{"kernelseal_secrets_denied_total", "Total secret requests refused.", "counter", float64(c.secretsDenied.Load())},
		{"kernelseal_access_blocked_total", "Total access attempts blocked by BPF-LSM.", "counter", float64(c.accessBlocked.Load())},
		{"kernelseal_access_audit_total", "Total access attempts audited but allowed.", "counter", float64(c.accessAudited.Load())},
	}

	c.mu.RLock()
	names := make([]string, 0, len(c.gauges))
	for name := range c.gauges {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, metric{name, "KernelSeal runtime gauge.", "gauge", c.gauges[name]()})
	}
	c.mu.RUnlock()

	return out
}

// WriteText renders the collector in Prometheus text exposition format.
// strings.Builder never returns a write error, so none is reported.
func (c *Collector) WriteText(w *strings.Builder) {
	for _, m := range c.snapshot() {
		w.WriteString("# HELP " + m.name + " " + m.help + "\n")
		w.WriteString("# TYPE " + m.name + " " + m.kind + "\n")
		w.WriteString(m.name + " " + formatValue(m.value) + "\n")
	}
}

// formatValue renders whole numbers without a decimal point, which keeps counter
// output readable.
func formatValue(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Server exposes a Collector plus health endpoints.
type Server struct {
	collector *Collector
	httpSrv   *http.Server
	ready     func() error

	mu sync.Mutex
	ln net.Listener
}

// NewServer builds the HTTP server. The ready function reports whether
// KernelSeal is fully operational; returning an error makes /ready respond 503.
func NewServer(port int, collector *Collector, ready func() error) *Server {
	s := &Server{collector: collector, ready: ready}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/ready", s.handleReady)

	s.httpSrv = &http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(port)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var b strings.Builder
	s.collector.WriteText(&b)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeBody(w, b.String())
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writeBody(w, "ok\n")
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if s.ready != nil {
		if err := s.ready(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			writeBody(w, fmt.Sprintf("not ready: %v\n", err))
			return
		}
	}
	writeBody(w, "ready\n")
}

// writeBody sends a response body, logging rather than propagating a write
// failure: by this point the status line is already committed and a disconnected
// scraper is not actionable.
func writeBody(w http.ResponseWriter, body string) {
	if _, err := w.Write([]byte(body)); err != nil {
		log.Printf("[WARN] Writing HTTP response: %v", err)
	}
}

// Start begins serving in the background. It returns an error if the port cannot
// be bound, so a misconfigured port fails loudly at startup instead of leaving
// the probes to discover it later.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.httpSrv.Addr)
	if err != nil {
		return fmt.Errorf("binding metrics listener on %s: %w", s.httpSrv.Addr, err)
	}

	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[WARN] Metrics server stopped: %v", err)
		}
	}()

	// Report the resolved address, which differs from the configured one when
	// port 0 was requested.
	log.Printf("[METRICS] Serving /metrics, /healthz and /ready on %s", ln.Addr())
	return nil
}

// Addr reports the address the server is listening on, or an empty string before
// Start succeeds.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Stop shuts the server down gracefully.
func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := s.httpSrv.Shutdown(ctx); err != nil {
		log.Printf("[WARN] Metrics server shutdown: %v", err)
	}
}
