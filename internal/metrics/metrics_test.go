package metrics

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func render(c *Collector) string {
	var b strings.Builder
	c.WriteText(&b)
	return b.String()
}

// metricValue pulls a single sample out of the exposition output.
func metricValue(t *testing.T, output, name string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if value, ok := strings.CutPrefix(line, name+" "); ok {
			return value
		}
	}
	t.Fatalf("metric %q not found in:\n%s", name, output)
	return ""
}

func TestCollector_CountersStartAtZero(t *testing.T) {
	out := render(NewCollector())

	for _, name := range []string{
		"kernelseal_exec_events_total",
		"kernelseal_secrets_issued_total",
		"kernelseal_secrets_denied_total",
		"kernelseal_access_blocked_total",
		"kernelseal_access_audit_total",
	} {
		if got := metricValue(t, out, name); got != "0" {
			t.Errorf("%s = %s, want 0", name, got)
		}
	}
}

func TestCollector_RecordsCounters(t *testing.T) {
	c := NewCollector()

	c.RecordExecEvent()
	c.RecordExecEvent()
	c.RecordSecretsIssued(3)
	c.RecordSecretsDenied()
	c.RecordAccessBlocked()
	c.RecordAccessAudited()
	c.RecordAccessAudited()

	out := render(c)

	tests := map[string]string{
		"kernelseal_exec_events_total":    "2",
		"kernelseal_secrets_issued_total": "3",
		"kernelseal_secrets_denied_total": "1",
		"kernelseal_access_blocked_total": "1",
		"kernelseal_access_audit_total":   "2",
	}
	for name, want := range tests {
		if got := metricValue(t, out, name); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
}

// Recording a non-positive count must not move the counter, so a zero-secret
// release does not look like activity.
func TestCollector_RecordSecretsIssued_IgnoresNonPositive(t *testing.T) {
	c := NewCollector()
	c.RecordSecretsIssued(0)
	c.RecordSecretsIssued(-5)

	if got := metricValue(t, render(c), "kernelseal_secrets_issued_total"); got != "0" {
		t.Errorf("kernelseal_secrets_issued_total = %s, want 0", got)
	}
}

func TestCollector_Gauges(t *testing.T) {
	c := NewCollector()
	c.SetGauge("kernelseal_protected_pids", func() float64 { return 7 })

	out := render(c)
	if got := metricValue(t, out, "kernelseal_protected_pids"); got != "7" {
		t.Errorf("kernelseal_protected_pids = %s, want 7", got)
	}
	if !strings.Contains(out, "# TYPE kernelseal_protected_pids gauge") {
		t.Errorf("gauge missing TYPE line:\n%s", out)
	}

	// Gauges are sampled at scrape time, not registration time.
	value := 1.0
	c.SetGauge("dynamic", func() float64 { return value })
	value = 2.0
	if got := metricValue(t, render(c), "dynamic"); got != "2" {
		t.Errorf("dynamic = %s, want 2 (gauge should re-sample)", got)
	}

	c.SetGauge("dynamic", nil)
	if strings.Contains(render(c), "dynamic ") {
		t.Error("gauge was not removed when set to nil")
	}
}

func TestCollector_ExpositionFormat(t *testing.T) {
	out := render(NewCollector())

	if !strings.Contains(out, "# HELP kernelseal_exec_events_total ") {
		t.Error("missing HELP line")
	}
	if !strings.Contains(out, "# TYPE kernelseal_exec_events_total counter") {
		t.Error("missing TYPE line")
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("exposition output must end with a newline")
	}
}

func TestFormatValue(t *testing.T) {
	tests := map[float64]string{
		0:   "0",
		7:   "7",
		-1:  "-1",
		1.5: "1.5",
		1e6: "1000000",
	}
	for in, want := range tests {
		if got := formatValue(in); got != want {
			t.Errorf("formatValue(%v) = %s, want %s", in, got, want)
		}
	}
}

func TestServer_MetricsEndpoint(t *testing.T) {
	c := NewCollector()
	c.RecordAccessBlocked()

	srv := NewServer(0, c, nil)

	rec := httptest.NewRecorder()
	srv.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if got := metricValue(t, rec.Body.String(), "kernelseal_access_blocked_total"); got != "1" {
		t.Errorf("kernelseal_access_blocked_total = %s, want 1", got)
	}
}

func TestServer_Healthz(t *testing.T) {
	// Liveness must not depend on readiness, or a pod that is merely degraded
	// would be restarted in a loop.
	srv := NewServer(0, NewCollector(), func() error { return errors.New("not ready") })

	rec := httptest.NewRecorder()
	srv.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestServer_Ready(t *testing.T) {
	tests := []struct {
		name  string
		ready func() error
		want  int
	}{
		{"no check configured", nil, http.StatusOK},
		{"check passes", func() error { return nil }, http.StatusOK},
		{"check fails", func() error { return errors.New("LSM not loaded") }, http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewServer(0, NewCollector(), tt.ready)

			rec := httptest.NewRecorder()
			srv.handleReady(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))

			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

// The reason /ready fails belongs in the response, so an operator debugging a
// stuck rollout can see it without reading logs.
func TestServer_ReadyIncludesReason(t *testing.T) {
	srv := NewServer(0, NewCollector(), func() error { return errors.New("LSM not loaded") })

	rec := httptest.NewRecorder()
	srv.handleReady(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if !strings.Contains(rec.Body.String(), "LSM not loaded") {
		t.Errorf("body = %q, want it to mention the reason", rec.Body.String())
	}
}

func TestServer_StartStop(t *testing.T) {
	srv := NewServer(0, NewCollector(), nil)

	if got := srv.Addr(); got != "" {
		t.Errorf("Addr before Start = %q, want empty", got)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if srv.Addr() == "" {
		t.Error("Addr after Start is empty")
	}
	srv.Stop()
}

// Binding a port already in use must surface as an error rather than being
// swallowed into a goroutine, so a misconfigured port is visible at startup.
func TestServer_StartReportsBindFailure(t *testing.T) {
	first := NewServer(0, NewCollector(), nil)
	if err := first.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer first.Stop()

	// Reuse the concrete port the first server was assigned, since port 0 would
	// simply pick another free one.
	_, port, err := net.SplitHostPort(first.Addr())
	if err != nil {
		t.Fatalf("parsing %q: %v", first.Addr(), err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parsing port %q: %v", port, err)
	}

	second := NewServer(portNum, NewCollector(), nil)
	if err := second.Start(); err == nil {
		second.Stop()
		t.Errorf("Start on busy port %d returned nil error", portNum)
	}
}
