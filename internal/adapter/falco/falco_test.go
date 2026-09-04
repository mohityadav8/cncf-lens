package falco

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/signal"
)

func mkAlert(rule, priority string, ts time.Time, ns, pod string) map[string]any {
	return map[string]any{
		"time":     ts.Format(time.RFC3339Nano),
		"rule":     rule,
		"priority": priority,
		"output":   rule + " detected on " + pod,
		"source":   "syscall",
		"hostname": "node-3",
		"output_fields": map[string]any{
			"k8s.ns.name":    ns,
			"k8s.pod.name":   pod,
			"container.name": "app",
			"k8s.node.name":  "node-3",
		},
	}
}

func writeJSONL(t *testing.T, alerts []map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "falco.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, a := range alerts {
		if err := enc.Encode(a); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestFetchFromFile(t *testing.T) {
	now := time.Now().UTC()
	path := writeJSONL(t, []map[string]any{
		mkAlert("Terminal shell in container", "Warning", now.Add(-5*time.Minute), "payments", "checkout-abc"),
		mkAlert("Write below etc", "Error", now.Add(-2*time.Minute), "payments", "checkout-abc"),
	})

	a := NewFromFile("falco", path)
	got, err := a.Fetch(context.Background(), adapter.Query{
		From: now.Add(-15 * time.Minute), To: now,
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 alerts, got %d", len(got))
	}

	for _, s := range got {
		if s.Type != signal.TypeSecurity {
			t.Errorf("type = %q, want security", s.Type)
		}
		if s.Source != "falco" {
			t.Errorf("source = %q", s.Source)
		}
		if s.Labels[signal.LabelNamespace] != "payments" {
			t.Errorf("namespace label not mapped from k8s.ns.name: %v", s.Labels)
		}
		if s.Labels[signal.LabelPod] != "checkout-abc" {
			t.Errorf("pod label not mapped from k8s.pod.name: %v", s.Labels)
		}
	}

	// Signals must be time-sorted so the correlation engine can bucket them.
	if !got[0].Timestamp.Before(got[1].Timestamp) {
		t.Error("alerts were not returned in time order")
	}
}

func TestFetchFromFalcosidekick(t *testing.T) {
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			mkAlert("Container escape attempt", "Critical", now.Add(-time.Minute), "payments", "legacy-agent"),
		})
	}))
	defer srv.Close()

	a := New("falco", srv.URL, "", false, 5*time.Second)
	if err := a.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}

	got, err := a.Fetch(context.Background(), adapter.Query{
		From: now.Add(-10 * time.Minute), To: now,
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 alert, got %d", len(got))
	}
	if got[0].Severity != signal.SevCritical {
		t.Errorf("severity = %v, want critical", got[0].Severity)
	}
	if got[0].Title != "Container escape attempt" {
		t.Errorf("title = %q", got[0].Title)
	}
}

func TestPriorityMapping(t *testing.T) {
	cases := map[string]signal.Severity{
		"Emergency":     signal.SevCritical,
		"Alert":         signal.SevCritical,
		"Critical":      signal.SevCritical,
		"Error":         signal.SevError,
		"Warning":       signal.SevWarning,
		"Notice":        signal.SevInfo,
		"Informational": signal.SevInfo,
		"Debug":         signal.SevDebug,
		// A priority from a future Falco version must surface, not vanish
		// silently beneath the default noise floor.
		"SomethingNew": signal.SevWarning,
	}
	for input, want := range cases {
		if got := parsePriority(input); got != want {
			t.Errorf("parsePriority(%q) = %v, want %v", input, got, want)
		}
	}
}

// Falco is deliberately chatty at Debug and Informational. An audit report
// drowning in noise gets ignored, so low-priority alerts are dropped by default.
func TestNoiseFloorDropsLowPriority(t *testing.T) {
	now := time.Now().UTC()
	path := writeJSONL(t, []map[string]any{
		mkAlert("Chatty debug rule", "Debug", now.Add(-time.Minute), "payments", "p1"),
		mkAlert("Informational rule", "Informational", now.Add(-time.Minute), "payments", "p1"),
		mkAlert("Real finding", "Critical", now.Add(-time.Minute), "payments", "p1"),
	})

	a := NewFromFile("falco", path)
	got, _ := a.Fetch(context.Background(), adapter.Query{From: now.Add(-time.Hour), To: now})
	if len(got) != 1 || got[0].Title != "Real finding" {
		t.Fatalf("noise floor did not filter correctly: %+v", got)
	}

	// Lowering the floor must bring everything back.
	a.SetMinPriority(signal.SevDebug)
	got, _ = a.Fetch(context.Background(), adapter.Query{From: now.Add(-time.Hour), To: now})
	if len(got) != 3 {
		t.Errorf("SetMinPriority(debug) returned %d alerts, want 3", len(got))
	}
}

// Falco can be killed mid-write, leaving a truncated final line. Losing every
// earlier alert to that would be absurd.
func TestTruncatedFinalLineIsSkipped(t *testing.T) {
	now := time.Now().UTC()
	path := writeJSONL(t, []map[string]any{
		mkAlert("Valid alert", "Critical", now.Add(-time.Minute), "payments", "p1"),
	})
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"rule":"truncated","prio`)
	_ = f.Close()

	a := NewFromFile("falco", path)
	got, err := a.Fetch(context.Background(), adapter.Query{From: now.Add(-time.Hour), To: now})
	if err != nil {
		t.Fatalf("a truncated line should not fail the read: %v", err)
	}
	if len(got) != 1 || got[0].Title != "Valid alert" {
		t.Errorf("valid alerts lost to a truncated line: %+v", got)
	}
}

func TestWindowFiltering(t *testing.T) {
	now := time.Now().UTC()
	path := writeJSONL(t, []map[string]any{
		mkAlert("Too old", "Critical", now.Add(-2*time.Hour), "payments", "p1"),
		mkAlert("In window", "Critical", now.Add(-5*time.Minute), "payments", "p1"),
	})

	a := NewFromFile("falco", path)
	got, _ := a.Fetch(context.Background(), adapter.Query{From: now.Add(-15 * time.Minute), To: now})
	if len(got) != 1 || got[0].Title != "In window" {
		t.Errorf("window filtering failed: %+v", got)
	}
}

func TestNamespaceFiltering(t *testing.T) {
	now := time.Now().UTC()
	path := writeJSONL(t, []map[string]any{
		mkAlert("Wrong namespace", "Critical", now.Add(-time.Minute), "other-ns", "p1"),
		mkAlert("Right namespace", "Critical", now.Add(-time.Minute), "payments", "p2"),
	})

	a := NewFromFile("falco", path)
	got, _ := a.Fetch(context.Background(), adapter.Query{
		From: now.Add(-time.Hour), To: now, Namespace: "payments",
	})
	if len(got) != 1 || got[0].Title != "Right namespace" {
		t.Errorf("namespace filtering failed: %+v", got)
	}
}

// A signal with no usable timestamp cannot be correlated and must be dropped
// rather than landing at the zero time, decades before the query window.
func TestAlertWithNoTimestampIsDropped(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "falco.jsonl")
	_ = os.WriteFile(path, []byte(
		`{"rule":"no time","priority":"Critical","output_fields":{}}`+"\n"+
			`{"time":"`+now.Add(-time.Minute).Format(time.RFC3339Nano)+`","rule":"has time","priority":"Critical","output_fields":{}}`+"\n"),
		0o600)

	a := NewFromFile("falco", path)
	got, _ := a.Fetch(context.Background(), adapter.Query{From: now.Add(-time.Hour), To: now})
	if len(got) != 1 || got[0].Title != "has time" {
		t.Errorf("timestampless alert was not dropped: %+v", got)
	}
}

// Newer Falco builds carry nanosecond precision in output_fields.evt.time.
func TestFallsBackToEvtTime(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "falco.jsonl")
	line := map[string]any{
		"rule":     "nanosecond alert",
		"priority": "Critical",
		"output_fields": map[string]any{
			"evt.time": float64(now.Add(-time.Minute).UnixNano()),
		},
	}
	raw, _ := json.Marshal(line)
	_ = os.WriteFile(path, append(raw, '\n'), 0o600)

	a := NewFromFile("falco", path)
	got, _ := a.Fetch(context.Background(), adapter.Query{From: now.Add(-time.Hour), To: now})
	if len(got) != 1 {
		t.Fatalf("evt.time fallback failed: %+v", got)
	}
}

func TestHealthCheckReportsMissingFile(t *testing.T) {
	a := NewFromFile("falco", filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if err := a.HealthCheck(context.Background()); err == nil {
		t.Error("expected an error for a missing output file")
	}
}

func TestCapabilities(t *testing.T) {
	a := NewFromFile("falco", "x")
	caps := a.Capabilities()
	if len(caps) != 1 || caps[0] != signal.TypeSecurity {
		t.Errorf("capabilities = %v, want [security]", caps)
	}
	// A metrics-only query must never wake this adapter.
	got, err := a.Fetch(context.Background(), adapter.Query{
		Types: []signal.Type{signal.TypeMetric},
	})
	if err != nil || got != nil {
		t.Errorf("adapter did work for a metric-only query: %v %v", got, err)
	}
}
