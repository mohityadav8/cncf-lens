package prometheus

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/signal"
)

// mockPrometheus serves a canned query_range response so we exercise the real
// HTTP path, JSON decoding and signal conversion rather than stubbing them out.
func mockPrometheus(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/-/healthy" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func rangeResponse(values [][2]any, labels map[string]string) map[string]any {
	return map[string]any{
		"status": "success",
		"data": map[string]any{
			"resultType": "matrix",
			"result": []map[string]any{
				{"metric": labels, "values": values},
			},
		},
	}
}

func TestFetchConvertsSamplesToSignals(t *testing.T) {
	now := float64(time.Now().Unix())
	body := rangeResponse(
		[][2]any{
			{now - 60, "0.05"},
			{now - 30, "0.95"}, // above the 0.1 error-rate threshold
			{now, "0.02"},
		},
		map[string]string{"namespace": "payments", "pod": "checkout-abc", "container": "app"},
	)

	srv := mockPrometheus(t, http.StatusOK, body)
	defer srv.Close()

	a := New("prometheus", srv.URL, "", false, 5*time.Second)
	got, err := a.Fetch(context.Background(), adapter.Query{
		From:  time.Now().Add(-5 * time.Minute),
		To:    time.Now(),
		Types: []signal.Type{signal.TypeMetric},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected signals, got none")
	}

	for _, s := range got {
		if s.Type != signal.TypeMetric {
			t.Errorf("want metric type, got %s", s.Type)
		}
		if s.Source != "prometheus" {
			t.Errorf("want source prometheus, got %s", s.Source)
		}
		if s.Value == nil {
			t.Error("metric signal must carry a value")
		}
		if s.Labels[signal.LabelNamespace] != "payments" {
			t.Errorf("namespace label not mapped: %v", s.Labels)
		}
		if s.Labels[signal.LabelPod] != "checkout-abc" {
			t.Errorf("pod label not mapped: %v", s.Labels)
		}
	}

	// The 0.95 sample exceeds the error-rate threshold and must be flagged.
	var sawWarning bool
	for _, s := range got {
		if s.Severity >= signal.SevWarning {
			sawWarning = true
		}
	}
	if !sawWarning {
		t.Error("a sample above the anomaly threshold should raise severity")
	}
}

func TestFetchSkipsNaNSamples(t *testing.T) {
	now := float64(time.Now().Unix())
	body := rangeResponse(
		[][2]any{{now - 30, "NaN"}, {now, "1.5"}},
		map[string]string{"namespace": "default"},
	)
	srv := mockPrometheus(t, http.StatusOK, body)
	defer srv.Close()

	a := New("prometheus", srv.URL, "", false, 5*time.Second)
	got, err := a.Fetch(context.Background(), adapter.Query{
		From: time.Now().Add(-time.Minute), To: time.Now(),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, s := range got {
		if s.Value != nil && math.IsNaN(*s.Value) {
			t.Error("NaN sample leaked into output — it would render as a bogus zero")
		}
	}
}

func TestFetchSurfacesQueryErrors(t *testing.T) {
	srv := mockPrometheus(t, http.StatusOK, map[string]any{
		"status": "error", "errorType": "bad_data", "error": "parse error at char 5",
	})
	defer srv.Close()

	a := New("prometheus", srv.URL, "", false, 5*time.Second)
	_, err := a.Fetch(context.Background(), adapter.Query{
		From: time.Now().Add(-time.Minute), To: time.Now(), Expr: "not valid promql {",
	})
	if err == nil {
		t.Fatal("expected an error for a failed PromQL query")
	}
}

func TestHealthCheck(t *testing.T) {
	srv := mockPrometheus(t, http.StatusOK, map[string]any{"status": "success"})
	defer srv.Close()

	a := New("prometheus", srv.URL, "", false, 5*time.Second)
	if err := a.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck against a healthy server: %v", err)
	}
}

func TestHealthCheckFailsOnUnreachable(t *testing.T) {
	// Port 1 is reserved and nothing listens there.
	a := New("prometheus", "http://127.0.0.1:1", "", false, 500*time.Millisecond)
	if err := a.HealthCheck(context.Background()); err == nil {
		t.Error("expected an error for an unreachable backend")
	}
}

func TestApplySelectorsInjectsNamespace(t *testing.T) {
	q := adapter.Query{Namespace: "payments"}
	got := applySelectors(`sum by (pod) (rate(http_requests_total{code=~"5.."}[2m]))`, q)
	want := `sum by (pod) (rate(http_requests_total{namespace="payments",code=~"5.."}[2m]))`
	if got != want {
		t.Errorf("applySelectors:\n got %s\nwant %s", got, want)
	}
}

// A user-supplied expression must be passed through untouched, because we
// cannot safely rewrite arbitrary PromQL without a parser.
func TestApplySelectorsNeverRewritesUserExpressions(t *testing.T) {
	expr := `up{job="custom"}`
	q := adapter.Query{Namespace: "payments", Expr: expr}
	if got := applySelectors(expr, q); got != expr {
		t.Errorf("user expression was rewritten: got %s", got)
	}
}

func TestChooseStepBoundsPointCount(t *testing.T) {
	for _, window := range []time.Duration{time.Minute, time.Hour, 24 * time.Hour, 30 * 24 * time.Hour} {
		step := chooseStep(window)
		if step < 15*time.Second {
			t.Errorf("window %s: step %s is below the 15s floor", window, step)
		}
		if points := int(window / step); points > 300 {
			t.Errorf("window %s: %d points exceeds the budget", window, points)
		}
	}
}
