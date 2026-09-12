package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/signal"
)

func TestWorkloadFromPod(t *testing.T) {
	// Kubernetes Deployment Pods follow:
	// <workload>-<replicaset-hash>-<random5>.
	//
	// The five-character Pod suffix may be entirely alphabetic, so workload
	// detection must not require a digit in that suffix.
	cases := map[string]string{
		"payments-7d4b9c5f8-x2k9p":          "payments",
		"payments-7d4b9c5f8-abcde":          "payments",
		"checkout-api-5f9c8d7b6c-abc12":     "checkout-api",
		"checkout-api-5f9c8d7b6c-fghjk":     "checkout-api",
		"nginx-deployment-66b6c48dd5-j2mn4": "nginx-deployment",

		// StatefulSet Pods use an ordinal rather than the Deployment
		// ReplicaSet/Pod suffix pair and must remain unchanged.
		"my-stateful-set-0": "my-stateful-set-0",
		"standalone":        "standalone",

		// Ordinary workload names must not be stripped just because their
		// final segment consists only of lowercase letters.
		"api-gateway-service": "api-gateway-service",

		// A five-character suffix without the preceding ReplicaSet hash is
		// not sufficient to identify a Deployment Pod.
		"api-service-abcde": "api-service-abcde",
	}

	for pod, want := range cases {
		if got := workloadFromPod(pod); got != want {
			t.Errorf("workloadFromPod(%q) = %q, want %q", pod, got, want)
		}
	}
}

func TestEventTimePrefersMostAccurate(t *testing.T) {
	ev := event{
		EventTime:      "2026-03-14T15:09:26.535Z",
		LastTimestamp:  "2026-03-14T15:00:00Z",
		FirstTimestamp: "2026-03-14T14:00:00Z",
	}
	got := eventTime(ev)
	if got.Nanosecond() == 0 {
		t.Errorf("sub-second precision lost: %s", got)
	}
	if got.Minute() != 9 {
		t.Errorf("wrong timestamp field chosen: %s", got)
	}
}

func TestEventTimeFallsBackThroughFields(t *testing.T) {
	// Older Kubernetes versions populate only lastTimestamp.
	ev := event{LastTimestamp: "2026-03-14T15:00:00Z"}
	if got := eventTime(ev); got.IsZero() {
		t.Error("fallback to lastTimestamp failed")
	}
	if got := eventTime(event{}); !got.IsZero() {
		t.Error("an event with no timestamps should return the zero time")
	}
}

// Classifying rollouts as TypeDeploy is what lets the causal engine apply its
// heaviest weight to them, so the mapping is load-bearing.
func TestEventClassification(t *testing.T) {
	a := New("kubernetes", "http://x", "", false, time.Second, "test-cluster")
	ts := time.Now()

	cases := []struct {
		reason   string
		evType   string
		wantType signal.Type
		wantSev  signal.Severity
	}{
		{"ScalingReplicaSet", "Normal", signal.TypeDeploy, signal.SevInfo},
		{"SuccessfulCreate", "Normal", signal.TypeDeploy, signal.SevInfo},
		{"SuccessfulDelete", "Normal", signal.TypeDeploy, signal.SevInfo},

		// Routine kubelet pod lifecycle events are ordinary events, not
		// deployment/change signals. They must not receive the deployment-specific
		// causal weight.
		{"Pulled", "Normal", signal.TypeEvent, signal.SevInfo},
		{"Pulling", "Normal", signal.TypeEvent, signal.SevInfo},
		{"Created", "Normal", signal.TypeEvent, signal.SevInfo},
		{"Started", "Normal", signal.TypeEvent, signal.SevInfo},
		{"Killing", "Normal", signal.TypeEvent, signal.SevInfo},

		{"OOMKilling", "Warning", signal.TypeEvent, signal.SevCritical},
		{"Evicted", "Warning", signal.TypeEvent, signal.SevCritical},
		{"FailedScheduling", "Warning", signal.TypeEvent, signal.SevError},
		{"BackOff", "Warning", signal.TypeEvent, signal.SevError},
		{"Unhealthy", "Warning", signal.TypeEvent, signal.SevWarning},
	}

	for _, tc := range cases {
		ev := event{Reason: tc.reason, Type: tc.evType}
		ev.InvolvedObject.Kind = "Pod"
		ev.InvolvedObject.Name = "checkout-7d4b9c5f8-x2k9p"
		ev.InvolvedObject.Namespace = "payments"

		got := a.eventToSignal(ev, ts)
		if got.Type != tc.wantType {
			t.Errorf("%s: type = %q, want %q", tc.reason, got.Type, tc.wantType)
		}
		if got.Severity != tc.wantSev {
			t.Errorf("%s: severity = %v, want %v", tc.reason, got.Severity, tc.wantSev)
		}
		if got.Labels[signal.LabelWorkload] != "checkout" {
			t.Errorf("%s: workload label = %q", tc.reason, got.Labels[signal.LabelWorkload])
		}
		if got.Labels[signal.LabelCluster] != "test-cluster" {
			t.Errorf("%s: cluster label missing", tc.reason)
		}
	}
}

func TestFetchWindowsEventsClientSide(t *testing.T) {
	now := time.Now().UTC()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := eventList{Items: []event{
			mkEvent("InWindow", now.Add(-5*time.Minute)),
			mkEvent("TooOld", now.Add(-3*time.Hour)),
			mkEvent("Future", now.Add(time.Hour)),
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	a := New("kubernetes", srv.URL, "", false, 5*time.Second, "test")
	got, err := a.Fetch(context.Background(), adapter.Query{
		From: now.Add(-15 * time.Minute),
		To:   now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 in-window event, got %d", len(got))
	}
	if got[0].Title[:8] != "InWindow" {
		t.Errorf("wrong event kept: %q", got[0].Title)
	}
}

func mkEvent(reason string, ts time.Time) event {
	ev := event{
		Reason:    reason,
		Type:      "Normal",
		Message:   "test event",
		EventTime: ts.Format(time.RFC3339Nano),
	}
	ev.InvolvedObject.Kind = "Pod"
	ev.InvolvedObject.Name = "test-pod"
	ev.InvolvedObject.Namespace = "default"
	return ev
}

func TestHealthCheckRequiresVersionEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"gitVersion": "v1.31.2"})
	}))
	defer srv.Close()

	a := New("kubernetes", srv.URL, "", false, 5*time.Second, "test")
	if err := a.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}
}

// Pointing lens at something that speaks JSON but is not an API server should
// produce a clear message, not a confusing empty result later.
func TestHealthCheckRejectsNonAPIServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer srv.Close()

	a := New("kubernetes", srv.URL, "", false, 5*time.Second, "test")
	if err := a.HealthCheck(context.Background()); err == nil {
		t.Error("expected an error when the endpoint is not an API server")
	}
}
