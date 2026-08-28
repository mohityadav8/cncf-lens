package loki

import (
	"testing"

	"github.com/cncf-lens/lens/internal/adapter"
	"github.com/cncf-lens/lens/internal/signal"
)

// Extracting a trace ID from a log line is the highest-value correlation the
// tool performs, so it is tested against the formats real services emit.
func TestExtractTraceID(t *testing.T) {
	cases := map[string]string{
		`{"level":"error","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","msg":"boom"}`: "4bf92f3577b34da6a3ce929d0e0e4736",
		`ts=2026-03-14 traceID=00f067aa0ba902b7 level=warn`:                            "00f067aa0ba902b7",
		`trace-id: 4bf92f3577b34da6a3ce929d0e0e4736 request failed`:                    "4bf92f3577b34da6a3ce929d0e0e4736",
		`TraceId="4BF92F3577B34DA6A3CE929D0E0E4736"`:                                   "4bf92f3577b34da6a3ce929d0e0e4736",
		`plain log line with no trace context at all`:                                  "",
		`trace_id=tooshort`: "",
	}
	for line, want := range cases {
		if got := extractTraceID(line); got != want {
			t.Errorf("extractTraceID(%.50s):\n got %q\nwant %q", line, got, want)
		}
	}
}

func TestSeverityFromLine(t *testing.T) {
	cases := map[string]signal.Severity{
		`{"level":"error","msg":"failed"}`: signal.SevError,
		"PANIC: runtime error":             signal.SevCritical,
		"WARN retrying connection":         signal.SevWarning,
		"DEBUG cache hit":                  signal.SevDebug,
		"request completed in 12ms":        signal.SevInfo,
		"unhandled exception in handler":   signal.SevError,
	}
	for line, want := range cases {
		if got := severityFromLine(line); got != want {
			t.Errorf("severityFromLine(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestBuildSelector(t *testing.T) {
	cases := []struct {
		name string
		q    adapter.Query
		want string
	}{
		{"namespace only", adapter.Query{Namespace: "payments"}, `{namespace="payments"}`},
		{"namespace and pod", adapter.Query{Namespace: "payments", Pod: "checkout-abc"},
			`{namespace="payments",pod="checkout-abc"}`},
		{"workload becomes a regex", adapter.Query{Namespace: "payments", Workload: "checkout"},
			`{namespace="payments",pod=~"checkout.*"}`},
		{"nothing to filter on", adapter.Query{}, ""},
	}
	for _, tc := range cases {
		if got := buildSelector(tc.q); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}
}

// Pushing the trace filter server-side turns a 500-line scan into a targeted
// query, which matters a great deal on a busy namespace.
func TestBuildSelectorPushesTraceFilterServerSide(t *testing.T) {
	got := buildSelector(adapter.Query{Namespace: "payments", TraceID: "abc123"})
	want := `{namespace="payments"} |= "abc123"`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
