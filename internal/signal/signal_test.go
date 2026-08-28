package signal

import (
	"testing"
	"time"
)

func TestParseSeverityAcceptsBackendSpellings(t *testing.T) {
	cases := map[string]Severity{
		"Warning": SevWarning, "WARN": SevWarning,
		"error": SevError, "Failed": SevError, "ERR": SevError,
		"Critical": SevCritical, "fatal": SevCritical, "Emergency": SevCritical,
		"Normal": SevInfo, "info": SevInfo,
		"debug": SevDebug, "trace": SevDebug,
		"":             SevInfo, // unknown must not crash or over-escalate
		"nonsense-xyz": SevInfo,
	}
	for input, want := range cases {
		if got := ParseSeverity(input); got != want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	// Filtering depends on this ordering holding.
	if !(SevDebug < SevInfo && SevInfo < SevWarning && SevWarning < SevError && SevError < SevCritical) {
		t.Fatal("severity constants are not monotonically ordered")
	}
}

func TestLabelOverlapCountsSharedIdentity(t *testing.T) {
	a := Signal{Labels: map[string]string{
		LabelNamespace: "payments", LabelPod: "checkout-abc", LabelContainer: "app",
	}}
	b := Signal{Labels: map[string]string{
		LabelNamespace: "payments", LabelPod: "checkout-abc", LabelNode: "node-1",
	}}
	if got := LabelOverlap(a, b); got != 2 {
		t.Errorf("LabelOverlap = %d, want 2", got)
	}
}

// Empty values must never count as a match, or every unlabelled signal would
// look related to every other one.
func TestLabelOverlapIgnoresEmptyValues(t *testing.T) {
	a := Signal{Labels: map[string]string{LabelNamespace: "", LabelPod: ""}}
	b := Signal{Labels: map[string]string{LabelNamespace: "", LabelPod: ""}}
	if got := LabelOverlap(a, b); got != 0 {
		t.Errorf("empty labels matched: got %d", got)
	}
}

func TestLabelOverlapHandlesNilMaps(t *testing.T) {
	if got := LabelOverlap(Signal{}, Signal{}); got != 0 {
		t.Errorf("nil label maps should overlap 0, got %d", got)
	}
}

func TestSetLabelDropsEmptyValues(t *testing.T) {
	var s Signal
	s.SetLabel(LabelPod, "")
	if len(s.Labels) != 0 {
		t.Errorf("empty label was stored: %v", s.Labels)
	}
	s.SetLabel(LabelPod, "real-pod")
	if s.Labels[LabelPod] != "real-pod" {
		t.Error("non-empty label was not stored")
	}
}

func TestSortByTimeIsDeterministic(t *testing.T) {
	base := time.Now()
	// Identical timestamps must break ties stably, so golden output and
	// report diffs stay meaningful across runs.
	s := Set{
		{Timestamp: base, Source: "zebra", Title: "z"},
		{Timestamp: base, Source: "alpha", Title: "a"},
		{Timestamp: base.Add(-time.Second), Source: "mid", Title: "earlier"},
	}
	s.SortByTime()

	if s[0].Title != "earlier" {
		t.Errorf("earliest signal not first: %q", s[0].Title)
	}
	if s[1].Source != "alpha" || s[2].Source != "zebra" {
		t.Errorf("tie-break not stable: %s then %s", s[1].Source, s[2].Source)
	}
}

func TestFilterType(t *testing.T) {
	s := Set{
		{Type: TypeMetric, Title: "m"},
		{Type: TypeLog, Title: "l"},
		{Type: TypeTrace, Title: "t"},
	}
	if got := len(s.FilterType(TypeMetric, TypeLog)); got != 2 {
		t.Errorf("FilterType returned %d, want 2", got)
	}
	// No filter means no filtering.
	if got := len(s.FilterType()); got != 3 {
		t.Errorf("empty filter returned %d, want all 3", got)
	}
}

func TestFilterSeverity(t *testing.T) {
	s := Set{
		{Severity: SevDebug}, {Severity: SevInfo},
		{Severity: SevWarning}, {Severity: SevCritical},
	}
	if got := len(s.FilterSeverity(SevWarning)); got != 2 {
		t.Errorf("FilterSeverity(warning) = %d, want 2", got)
	}
}

func TestWindow(t *testing.T) {
	base := time.Now()
	s := Set{
		{Timestamp: base.Add(-time.Hour), Title: "too old"},
		{Timestamp: base, Title: "in range"},
		{Timestamp: base.Add(time.Hour), Title: "too new"},
	}
	got := s.Window(base.Add(-time.Minute), base.Add(time.Minute))
	if len(got) != 1 || got[0].Title != "in range" {
		t.Errorf("Window returned %+v", got)
	}
}

func TestSpanReportsBounds(t *testing.T) {
	base := time.Now()
	s := Set{
		{Timestamp: base.Add(time.Minute)},
		{Timestamp: base},
		{Timestamp: base.Add(2 * time.Minute)},
	}
	from, to, ok := s.Span()
	if !ok {
		t.Fatal("Span should report ok for a non-empty set")
	}
	if !from.Equal(base) || !to.Equal(base.Add(2*time.Minute)) {
		t.Errorf("Span = %s..%s", from, to)
	}

	if _, _, ok := (Set{}).Span(); ok {
		t.Error("empty set should report ok=false, not zero times")
	}
}

func TestIdentityIsStable(t *testing.T) {
	a := Signal{Labels: map[string]string{LabelNamespace: "ns", LabelPod: "p"}}
	b := Signal{Labels: map[string]string{LabelPod: "p", LabelNamespace: "ns"}}
	// Map iteration order is random in Go; Identity must not be.
	if a.Identity() != b.Identity() {
		t.Errorf("Identity is not order-independent:\n %q\n %q", a.Identity(), b.Identity())
	}
	if (Signal{}).Identity() != "" {
		t.Error("unlabelled signal should have an empty identity")
	}
}
