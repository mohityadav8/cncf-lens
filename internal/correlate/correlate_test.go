package correlate

import (
	"testing"
	"time"

	"github.com/cncf-lens/lens/internal/signal"
)

func base() time.Time {
	return time.Date(2026, 3, 14, 15, 9, 26, 0, time.UTC)
}

func sig(offset time.Duration, source, title string, sev signal.Severity, labels map[string]string) signal.Signal {
	return signal.Signal{
		Timestamp: base().Add(offset),
		Source:    source,
		Title:     title,
		Severity:  sev,
		Type:      signal.TypeEvent,
		Labels:    labels,
	}
}

func TestAssembleGroupsCoOccurringSignals(t *testing.T) {
	sigs := signal.Set{
		sig(0, "prometheus", "latency spike", signal.SevWarning, nil),
		sig(100*time.Millisecond, "loki", "connection refused", signal.SevError, nil),
		sig(200*time.Millisecond, "kubernetes", "Unhealthy", signal.SevWarning, nil),
		// Well outside tolerance — must land in its own bucket.
		sig(30*time.Second, "loki", "unrelated later line", signal.SevInfo, nil),
	}

	tl := Assemble(sigs, DefaultTolerance)

	if len(tl.Buckets) != 2 {
		t.Fatalf("want 2 buckets, got %d", len(tl.Buckets))
	}
	if got := len(tl.Buckets[0].Signals); got != 3 {
		t.Errorf("first bucket: want 3 signals, got %d", got)
	}
	if !tl.Buckets[0].CrossSource() {
		t.Error("first bucket should be cross-source (prometheus + loki + kubernetes)")
	}
	if tl.Buckets[1].CrossSource() {
		t.Error("second bucket has one source and should not be cross-source")
	}
}

// TestAssembleDoesNotChainLink is the regression test for the bug this design
// explicitly avoids: anchoring to the previous signal rather than the bucket
// start lets a dense stream merge into one unbounded bucket.
func TestAssembleDoesNotChainLink(t *testing.T) {
	var sigs signal.Set
	for i := 0; i < 20; i++ {
		// Each 300ms after the last: within tolerance of its predecessor, but
		// spanning 6 seconds overall.
		sigs = append(sigs, sig(time.Duration(i)*300*time.Millisecond, "loki", "line", signal.SevInfo, nil))
	}

	tl := Assemble(sigs, DefaultTolerance)

	if len(tl.Buckets) < 5 {
		t.Fatalf("chain-linking regression: 6s of signals collapsed into %d bucket(s)", len(tl.Buckets))
	}
	for i, b := range tl.Buckets {
		if span := b.End.Sub(b.Start); span > DefaultTolerance {
			t.Errorf("bucket %d spans %s, exceeding tolerance %s", i, span, DefaultTolerance)
		}
	}
}

func TestAssembleEmpty(t *testing.T) {
	tl := Assemble(nil, DefaultTolerance)
	if len(tl.Buckets) != 0 {
		t.Errorf("empty input should produce no buckets, got %d", len(tl.Buckets))
	}
}

func TestInterestingFiltersNoise(t *testing.T) {
	sigs := signal.Set{
		sig(0, "loki", "debug chatter", signal.SevDebug, nil),
		sig(10*time.Second, "loki", "info chatter", signal.SevInfo, nil),
		sig(20*time.Second, "loki", "real error", signal.SevError, nil),
	}
	tl := Assemble(sigs, DefaultTolerance)

	interesting := tl.Interesting()
	if len(interesting) != 1 {
		t.Fatalf("want 1 interesting bucket, got %d", len(interesting))
	}
	if interesting[0].Signals[0].Title != "real error" {
		t.Errorf("wrong bucket kept: %q", interesting[0].Signals[0].Title)
	}
}

func TestDiagnoseRanksDeploymentHighest(t *testing.T) {
	labels := map[string]string{
		signal.LabelNamespace: "payments",
		signal.LabelWorkload:  "checkout",
	}

	anomaly := signal.Signal{
		Timestamp: base(),
		Source:    "prometheus",
		Title:     "p99 latency 3.2s",
		Severity:  signal.SevCritical,
		Type:      signal.TypeMetric,
		Labels:    labels,
	}

	deploy := signal.Signal{
		Timestamp: base().Add(-90 * time.Second),
		Source:    "kubernetes",
		Title:     "ScalingReplicaSet: checkout-7d4b",
		Severity:  signal.SevInfo,
		Type:      signal.TypeDeploy,
		Labels:    labels,
	}

	unrelated := signal.Signal{
		Timestamp: base().Add(-60 * time.Second),
		Source:    "loki",
		Title:     "cache warm complete",
		Severity:  signal.SevInfo,
		Type:      signal.TypeLog,
		Labels:    map[string]string{signal.LabelNamespace: "other-ns"},
	}

	// A cause that happens AFTER the anomaly must never be ranked.
	future := signal.Signal{
		Timestamp: base().Add(30 * time.Second),
		Source:    "kubernetes",
		Title:     "ScalingReplicaSet: later rollout",
		Severity:  signal.SevInfo,
		Type:      signal.TypeDeploy,
		Labels:    labels,
	}

	pool := signal.Set{deploy, unrelated, future, anomaly}
	hyps := Diagnose(anomaly, pool, DefaultDiagnoseOptions())

	if len(hyps) == 0 {
		t.Fatal("expected at least one hypothesis")
	}
	if hyps[0].Cause.Title != deploy.Title {
		t.Errorf("want deployment ranked first, got %q", hyps[0].Cause.Title)
	}
	for _, h := range hyps {
		if h.Cause.Title == future.Title {
			t.Error("a signal after the anomaly was ranked as a cause")
		}
	}
	if len(hyps[0].Evidence) == 0 {
		t.Error("top hypothesis has no evidence — rankings must be explainable")
	}
}

func TestDiagnoseRespectsLookback(t *testing.T) {
	anomaly := signal.Signal{Timestamp: base(), Severity: signal.SevError, Source: "prometheus", Title: "spike"}
	ancient := signal.Signal{
		Timestamp: base().Add(-2 * time.Hour),
		Type:      signal.TypeDeploy,
		Source:    "kubernetes",
		Title:     "very old deploy",
		Severity:  signal.SevInfo,
	}

	opts := DefaultDiagnoseOptions()
	opts.Lookback = 15 * time.Minute

	if hyps := Diagnose(anomaly, signal.Set{ancient, anomaly}, opts); len(hyps) != 0 {
		t.Errorf("signal outside lookback was ranked: %+v", hyps)
	}
}

func TestRelatedPrefersTraceID(t *testing.T) {
	const tid = "4bf92f3577b34da6a3ce929d0e0e4736"

	anchor := signal.Signal{
		Timestamp: base(), Source: "loki", Title: "error", TraceID: tid,
	}
	sameTrace := signal.Signal{
		// Deliberately far away in time: trace ID must win over proximity.
		Timestamp: base().Add(45 * time.Second), Source: "jaeger", Title: "span", TraceID: tid,
	}
	nearbyNoTrace := signal.Signal{
		Timestamp: base().Add(time.Millisecond), Source: "prometheus", Title: "metric",
	}

	got := Related(anchor, signal.Set{sameTrace, nearbyNoTrace}, 5*time.Second, 1)

	if len(got) != 1 {
		t.Fatalf("want 1 related signal, got %d", len(got))
	}
	if got[0].Title != "span" {
		t.Errorf("trace-ID match should win, got %q", got[0].Title)
	}
}

func TestRelatedRequiresBothTimeAndLabels(t *testing.T) {
	labels := map[string]string{signal.LabelNamespace: "payments", signal.LabelPod: "checkout-abc"}
	anchor := signal.Signal{Timestamp: base(), Source: "loki", Title: "anchor", Labels: labels}

	sameLabelsFarAway := signal.Signal{
		Timestamp: base().Add(time.Hour), Source: "prometheus", Title: "far", Labels: labels,
	}
	nearButDifferentLabels := signal.Signal{
		Timestamp: base().Add(time.Millisecond), Source: "prometheus", Title: "near",
		Labels: map[string]string{signal.LabelNamespace: "elsewhere"},
	}
	nearAndMatching := signal.Signal{
		Timestamp: base().Add(500 * time.Millisecond), Source: "prometheus", Title: "match", Labels: labels,
	}

	pool := signal.Set{sameLabelsFarAway, nearButDifferentLabels, nearAndMatching}
	got := Related(anchor, pool, 5*time.Second, 1)

	if len(got) != 1 || got[0].Title != "match" {
		t.Fatalf("want only the near+matching signal, got %+v", got)
	}
}

func TestFindAnomalyPicksEarliestOfHighestSeverity(t *testing.T) {
	sigs := signal.Set{
		sig(0, "loki", "info", signal.SevInfo, nil),
		sig(10*time.Second, "prometheus", "later critical", signal.SevCritical, nil),
		sig(5*time.Second, "kubernetes", "earlier critical", signal.SevCritical, nil),
		sig(2*time.Second, "loki", "an error", signal.SevError, nil),
	}

	got, found := FindAnomaly(sigs)
	if !found {
		t.Fatal("expected to find an anomaly")
	}
	if got.Title != "earlier critical" {
		t.Errorf("want the earliest critical signal, got %q", got.Title)
	}
}

func TestFindAnomalyIgnoresHealthyWindow(t *testing.T) {
	sigs := signal.Set{
		sig(0, "loki", "all good", signal.SevInfo, nil),
		sig(time.Second, "prometheus", "also fine", signal.SevDebug, nil),
	}
	if _, found := FindAnomaly(sigs); found {
		t.Error("a healthy window should report no anomaly")
	}
}

// stubHistory lets us assert the historical rule fires only with enough data.
type stubHistory struct{ together, total int }

func (s stubHistory) CoOccurrences(string, string) (int, int) { return s.together, s.total }

func TestHistoricalRuleNeedsMinimumSample(t *testing.T) {
	labels := map[string]string{signal.LabelNamespace: "payments"}
	anomaly := signal.Signal{Timestamp: base(), Severity: signal.SevError, Labels: labels, Source: "prometheus", Title: "spike"}
	cause := signal.Signal{
		Timestamp: base().Add(-time.Minute), Type: signal.TypeLog,
		Source: "loki", Title: "pull failed", Severity: signal.SevInfo, Labels: labels,
	}
	pool := signal.Set{cause, anomaly}

	// 2 of 2 looks perfect but is too small a sample; the rule must not fire.
	small := DefaultDiagnoseOptions()
	small.MinScore = 0
	small.History = stubHistory{together: 2, total: 2}
	smallHyps := Diagnose(anomaly, pool, small)

	big := DefaultDiagnoseOptions()
	big.MinScore = 0
	big.History = stubHistory{together: 8, total: 10}
	bigHyps := Diagnose(anomaly, pool, big)

	if len(smallHyps) == 0 || len(bigHyps) == 0 {
		t.Fatal("expected hypotheses in both cases")
	}
	if bigHyps[0].Score <= smallHyps[0].Score {
		t.Errorf("a well-supported history should raise the score: small=%.3f big=%.3f",
			smallHyps[0].Score, bigHyps[0].Score)
	}
}
