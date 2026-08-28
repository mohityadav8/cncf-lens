package correlate

import (
	"fmt"
	"sort"
	"time"

	"github.com/cncf-lens/lens/internal/signal"
)

// Hypothesis is one candidate explanation for an anomaly, with the evidence
// that produced its score.
//
// Every field here exists to be printed. An unexplained ranking is useless to
// an on-call engineer at 3am — they need to be able to disagree with the tool,
// which means they need to see its reasoning.
type Hypothesis struct {
	// Cause is the signal we believe may have caused the anomaly.
	Cause signal.Signal

	// Score is the summed weight of all matched evidence rules, normalised to
	// 0..1 against the theoretical maximum.
	Score float64

	// Lead is how long before the anomaly this cause occurred.
	Lead time.Duration

	// Evidence lists the human-readable reasons this scored where it did.
	Evidence []string
}

// Confidence buckets the score into words, because a bare "0.62" invites false
// precision that the underlying heuristics do not earn.
func (h Hypothesis) Confidence() string {
	switch {
	case h.Score >= 0.70:
		return "likely"
	case h.Score >= 0.40:
		return "possible"
	default:
		return "weak"
	}
}

// causalRule is one scoring heuristic.
type causalRule struct {
	name   string
	weight float64
	// apply returns (matched, explanation).
	apply func(cause signal.Signal, anomaly signal.Signal, lead time.Duration, hist History) (bool, string)
}

// History provides past co-occurrence data so the engine can learn, cheaply,
// which change types have preceded anomalies on *this* cluster before. It is
// backed by the local cache; an empty History simply means every rule that
// depends on history scores zero, degrading gracefully on first run.
type History interface {
	// CoOccurrences returns how many times a cause of this kind has preceded an
	// anomaly of this kind, and how many times that cause was observed at all.
	CoOccurrences(causeKey, anomalyKey string) (together, causeTotal int)
}

// nilHistory is used when no cache is available.
type nilHistory struct{}

func (nilHistory) CoOccurrences(string, string) (int, int) { return 0, 0 }

// NoHistory returns a History that knows nothing. Used on first run and in
// tests where we want deterministic scores.
func NoHistory() History { return nilHistory{} }

// rules is the full rule set, evaluated in order. Weights were chosen so that
// the two rules an engineer would themselves apply first — "was it a
// deployment?" and "does it involve the same workload?" — dominate.
var rules = []causalRule{
	{
		name:   "change-vector",
		weight: 0.30,
		apply: func(cause, _ signal.Signal, _ time.Duration, _ History) (bool, string) {
			// Deployments, config changes and scaling events are the overwhelming
			// majority of real root causes in Kubernetes. Weight them heavily.
			if cause.Type == signal.TypeDeploy {
				return true, "is a deployment or config change — the most common root cause class"
			}
			return false, ""
		},
	},
	{
		name:   "identity-overlap",
		weight: 0.25,
		apply: func(cause, anomaly signal.Signal, _ time.Duration, _ History) (bool, string) {
			n := signal.LabelOverlap(cause, anomaly)
			if n == 0 {
				return false, ""
			}
			return true, fmt.Sprintf("shares %d Kubernetes identity label(s) with the anomaly", n)
		},
	},
	{
		name:   "tight-precedence",
		weight: 0.20,
		apply: func(_, _ signal.Signal, lead time.Duration, _ History) (bool, string) {
			// Causes that fire immediately before an anomaly are more suspicious
			// than ones from twenty minutes earlier. "Tight" is two minutes:
			// long enough for a rollout to propagate, short enough to be causal.
			if lead > 0 && lead <= 2*time.Minute {
				return true, fmt.Sprintf("occurred %s before the anomaly", lead.Round(time.Second))
			}
			return false, ""
		},
	},
	{
		name:   "severity",
		weight: 0.10,
		apply: func(cause, _ signal.Signal, _ time.Duration, _ History) (bool, string) {
			if cause.Severity >= signal.SevWarning {
				return true, fmt.Sprintf("was itself logged at %s severity", cause.Severity)
			}
			return false, ""
		},
	},
	{
		name:   "trace-linked",
		weight: 0.15,
		apply: func(cause, anomaly signal.Signal, _ time.Duration, _ History) (bool, string) {
			if cause.TraceID != "" && cause.TraceID == anomaly.TraceID {
				return true, "shares a trace ID with the anomaly — a direct causal link"
			}
			return false, ""
		},
	},
	{
		name:   "historical-cooccurrence",
		weight: 0.20,
		apply: func(cause, anomaly signal.Signal, _ time.Duration, hist History) (bool, string) {
			together, total := hist.CoOccurrences(CauseKey(cause), AnomalyKey(anomaly))
			// Require a minimum sample size. Two out of two looks like a perfect
			// correlation and means nothing.
			if total < 3 || together == 0 {
				return false, ""
			}
			ratio := float64(together) / float64(total)
			if ratio < 0.5 {
				return false, ""
			}
			return true, fmt.Sprintf(
				"has preceded this anomaly %d of the last %d times it occurred", together, total)
		},
	},
}

// maxScore is the sum of all rule weights, used to normalise into 0..1.
var maxScore = func() float64 {
	var s float64
	for _, r := range rules {
		s += r.weight
	}
	return s
}()

// DiagnoseOptions tunes hypothesis generation.
type DiagnoseOptions struct {
	// Lookback is how far before the anomaly to search for causes.
	Lookback time.Duration
	// MaxResults caps the returned hypotheses.
	MaxResults int
	// MinScore drops hypotheses below this normalised score entirely, so the
	// output is not padded with noise to fill a quota.
	MinScore float64
	// History supplies past co-occurrence data. Nil means NoHistory().
	History History
}

// DefaultDiagnoseOptions returns sensible defaults.
func DefaultDiagnoseOptions() DiagnoseOptions {
	return DiagnoseOptions{
		Lookback:   15 * time.Minute,
		MaxResults: 5,
		MinScore:   0.25,
		History:    NoHistory(),
	}
}

// Diagnose ranks candidate causes for an anomaly.
//
// Candidates are drawn only from signals that *precede* the anomaly, because a
// cause cannot follow its effect. This single constraint eliminates most of the
// spurious correlations a naive "what else was happening" query would surface.
func Diagnose(anomaly signal.Signal, pool signal.Set, opts DiagnoseOptions) []Hypothesis {
	if opts.Lookback <= 0 {
		opts.Lookback = 15 * time.Minute
	}
	if opts.MaxResults <= 0 {
		opts.MaxResults = 5
	}
	if opts.History == nil {
		opts.History = NoHistory()
	}

	earliest := anomaly.Timestamp.Add(-opts.Lookback)
	var out []Hypothesis

	for _, cause := range pool {
		if sameSignal(cause, anomaly) {
			continue
		}
		// Strict precedence. Equal timestamps are excluded because at our
		// tolerance they are indistinguishable from simultaneity, and
		// simultaneous events are correlated, not causal.
		if !cause.Timestamp.Before(anomaly.Timestamp) {
			continue
		}
		if cause.Timestamp.Before(earliest) {
			continue
		}

		lead := anomaly.Timestamp.Sub(cause.Timestamp)

		var score float64
		var evidence []string
		for _, r := range rules {
			ok, why := r.apply(cause, anomaly, lead, opts.History)
			if ok {
				score += r.weight
				evidence = append(evidence, why)
			}
		}

		normalised := score / maxScore
		if normalised < opts.MinScore {
			continue
		}

		out = append(out, Hypothesis{
			Cause:    cause,
			Score:    normalised,
			Lead:     lead,
			Evidence: evidence,
		})
	}

	// Highest score first; ties broken by recency, since a closer cause is the
	// more actionable one to check first.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].Lead < out[j].Lead
		}
		return out[i].Score > out[j].Score
	})

	if len(out) > opts.MaxResults {
		out = out[:opts.MaxResults]
	}
	return out
}

// FindAnomaly picks the most likely anomaly signal from a set, used when the
// user runs `lens diagnose` without naming one explicitly. We take the highest
// severity signal, breaking ties toward the earliest — the start of a failure
// cascade is more informative than its tail.
func FindAnomaly(sigs signal.Set) (signal.Signal, bool) {
	if len(sigs) == 0 {
		return signal.Signal{}, false
	}
	best := sigs[0]
	found := false
	for _, s := range sigs {
		if s.Severity < signal.SevWarning {
			continue
		}
		if !found || s.Severity > best.Severity ||
			(s.Severity == best.Severity && s.Timestamp.Before(best.Timestamp)) {
			best = s
			found = true
		}
	}
	return best, found
}

// causeKey and anomalyKey produce the coarse identifiers used for historical
// co-occurrence lookups. They deliberately drop pod names and timestamps: we
// want to learn "image pull failures precede latency spikes in this namespace",
// not memorise one specific pod's bad afternoon.
// CauseKey is the coarse identifier used for historical co-occurrence lookups.
func CauseKey(s signal.Signal) string {
	ns := ""
	if s.Labels != nil {
		ns = s.Labels[signal.LabelNamespace]
	}
	return fmt.Sprintf("%s/%s/%s", s.Source, s.Type, ns)
}

// AnomalyKey is the coarse identifier for the anomaly side of a co-occurrence.
func AnomalyKey(s signal.Signal) string {
	ns := ""
	wl := ""
	if s.Labels != nil {
		ns = s.Labels[signal.LabelNamespace]
		wl = s.Labels[signal.LabelWorkload]
	}
	return fmt.Sprintf("%s/%s/%s/%s", s.Source, s.Type, ns, wl)
}
