// Package correlate contains the engine that turns a pile of signals from
// unrelated backends into an explainable, time-ordered story.
package correlate

import (
	"time"

	"github.com/cncf-lens/lens/internal/signal"
)

// DefaultTolerance is the window within which signals from different backends
// are considered simultaneous.
//
// Why 500ms: Prometheus scrapes on a 15s interval and timestamps samples at
// scrape time, Kubernetes events carry second precision, Jaeger spans carry
// nanosecond precision, and container clocks drift. Anything tighter than this
// splits genuinely co-occurring events into separate buckets; anything much
// wider starts merging unrelated activity on a busy cluster.
const DefaultTolerance = 500 * time.Millisecond

// Bucket is a group of signals the engine believes happened "at the same time".
type Bucket struct {
	// Start is the timestamp of the earliest signal in the bucket, and acts as
	// the bucket's canonical time.
	Start time.Time
	// End is the timestamp of the latest signal in the bucket.
	End time.Time
	// Signals are the members, time-sorted.
	Signals signal.Set
}

// Sources lists the distinct adapters that contributed to this bucket. A bucket
// touched by three backends is far more interesting than one touched by a
// single chatty log stream, and the renderer highlights it accordingly.
func (b Bucket) Sources() []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range b.Signals {
		if !seen[s.Source] {
			seen[s.Source] = true
			out = append(out, s.Source)
		}
	}
	return out
}

// MaxSeverity returns the highest severity present in the bucket.
func (b Bucket) MaxSeverity() signal.Severity {
	max := signal.SevDebug
	for _, s := range b.Signals {
		if s.Severity > max {
			max = s.Severity
		}
	}
	return max
}

// CrossSource reports whether more than one backend saw activity in this
// bucket. This is the cheapest and most reliable signal of a real event: a
// spike that shows up in metrics AND logs AND events is not noise.
func (b Bucket) CrossSource() bool { return len(b.Sources()) > 1 }

// Timeline is the assembled, bucketed view of an incident window.
type Timeline struct {
	From      time.Time
	To        time.Time
	Tolerance time.Duration
	Buckets   []Bucket
}

// Assemble groups a signal set into time buckets.
//
// The algorithm is a single-pass sweep over time-sorted signals. A signal joins
// the current bucket if it falls within Tolerance of the bucket's *start*, not
// of the previous signal. Anchoring to the start is deliberate: anchoring to
// the previous signal lets a dense stream of log lines chain-link into one
// unbounded bucket spanning minutes, which destroys the whole point.
func Assemble(sigs signal.Set, tolerance time.Duration) Timeline {
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}

	sorted := make(signal.Set, len(sigs))
	copy(sorted, sigs)
	sorted.SortByTime()

	tl := Timeline{Tolerance: tolerance}
	if len(sorted) == 0 {
		return tl
	}
	tl.From = sorted[0].Timestamp
	tl.To = sorted[len(sorted)-1].Timestamp

	current := Bucket{
		Start:   sorted[0].Timestamp,
		End:     sorted[0].Timestamp,
		Signals: signal.Set{sorted[0]},
	}

	for _, s := range sorted[1:] {
		if s.Timestamp.Sub(current.Start) <= tolerance {
			current.Signals = append(current.Signals, s)
			if s.Timestamp.After(current.End) {
				current.End = s.Timestamp
			}
			continue
		}
		tl.Buckets = append(tl.Buckets, current)
		current = Bucket{Start: s.Timestamp, End: s.Timestamp, Signals: signal.Set{s}}
	}
	tl.Buckets = append(tl.Buckets, current)

	return tl
}

// Interesting returns only the buckets worth an engineer's attention: those
// seen by more than one backend, or containing at least a warning.
//
// On a production cluster a five-minute window can hold tens of thousands of
// log lines. Showing all of them is the same as showing none.
func (t Timeline) Interesting() []Bucket {
	var out []Bucket
	for _, b := range t.Buckets {
		if b.CrossSource() || b.MaxSeverity() >= signal.SevWarning {
			out = append(out, b)
		}
	}
	return out
}

// TraceGroups partitions signals by TraceID. Signals with no trace ID land
// under the empty key. This gives `lens trace` its per-request view: every log
// line, span and metric sample that carried the same trace context.
func TraceGroups(sigs signal.Set) map[string]signal.Set {
	out := make(map[string]signal.Set)
	for _, s := range sigs {
		out[s.TraceID] = append(out[s.TraceID], s)
	}
	for k := range out {
		out[k].SortByTime()
	}
	return out
}

// IdentityGroups partitions signals by their canonical Kubernetes identity,
// used to answer "show me everything about this pod, from every backend".
func IdentityGroups(sigs signal.Set) map[string]signal.Set {
	out := make(map[string]signal.Set)
	for _, s := range sigs {
		out[s.Identity()] = append(out[s.Identity()], s)
	}
	for k := range out {
		out[k].SortByTime()
	}
	return out
}

// Related finds signals from *other* backends that plausibly describe the same
// thing as the anchor signal. This is the primitive behind "jump from this log
// line to the metric spike that caused it".
//
// Matching is tiered, strongest first:
//  1. Exact trace ID match — unambiguous, returned immediately.
//  2. Time proximity plus at least minOverlap shared identity labels.
//
// We require BOTH time and label agreement in tier 2 because either alone is
// far too loose: on a busy cluster thousands of signals share a timestamp, and
// a pod's labels match across its entire lifetime.
func Related(anchor signal.Signal, pool signal.Set, window time.Duration, minOverlap int) signal.Set {
	if window <= 0 {
		window = 5 * time.Second
	}
	if minOverlap < 1 {
		minOverlap = 1
	}

	var out signal.Set

	if anchor.TraceID != "" {
		for _, s := range pool {
			if s.TraceID == anchor.TraceID && !sameSignal(s, anchor) {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			out.SortByTime()
			return out
		}
	}

	for _, s := range pool {
		if sameSignal(s, anchor) || s.Source == anchor.Source {
			continue
		}
		delta := s.Timestamp.Sub(anchor.Timestamp)
		if delta < 0 {
			delta = -delta
		}
		if delta > window {
			continue
		}
		if signal.LabelOverlap(anchor, s) < minOverlap {
			continue
		}
		out = append(out, s)
	}

	out.SortByTime()
	return out
}

// sameSignal reports identity for dedup purposes. We compare the fields that
// together uniquely identify an observation rather than using pointer equality,
// because signals are passed by value throughout.
func sameSignal(a, b signal.Signal) bool {
	return a.Timestamp.Equal(b.Timestamp) &&
		a.Source == b.Source &&
		a.Title == b.Title &&
		a.Detail == b.Detail
}
