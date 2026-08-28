// Package signal defines the universal data type that every backend adapter
// produces. Metrics, traces, logs, Kubernetes events and security alerts are
// all normalised into a Signal so the correlation engine can reason about them
// on a single timeline without caring where they came from.
package signal

import (
	"sort"
	"strings"
	"time"
)

// Type classifies what kind of observability data a Signal carries.
type Type string

const (
	TypeMetric   Type = "metric"
	TypeTrace    Type = "trace"
	TypeLog      Type = "log"
	TypeEvent    Type = "event"
	TypeSecurity Type = "security"
	TypeDeploy   Type = "deploy"
)

// AllTypes returns every known signal type. Used by adapters that declare
// broad capabilities and by the CLI for validating --type filters.
func AllTypes() []Type {
	return []Type{TypeMetric, TypeTrace, TypeLog, TypeEvent, TypeSecurity, TypeDeploy}
}

// Severity ranks how much attention a Signal deserves. Ordering matters:
// higher values are more severe, so they sort and filter naturally.
type Severity int

const (
	SevDebug Severity = iota
	SevInfo
	SevWarning
	SevError
	SevCritical
)

var severityNames = map[Severity]string{
	SevDebug:    "debug",
	SevInfo:     "info",
	SevWarning:  "warning",
	SevError:    "error",
	SevCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// ParseSeverity maps the many spellings backends use onto our scale. Falco says
// "Critical", Kubernetes says "Warning", Loki lines say "ERROR" — all land here.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace":
		return SevDebug
	case "info", "informational", "normal", "notice":
		return SevInfo
	case "warn", "warning":
		return SevWarning
	case "err", "error", "failed", "failure":
		return SevError
	case "crit", "critical", "fatal", "emergency", "alert":
		return SevCritical
	default:
		return SevInfo
	}
}

// Signal is one observation at one instant from one backend.
//
// The Labels map is the join key that makes correlation possible. Every adapter
// is responsible for populating the canonical Kubernetes identity labels
// (namespace, pod, service, container) where it can, because the correlation
// engine scores relatedness primarily by label overlap.
type Signal struct {
	// Timestamp is when the observation happened at the source, not when we
	// fetched it. Always stored in UTC.
	Timestamp time.Time `json:"timestamp"`

	Type     Type     `json:"type"`
	Severity Severity `json:"-"`

	// Source names the adapter that produced this Signal ("prometheus", "loki").
	Source string `json:"source"`

	// Title is a short human-readable summary, shown in terminal timelines.
	Title string `json:"title"`

	// Detail is the full payload: a log line, an event message, a span name.
	Detail string `json:"detail,omitempty"`

	// Labels carry the identity of whatever emitted this. Canonical keys are
	// listed in the Label* constants below.
	Labels map[string]string `json:"labels,omitempty"`

	// Value is set for numeric signals (metrics). Nil for everything else so we
	// can distinguish "zero" from "not a numeric signal".
	Value *float64 `json:"value,omitempty"`

	// TraceID links this Signal to a distributed trace when one is known. This
	// is the strongest correlation key available and is checked before labels.
	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`

	// Duration is set for signals that span time rather than occurring at an
	// instant, such as trace spans.
	Duration time.Duration `json:"duration,omitempty"`
}

// Canonical label keys. Adapters should use these exact strings so that label
// overlap scoring works across backends that natively use different names.
const (
	LabelNamespace = "namespace"
	LabelPod       = "pod"
	LabelService   = "service"
	LabelContainer = "container"
	LabelNode      = "node"
	LabelWorkload  = "workload"
	LabelCluster   = "cluster"
)

// MarshalJSON is customised only to render Severity as a readable string
// instead of an integer, which matters for `--output=json` consumers.
func (s Signal) SeverityString() string { return s.Severity.String() }

// Identity returns the canonical Kubernetes identity of this Signal as a
// stable string, used as a grouping key. Empty when the Signal carries no
// identity labels at all.
func (s Signal) Identity() string {
	if s.Labels == nil {
		return ""
	}
	var parts []string
	for _, k := range []string{LabelCluster, LabelNamespace, LabelWorkload, LabelPod} {
		if v := s.Labels[k]; v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, ",")
}

// LabelOverlap counts how many canonical identity labels two Signals share with
// equal values. This is the primary relatedness heuristic in the correlation
// engine: two signals from different backends that agree on namespace+pod are
// almost certainly describing the same thing.
func LabelOverlap(a, b Signal) int {
	if a.Labels == nil || b.Labels == nil {
		return 0
	}
	canonical := []string{
		LabelCluster, LabelNamespace, LabelService,
		LabelWorkload, LabelPod, LabelContainer, LabelNode,
	}
	n := 0
	for _, k := range canonical {
		av, aok := a.Labels[k]
		bv, bok := b.Labels[k]
		if aok && bok && av != "" && av == bv {
			n++
		}
	}
	return n
}

// SetLabel safely writes a label, allocating the map on first use. Empty values
// are dropped rather than stored, so that LabelOverlap never matches on "".
func (s *Signal) SetLabel(k, v string) {
	if v == "" {
		return
	}
	if s.Labels == nil {
		s.Labels = make(map[string]string, 4)
	}
	s.Labels[k] = v
}

// Set is an ordered collection of Signals from one or more adapters.
type Set []Signal

// SortByTime orders signals oldest-first, which is the order every renderer
// expects. Ties are broken by source name so output is deterministic across
// runs — important for golden-file tests and for diffing two incident reports.
func (s Set) SortByTime() {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Timestamp.Equal(s[j].Timestamp) {
			if s[i].Source == s[j].Source {
				return s[i].Title < s[j].Title
			}
			return s[i].Source < s[j].Source
		}
		return s[i].Timestamp.Before(s[j].Timestamp)
	})
}

// FilterType returns only the signals matching any of the given types. Passing
// no types returns the set unchanged, so callers can pass a nil filter freely.
func (s Set) FilterType(types ...Type) Set {
	if len(types) == 0 {
		return s
	}
	want := make(map[Type]bool, len(types))
	for _, t := range types {
		want[t] = true
	}
	out := make(Set, 0, len(s))
	for _, sig := range s {
		if want[sig.Type] {
			out = append(out, sig)
		}
	}
	return out
}

// FilterSeverity returns signals at or above the given severity.
func (s Set) FilterSeverity(min Severity) Set {
	out := make(Set, 0, len(s))
	for _, sig := range s {
		if sig.Severity >= min {
			out = append(out, sig)
		}
	}
	return out
}

// Window returns the signals falling inside [from, to]. Both bounds inclusive.
func (s Set) Window(from, to time.Time) Set {
	out := make(Set, 0, len(s))
	for _, sig := range s {
		if sig.Timestamp.Before(from) || sig.Timestamp.After(to) {
			continue
		}
		out = append(out, sig)
	}
	return out
}

// Span reports the earliest and latest timestamps in the set. ok is false when
// the set is empty, so callers do not have to special-case zero times.
func (s Set) Span() (from, to time.Time, ok bool) {
	if len(s) == 0 {
		return time.Time{}, time.Time{}, false
	}
	from, to = s[0].Timestamp, s[0].Timestamp
	for _, sig := range s[1:] {
		if sig.Timestamp.Before(from) {
			from = sig.Timestamp
		}
		if sig.Timestamp.After(to) {
			to = sig.Timestamp
		}
	}
	return from, to, true
}

// BySource groups signals by the adapter that produced them, for per-backend
// summaries in the terminal renderer.
func (s Set) BySource() map[string]Set {
	out := make(map[string]Set)
	for _, sig := range s {
		out[sig.Source] = append(out[sig.Source], sig)
	}
	return out
}
