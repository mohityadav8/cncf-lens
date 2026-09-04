// Package falco implements the Adapter interface against Falco, the CNCF
// runtime security engine.
//
// Falco has no query API of its own — it is a streaming detector that pushes
// alerts outward. In practice teams collect those alerts in one of two places,
// and this adapter reads both:
//
//   - Falcosidekick's /events endpoint, when the cluster runs the standard
//     falcosidekick fan-out component.
//   - A JSON-lines file or HTTP endpoint, when alerts are written by Falco's
//     own file_output or http_output.
//
// Either way lens ends up with the same Signals, so `lens audit` and
// `lens diagnose` can correlate a container escape attempt against the
// deployment that preceded it.
package falco

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/signal"
)

// Adapter reads Falco runtime security alerts.
type Adapter struct {
	http *adapter.HTTPClient
	name string

	// file, when set, makes the adapter read a JSON-lines file instead of
	// talking to falcosidekick. This is how lens works against a cluster that
	// only configures Falco's file_output, and it makes the adapter trivially
	// testable without a live Falco.
	file string

	// minPriority drops alerts below a Falco priority level before they ever
	// reach the correlation engine. Falco is deliberately chatty at Debug and
	// Informational, and an audit drowning in noise gets ignored.
	minPriority signal.Severity
}

// New builds a Falco adapter reading from falcosidekick over HTTP.
func New(name, baseURL, token string, insecure bool, timeout time.Duration) *Adapter {
	if name == "" {
		name = "falco"
	}
	return &Adapter{
		name:        name,
		http:        adapter.NewHTTPClient(baseURL, token, insecure, timeout),
		minPriority: signal.SevWarning,
	}
}

// NewFromFile builds an adapter that reads Falco's JSON-lines output from disk.
func NewFromFile(name, path string) *Adapter {
	if name == "" {
		name = "falco"
	}
	return &Adapter{name: name, file: path, minPriority: signal.SevWarning}
}

// SetMinPriority overrides the noise floor. Passing SevDebug disables filtering.
func (a *Adapter) SetMinPriority(s signal.Severity) { a.minPriority = s }

func (a *Adapter) Name() string { return a.name }

func (a *Adapter) Capabilities() []signal.Type {
	return []signal.Type{signal.TypeSecurity}
}

func (a *Adapter) HealthCheck(ctx context.Context) error {
	if a.file != "" {
		fi, err := os.Stat(a.file)
		if err != nil {
			return fmt.Errorf("falco output file %s is not readable: %w", a.file, err)
		}
		if fi.IsDir() {
			return fmt.Errorf("falco `file` points at a directory, not a JSON-lines file: %s", a.file)
		}
		return nil
	}
	if err := a.http.Ping(ctx, "/ping"); err != nil {
		return fmt.Errorf("falcosidekick unreachable: %w", err)
	}
	return nil
}

// Fetch retrieves alerts within the query window.
func (a *Adapter) Fetch(ctx context.Context, q adapter.Query) (signal.Set, error) {
	if !q.WantsType(signal.TypeSecurity) {
		return nil, nil
	}

	var alerts []alert
	var err error
	if a.file != "" {
		alerts, err = a.readFile()
	} else {
		alerts, err = a.readHTTP(ctx, q)
	}
	if err != nil {
		return nil, err
	}

	var out signal.Set
	for _, al := range alerts {
		s, ok := a.toSignal(al)
		if !ok {
			continue
		}
		// Falcosidekick has no server-side time filter, so the window is
		// applied here. Cheap: alert volumes are orders of magnitude below
		// log volumes.
		if s.Timestamp.Before(q.From) || s.Timestamp.After(q.To) {
			continue
		}
		if s.Severity < a.minPriority {
			continue
		}
		if q.Namespace != "" && s.Labels[signal.LabelNamespace] != q.Namespace {
			continue
		}
		if q.Pod != "" && s.Labels[signal.LabelPod] != q.Pod {
			continue
		}
		out = append(out, s)
	}

	if q.Limit > 0 && len(out) > q.Limit {
		// Keep the most recent, since an audit cares about what is happening
		// now rather than the start of the retention window.
		out = out[len(out)-q.Limit:]
	}
	out.SortByTime()
	return out, nil
}

func (a *Adapter) readHTTP(ctx context.Context, q adapter.Query) ([]alert, error) {
	params := url.Values{}
	if q.Limit > 0 {
		params.Set("limit", fmt.Sprint(q.Limit))
	}

	// Falcosidekick returns a bare array from /events.
	var alerts []alert
	if err := a.http.GetJSON(ctx, "/events", params, &alerts); err != nil {
		return nil, err
	}
	return alerts, nil
}

// readFile parses Falco's JSON-lines output. A malformed line is skipped rather
// than failing the read: Falco can be killed mid-write, leaving a truncated
// final line, and losing every earlier alert to that would be absurd.
func (a *Adapter) readFile() ([]alert, error) {
	f, err := os.Open(a.file)
	if err != nil {
		return nil, fmt.Errorf("opening falco output %s: %w", a.file, err)
	}
	defer f.Close()

	var alerts []alert
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var al alert
		if err := json.Unmarshal([]byte(line), &al); err != nil {
			continue
		}
		alerts = append(alerts, al)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading falco output %s: %w", a.file, err)
	}
	return alerts, nil
}

// toSignal converts one Falco alert. ok is false when the alert carries no
// usable timestamp, since an uncorrelatable signal is worse than none.
func (a *Adapter) toSignal(al alert) (signal.Signal, bool) {
	ts, ok := parseTime(al)
	if !ok {
		return signal.Signal{}, false
	}

	s := signal.Signal{
		Timestamp: ts.UTC(),
		Type:      signal.TypeSecurity,
		Source:    a.name,
		Severity:  parsePriority(al.Priority),
		Title:     al.Rule,
		Detail:    strings.TrimSpace(al.Output),
	}

	// Falco's output_fields use its own naming. Mapping them onto the canonical
	// keys is what lets a container-escape alert join to the Prometheus metric
	// and the Kubernetes event for the same pod.
	f := al.OutputFields
	s.SetLabel(signal.LabelNamespace, firstNonEmpty(
		str(f["k8s.ns.name"]), str(f["k8s.ns"]), str(f["container.namespace"])))
	s.SetLabel(signal.LabelPod, firstNonEmpty(
		str(f["k8s.pod.name"]), str(f["k8s.pod"])))
	s.SetLabel(signal.LabelContainer, firstNonEmpty(
		str(f["container.name"]), str(f["k8s.container.name"])))
	s.SetLabel(signal.LabelNode, firstNonEmpty(
		str(f["k8s.node.name"]), al.Hostname))

	if s.Title == "" {
		s.Title = "Falco alert"
	}
	return s, true
}

// parseTime reads whichever timestamp form this Falco version emitted. Older
// builds send only `time`; newer ones add nanosecond `output_fields.evt.time`.
func parseTime(al alert) (time.Time, bool) {
	if al.Time != "" {
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if t, err := time.Parse(layout, al.Time); err == nil {
				return t, true
			}
		}
	}
	if raw, ok := al.OutputFields["evt.time"]; ok {
		switch v := raw.(type) {
		case float64:
			// Falco emits epoch nanoseconds here.
			return time.Unix(0, int64(v)), true
		case string:
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

// parsePriority maps Falco's syslog-style priority names onto our scale.
//
// Falco's Notice sits above Informational in its own ordering but is not
// something that should wake anyone, so it lands on info rather than warning.
func parsePriority(p string) signal.Severity {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "emergency", "alert", "critical":
		return signal.SevCritical
	case "error":
		return signal.SevError
	case "warning":
		return signal.SevWarning
	case "notice", "informational", "info":
		return signal.SevInfo
	case "debug":
		return signal.SevDebug
	default:
		// An unrecognised priority from a future Falco version should surface,
		// not vanish under the default noise floor.
		return signal.SevWarning
	}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- Falco wire format ------------------------------------------------------

// alert is one Falco alert as emitted by http_output, file_output and
// falcosidekick, which all share this shape.
type alert struct {
	Time         string         `json:"time"`
	Rule         string         `json:"rule"`
	Priority     string         `json:"priority"`
	Output       string         `json:"output"`
	Source       string         `json:"source"`
	Hostname     string         `json:"hostname"`
	Tags         []string       `json:"tags"`
	OutputFields map[string]any `json:"output_fields"`
}
