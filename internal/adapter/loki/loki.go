// Package loki implements the Adapter interface against Grafana Loki's
// query_range API. It also works against Grafana Cloud Logs and any backend
// speaking the LogQL HTTP protocol.
package loki

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cncf-lens/lens/internal/adapter"
	"github.com/cncf-lens/lens/internal/signal"
)

// Adapter queries a Loki-compatible log backend.
type Adapter struct {
	http *adapter.HTTPClient
	name string
}

// New builds a Loki adapter.
func New(name, baseURL, token string, insecure bool, timeout time.Duration) *Adapter {
	if name == "" {
		name = "loki"
	}
	return &Adapter{name: name, http: adapter.NewHTTPClient(baseURL, token, insecure, timeout)}
}

func (a *Adapter) Name() string { return a.name }

func (a *Adapter) Capabilities() []signal.Type { return []signal.Type{signal.TypeLog} }

func (a *Adapter) HealthCheck(ctx context.Context) error {
	if err := a.http.Ping(ctx, "/ready"); err != nil {
		return fmt.Errorf("loki health check failed: %w", err)
	}
	return nil
}

// Fetch pulls log lines matching the query window and identity.
func (a *Adapter) Fetch(ctx context.Context, q adapter.Query) (signal.Set, error) {
	if !q.WantsType(signal.TypeLog) {
		return nil, nil
	}

	selector := buildSelector(q)
	if selector == "" {
		// Loki requires at least one non-empty label matcher. Rather than
		// error, we decline: a namespace-wide log dump with no filter is never
		// what the user wanted and would hammer the backend.
		return nil, fmt.Errorf("loki needs at least --namespace or --pod to build a stream selector")
	}

	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 500
	}

	params := url.Values{
		"query":     {selector},
		"start":     {strconv.FormatInt(q.From.UnixNano(), 10)},
		"end":       {strconv.FormatInt(q.To.UnixNano(), 10)},
		"limit":     {strconv.Itoa(limit)},
		"direction": {"backward"},
	}

	var resp queryResponse
	if err := a.http.GetJSON(ctx, "/loki/api/v1/query_range", params, &resp); err != nil {
		return nil, err
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("loki returned status %q", resp.Status)
	}

	var out signal.Set
	for _, stream := range resp.Data.Result {
		for _, entry := range stream.Values {
			if len(entry) < 2 {
				continue
			}
			nsec, err := strconv.ParseInt(entry[0], 10, 64)
			if err != nil {
				continue
			}
			line := entry[1]

			s := signal.Signal{
				Timestamp: time.Unix(0, nsec).UTC(),
				Type:      signal.TypeLog,
				Source:    a.name,
				Severity:  severityFromLine(line),
				Title:     summarise(line),
				Detail:    strings.TrimSpace(line),
				TraceID:   extractTraceID(line),
			}
			applyStreamLabels(&s, stream.Stream)
			out = append(out, s)
		}
	}

	out.SortByTime()
	return out, nil
}

// buildSelector constructs a LogQL stream selector from the query identity.
func buildSelector(q adapter.Query) string {
	var matchers []string
	if q.Namespace != "" {
		matchers = append(matchers, fmt.Sprintf("namespace=%q", q.Namespace))
	}
	if q.Pod != "" {
		matchers = append(matchers, fmt.Sprintf("pod=%q", q.Pod))
	}
	if q.Workload != "" && q.Pod == "" {
		// Regex match so we catch every pod of the deployment.
		matchers = append(matchers, fmt.Sprintf("pod=~%q", q.Workload+".*"))
	}
	if len(matchers) == 0 {
		return ""
	}
	sel := "{" + strings.Join(matchers, ",") + "}"

	// When chasing a specific trace, push the filter server-side. This turns a
	// 500-line client-side scan into a targeted query and is dramatically
	// faster on a busy namespace.
	if q.TraceID != "" {
		sel += fmt.Sprintf(" |= %q", q.TraceID)
	}
	return sel
}

// traceIDPattern matches the hex trace IDs emitted by OpenTelemetry (32 hex
// chars) and legacy Jaeger (16 hex chars), in the common key=value and
// JSON-field spellings.
var traceIDPattern = regexp.MustCompile(`(?i)(?:trace[_-]?id"?\s*[=:]\s*"?)([0-9a-f]{16,32})`)

// extractTraceID pulls a trace ID out of a log line so that a log can be
// joined to a span. This is the single highest-value correlation in the whole
// tool: it turns "an error happened" into "this exact request failed here".
func extractTraceID(line string) string {
	m := traceIDPattern.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	return strings.ToLower(m[1])
}

// severityFromLine infers a level from the log text. Loki does not carry a
// structured level by default, so this pattern match is what lets us filter
// noise without requiring every team to standardise their log format first.
func severityFromLine(line string) signal.Severity {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "PANIC"), strings.Contains(upper, "FATAL"):
		return signal.SevCritical
	case strings.Contains(upper, "ERROR"), strings.Contains(upper, "ERR "),
		strings.Contains(upper, `"level":"error"`), strings.Contains(upper, "EXCEPTION"):
		return signal.SevError
	case strings.Contains(upper, "WARN"):
		return signal.SevWarning
	case strings.Contains(upper, "DEBUG"), strings.Contains(upper, "TRACE"):
		return signal.SevDebug
	default:
		return signal.SevInfo
	}
}

// summarise produces a short single-line title for terminal display.
func summarise(line string) string {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, "\n\r"); i >= 0 {
		line = line[:i]
	}
	const max = 90
	if len(line) <= max {
		return line
	}
	return line[:max] + "…"
}

func applyStreamLabels(s *signal.Signal, stream map[string]string) {
	s.SetLabel(signal.LabelNamespace, stream["namespace"])
	s.SetLabel(signal.LabelPod, stream["pod"])
	s.SetLabel(signal.LabelContainer, stream["container"])
	s.SetLabel(signal.LabelNode, stream["node_name"])
	if app := stream["app"]; app != "" {
		s.SetLabel(signal.LabelWorkload, app)
	}
}

// --- Loki API wire types ----------------------------------------------------

type queryResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		} `json:"result"`
	} `json:"data"`
}
