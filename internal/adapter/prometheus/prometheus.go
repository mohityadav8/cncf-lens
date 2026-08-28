// Package prometheus implements the Adapter interface against the Prometheus
// HTTP API v1. It also works unmodified against Thanos Query, Cortex, Mimir and
// VictoriaMetrics, all of which implement the same API surface.
package prometheus

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cncf-lens/lens/internal/adapter"
	"github.com/cncf-lens/lens/internal/signal"
)

// Adapter queries a Prometheus-compatible metrics backend.
type Adapter struct {
	http *adapter.HTTPClient
	name string

	// defaultQueries run when the caller does not supply an explicit PromQL
	// expression. They cover the four golden signals plus the Kubernetes
	// failure modes that actually page people.
	defaultQueries []namedQuery
}

type namedQuery struct {
	title string
	expr  string
	// anomalyAbove marks a sample as a warning when the value exceeds this.
	// NaN means "never flag on value alone".
	anomalyAbove float64
	unit         string
}

// New builds a Prometheus adapter from backend config.
func New(name, baseURL, token string, insecure bool, timeout time.Duration) *Adapter {
	if name == "" {
		name = "prometheus"
	}
	return &Adapter{
		name: name,
		http: adapter.NewHTTPClient(baseURL, token, insecure, timeout),
		defaultQueries: []namedQuery{
			{
				title:        "HTTP error rate",
				expr:         `sum by (namespace, pod) (rate(http_requests_total{code=~"5.."}[2m]))`,
				anomalyAbove: 0.1,
				unit:         "req/s",
			},
			{
				title:        "Request latency p99",
				expr:         `histogram_quantile(0.99, sum by (namespace, pod, le) (rate(http_request_duration_seconds_bucket[2m])))`,
				anomalyAbove: 1.0,
				unit:         "s",
			},
			{
				title:        "Container CPU throttling",
				expr:         `sum by (namespace, pod) (rate(container_cpu_cfs_throttled_seconds_total[2m]))`,
				anomalyAbove: 0.5,
				unit:         "s/s",
			},
			{
				title:        "Container memory working set",
				expr:         `sum by (namespace, pod) (container_memory_working_set_bytes)`,
				anomalyAbove: math.NaN(),
				unit:         "bytes",
			},
			{
				title:        "Pod restart rate",
				expr:         `sum by (namespace, pod) (rate(kube_pod_container_status_restarts_total[5m]))`,
				anomalyAbove: 0.0,
				unit:         "restarts/s",
			},
		},
	}
}

func (a *Adapter) Name() string { return a.name }

func (a *Adapter) Capabilities() []signal.Type {
	return []signal.Type{signal.TypeMetric}
}

func (a *Adapter) HealthCheck(ctx context.Context) error {
	// -/healthy is the Prometheus liveness path; Thanos and Mimir expose it too.
	if err := a.http.Ping(ctx, "/-/healthy"); err == nil {
		return nil
	}
	// Fall back to a trivial query, which works on backends that do not expose
	// the health path (some managed offerings gate it behind auth).
	var resp queryResponse
	params := url.Values{"query": {"vector(1)"}}
	if err := a.http.GetJSON(ctx, "/api/v1/query", params, &resp); err != nil {
		return fmt.Errorf("prometheus health check failed: %w", err)
	}
	if resp.Status != "success" {
		return fmt.Errorf("prometheus returned status %q", resp.Status)
	}
	return nil
}

// Fetch runs either the caller's PromQL expression or the built-in golden
// signal queries, and converts the samples into Signals.
func (a *Adapter) Fetch(ctx context.Context, q adapter.Query) (signal.Set, error) {
	if !q.WantsType(signal.TypeMetric) {
		return nil, nil
	}

	queries := a.defaultQueries
	if q.Expr != "" {
		queries = []namedQuery{{
			title:        "custom query",
			expr:         q.Expr,
			anomalyAbove: math.NaN(),
		}}
	}

	step := chooseStep(q.Duration())
	var out signal.Set
	var firstErr error

	for _, nq := range queries {
		expr := applySelectors(nq.expr, q)
		sigs, err := a.queryRange(ctx, nq, expr, q.From, q.To, step)
		if err != nil {
			// One bad query must not sink the rest. A cluster without
			// kube-state-metrics installed will legitimately fail the pod
			// restart query while every other query succeeds.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, sigs...)
	}

	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = downsample(out, q.Limit)
	}
	out.SortByTime()
	return out, nil
}

// queryRange executes one range query and converts the matrix result.
func (a *Adapter) queryRange(ctx context.Context, nq namedQuery, expr string, from, to time.Time, step time.Duration) (signal.Set, error) {
	params := url.Values{
		"query": {expr},
		"start": {formatTime(from)},
		"end":   {formatTime(to)},
		"step":  {strconv.FormatFloat(step.Seconds(), 'f', -1, 64)},
	}

	var resp queryResponse
	if err := a.http.GetJSON(ctx, "/api/v1/query_range", params, &resp); err != nil {
		return nil, err
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("promql %q: %s: %s", truncateExpr(expr), resp.ErrorType, resp.Error)
	}

	var out signal.Set
	for _, series := range resp.Data.Result {
		// Reduce each series to its interesting points rather than emitting
		// every sample. A 15-minute window at 15s resolution is 60 samples per
		// series; across ten series that is 600 signals of which perhaps three
		// matter. We keep the extremes and any anomalous points.
		for _, pt := range selectInterestingPoints(series.Values, nq.anomalyAbove) {
			s := signal.Signal{
				Timestamp: pt.ts,
				Type:      signal.TypeMetric,
				Source:    a.name,
				Title:     nq.title,
				Detail:    formatSampleDetail(nq, series.Metric, pt.value),
				Value:     &pt.value,
				Severity:  severityFor(nq, pt.value),
			}
			applyMetricLabels(&s, series.Metric)
			out = append(out, s)
		}
	}
	return out, nil
}

// point is one sample.
type point struct {
	ts    time.Time
	value float64
}

// selectInterestingPoints reduces a dense series to the few samples worth
// showing: the maximum, the minimum, and every point above the anomaly
// threshold. This is what keeps `lens diagnose` output readable.
func selectInterestingPoints(values [][2]any, anomalyAbove float64) []point {
	pts := make([]point, 0, len(values))
	for _, v := range values {
		p, ok := parseSamplePair(v)
		if !ok {
			continue
		}
		pts = append(pts, p)
	}
	if len(pts) == 0 {
		return nil
	}

	seen := make(map[int64]bool)
	var out []point
	add := func(p point) {
		key := p.ts.UnixNano()
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, p)
	}

	maxIdx, minIdx := 0, 0
	for i, p := range pts {
		if p.value > pts[maxIdx].value {
			maxIdx = i
		}
		if p.value < pts[minIdx].value {
			minIdx = i
		}
	}

	if !math.IsNaN(anomalyAbove) {
		for _, p := range pts {
			if p.value > anomalyAbove {
				add(p)
			}
		}
	}
	add(pts[maxIdx])
	if minIdx != maxIdx {
		add(pts[minIdx])
	}

	// Cap per-series output so one pathological series cannot dominate.
	const perSeriesCap = 12
	if len(out) > perSeriesCap {
		out = out[:perSeriesCap]
	}
	return out
}

// parseSamplePair decodes Prometheus's [unixTimestamp, "value"] pair, which is
// a heterogeneous JSON array — hence the `any` handling.
func parseSamplePair(v [2]any) (point, bool) {
	tsFloat, ok := v[0].(float64)
	if !ok {
		return point{}, false
	}
	valStr, ok := v[1].(string)
	if !ok {
		return point{}, false
	}
	val, err := strconv.ParseFloat(valStr, 64)
	if err != nil || math.IsNaN(val) {
		// NaN samples are Prometheus's way of saying "no data here"; they are
		// not zeros and must not be rendered as such.
		return point{}, false
	}
	sec := int64(tsFloat)
	nsec := int64((tsFloat - float64(sec)) * 1e9)
	return point{ts: time.Unix(sec, nsec).UTC(), value: val}, true
}

func severityFor(nq namedQuery, val float64) signal.Severity {
	if math.IsNaN(nq.anomalyAbove) {
		return signal.SevInfo
	}
	switch {
	case val > nq.anomalyAbove*5:
		return signal.SevCritical
	case val > nq.anomalyAbove*2:
		return signal.SevError
	case val > nq.anomalyAbove:
		return signal.SevWarning
	default:
		return signal.SevInfo
	}
}

// applyMetricLabels maps Prometheus label names onto our canonical ones so that
// cross-backend label overlap scoring works.
func applyMetricLabels(s *signal.Signal, metric map[string]string) {
	s.SetLabel(signal.LabelNamespace, firstNonEmpty(metric["namespace"], metric["kubernetes_namespace"]))
	s.SetLabel(signal.LabelPod, firstNonEmpty(metric["pod"], metric["pod_name"], metric["instance"]))
	s.SetLabel(signal.LabelContainer, metric["container"])
	s.SetLabel(signal.LabelService, firstNonEmpty(metric["service"], metric["job"]))
	s.SetLabel(signal.LabelNode, metric["node"])
	s.SetLabel(signal.LabelWorkload, firstNonEmpty(metric["workload"], metric["deployment"], metric["job"]))
}

// applySelectors injects namespace/pod constraints into a PromQL expression.
//
// We do this textually on the first `{` of the expression. A real PromQL AST
// would be more robust, but pulling in a parser would break the zero-dependency
// property, and every built-in query is written to make this safe. Custom
// expressions from --metric are passed through untouched precisely because we
// cannot make that guarantee for arbitrary user input.
func applySelectors(expr string, q adapter.Query) string {
	if q.Expr != "" {
		return expr // user-supplied; never rewrite
	}
	var sel []string
	if q.Namespace != "" {
		sel = append(sel, fmt.Sprintf("namespace=%q", q.Namespace))
	}
	if q.Pod != "" {
		sel = append(sel, fmt.Sprintf("pod=%q", q.Pod))
	}
	if len(sel) == 0 {
		return expr
	}
	inject := strings.Join(sel, ",")

	idx := strings.Index(expr, "{")
	if idx == -1 {
		return expr
	}
	// Insert immediately after the opening brace, adding a comma only when the
	// existing selector is non-empty.
	rest := expr[idx+1:]
	if strings.HasPrefix(strings.TrimSpace(rest), "}") {
		return expr[:idx+1] + inject + rest
	}
	return expr[:idx+1] + inject + "," + rest
}

// chooseStep picks a resolution that keeps any window under ~250 points, which
// is both kind to the backend and enough detail for visual inspection.
//
// The step is snapped up to the next "round" interval an operator would
// recognise, rather than emitting something like 4m17s. Crucially the ladder
// ends by computing a step from the window itself: a fixed maximum would let a
// 30-day query request thousands of points and hammer the backend, which is
// exactly the kind of query that gets an observability tool banned from a
// production cluster.
func chooseStep(window time.Duration) time.Duration {
	const targetPoints = 250

	ideal := window / targetPoints
	ladder := []time.Duration{
		15 * time.Second,
		30 * time.Second,
		time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		time.Hour,
		6 * time.Hour,
		24 * time.Hour,
	}
	for _, step := range ladder {
		if ideal <= step {
			return step
		}
	}

	// Beyond the ladder, round the computed step up to whole days so the
	// point budget still holds for arbitrarily long windows.
	days := (ideal + 24*time.Hour - 1) / (24 * time.Hour)
	return days * 24 * time.Hour
}

// downsample keeps signals evenly spread across the window rather than
// truncating, so a limit never silently hides the end of an incident.
func downsample(in signal.Set, limit int) signal.Set {
	if len(in) <= limit {
		return in
	}
	stride := float64(len(in)) / float64(limit)
	out := make(signal.Set, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, in[int(float64(i)*stride)])
	}
	return out
}

func formatSampleDetail(nq namedQuery, metric map[string]string, val float64) string {
	var b strings.Builder
	b.WriteString(formatValue(val, nq.unit))
	if pod := firstNonEmpty(metric["pod"], metric["instance"]); pod != "" {
		b.WriteString("  pod=")
		b.WriteString(pod)
	}
	if ns := metric["namespace"]; ns != "" {
		b.WriteString("  ns=")
		b.WriteString(ns)
	}
	return b.String()
}

func formatValue(v float64, unit string) string {
	switch unit {
	case "bytes":
		return humanBytes(v)
	case "s":
		return time.Duration(v * float64(time.Second)).Round(time.Millisecond).String()
	default:
		if unit != "" {
			return strconv.FormatFloat(v, 'f', 3, 64) + " " + unit
		}
		return strconv.FormatFloat(v, 'f', 3, 64)
	}
}

func humanBytes(v float64) string {
	const unit = 1024.0
	if v < unit {
		return fmt.Sprintf("%.0f B", v)
	}
	div, exp := unit, 0
	for n := v / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", v/div, "KMGTP"[exp])
}

func formatTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixNano())/1e9, 'f', 3, 64)
}

func truncateExpr(s string) string {
	if len(s) <= 60 {
		return s
	}
	return s[:60] + "…"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- Prometheus API wire types ---------------------------------------------

type queryResponse struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType,omitempty"`
	Error     string `json:"error,omitempty"`
	Data      struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			// Values is the matrix form: [[ts, "val"], ...]
			Values [][2]any `json:"values"`
			// Value is the vector form: [ts, "val"]
			Value [2]any `json:"value"`
		} `json:"result"`
	} `json:"data"`
}
