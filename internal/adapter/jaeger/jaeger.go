// Package jaeger implements the Adapter interface against Jaeger's query API.
// The same wire format is served by Grafana Tempo's Jaeger-compatible endpoint,
// so this adapter covers both.
package jaeger

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cncf-lens/lens/internal/adapter"
	"github.com/cncf-lens/lens/internal/signal"
)

// Adapter queries a Jaeger-compatible trace backend.
type Adapter struct {
	http *adapter.HTTPClient
	name string
}

// New builds a Jaeger adapter.
func New(name, baseURL, token string, insecure bool, timeout time.Duration) *Adapter {
	if name == "" {
		name = "jaeger"
	}
	return &Adapter{name: name, http: adapter.NewHTTPClient(baseURL, token, insecure, timeout)}
}

func (a *Adapter) Name() string { return a.name }

func (a *Adapter) Capabilities() []signal.Type { return []signal.Type{signal.TypeTrace} }

func (a *Adapter) HealthCheck(ctx context.Context) error {
	var resp servicesResponse
	if err := a.http.GetJSON(ctx, "/api/services", nil, &resp); err != nil {
		return fmt.Errorf("jaeger health check failed: %w", err)
	}
	return nil
}

// Fetch retrieves traces. When a TraceID is supplied it fetches that one trace
// directly; otherwise it searches by service within the window.
func (a *Adapter) Fetch(ctx context.Context, q adapter.Query) (signal.Set, error) {
	if !q.WantsType(signal.TypeTrace) {
		return nil, nil
	}

	if q.TraceID != "" {
		return a.fetchByID(ctx, q.TraceID)
	}

	service := q.Workload
	if service == "" {
		service = q.Pod
	}
	if service == "" {
		// Without a service name Jaeger search returns nothing useful, and
		// enumerating every service would be a denial of service against the
		// query backend during an incident.
		return nil, fmt.Errorf("jaeger needs --service or --workload to search traces")
	}

	limit := q.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	params := url.Values{
		"service": {service},
		"start":   {strconv.FormatInt(q.From.UnixMicro(), 10)},
		"end":     {strconv.FormatInt(q.To.UnixMicro(), 10)},
		"limit":   {strconv.Itoa(limit)},
	}
	if q.Namespace != "" {
		// Jaeger encodes resource attributes as tags; the OTel semantic
		// convention for namespace is k8s.namespace.name.
		params.Set("tags", fmt.Sprintf(`{"k8s.namespace.name":%q}`, q.Namespace))
	}

	var resp tracesResponse
	if err := a.http.GetJSON(ctx, "/api/traces", params, &resp); err != nil {
		return nil, err
	}
	return a.tracesToSignals(resp.Data), nil
}

func (a *Adapter) fetchByID(ctx context.Context, traceID string) (signal.Set, error) {
	var resp tracesResponse
	path := "/api/traces/" + url.PathEscape(traceID)
	if err := a.http.GetJSON(ctx, path, nil, &resp); err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("trace %s not found — it may have aged out of retention", traceID)
	}
	return a.tracesToSignals(resp.Data), nil
}

// tracesToSignals flattens traces into per-span signals.
func (a *Adapter) tracesToSignals(traces []trace) signal.Set {
	var out signal.Set

	for _, tr := range traces {
		// Build the processID -> service name map once per trace.
		services := make(map[string]string, len(tr.Processes))
		for pid, proc := range tr.Processes {
			services[pid] = proc.ServiceName
		}

		for _, sp := range tr.Spans {
			start := time.UnixMicro(sp.StartTime).UTC()
			dur := time.Duration(sp.Duration) * time.Microsecond

			s := signal.Signal{
				Timestamp: start,
				Type:      signal.TypeTrace,
				Source:    a.name,
				Title:     fmt.Sprintf("%s %s", services[sp.ProcessID], sp.OperationName),
				Detail:    fmt.Sprintf("span took %s", dur.Round(time.Microsecond)),
				TraceID:   strings.ToLower(sp.TraceID),
				SpanID:    sp.SpanID,
				Duration:  dur,
				Severity:  spanSeverity(sp, dur),
			}

			s.SetLabel(signal.LabelService, services[sp.ProcessID])
			applyTagLabels(&s, sp.Tags)
			applyProcessLabels(&s, tr.Processes[sp.ProcessID].Tags)

			out = append(out, s)
		}
	}

	out.SortByTime()
	return out
}

// spanSeverity flags error spans and unusually slow ones. The 1s threshold is a
// blunt heuristic; it exists so that `lens trace` surfaces the slow span in a
// wall of fast ones without the user having to eyeball every duration.
func spanSeverity(sp span, dur time.Duration) signal.Severity {
	for _, t := range sp.Tags {
		if t.Key == "error" && fmt.Sprint(t.Value) == "true" {
			return signal.SevError
		}
		if t.Key == "otel.status_code" && fmt.Sprint(t.Value) == "ERROR" {
			return signal.SevError
		}
		if t.Key == "http.status_code" {
			if code, err := strconv.Atoi(fmt.Sprint(t.Value)); err == nil && code >= 500 {
				return signal.SevError
			}
		}
	}
	if dur > time.Second {
		return signal.SevWarning
	}
	return signal.SevInfo
}

// applyTagLabels maps OpenTelemetry semantic-convention resource attributes
// onto our canonical label names.
func applyTagLabels(s *signal.Signal, tags []tag) {
	for _, t := range tags {
		v := fmt.Sprint(t.Value)
		switch t.Key {
		case "k8s.namespace.name", "namespace":
			s.SetLabel(signal.LabelNamespace, v)
		case "k8s.pod.name", "pod":
			s.SetLabel(signal.LabelPod, v)
		case "k8s.container.name", "container":
			s.SetLabel(signal.LabelContainer, v)
		case "k8s.node.name":
			s.SetLabel(signal.LabelNode, v)
		case "k8s.deployment.name", "k8s.statefulset.name":
			s.SetLabel(signal.LabelWorkload, v)
		case "k8s.cluster.name":
			s.SetLabel(signal.LabelCluster, v)
		}
	}
}

func applyProcessLabels(s *signal.Signal, tags []tag) { applyTagLabels(s, tags) }

// --- Jaeger API wire types --------------------------------------------------

type servicesResponse struct {
	Data []string `json:"data"`
}

type tracesResponse struct {
	Data []trace `json:"data"`
}

type trace struct {
	TraceID   string             `json:"traceID"`
	Spans     []span             `json:"spans"`
	Processes map[string]process `json:"processes"`
}

type span struct {
	TraceID       string `json:"traceID"`
	SpanID        string `json:"spanID"`
	OperationName string `json:"operationName"`
	StartTime     int64  `json:"startTime"`
	Duration      int64  `json:"duration"`
	ProcessID     string `json:"processID"`
	Tags          []tag  `json:"tags"`
}

type process struct {
	ServiceName string `json:"serviceName"`
	Tags        []tag  `json:"tags"`
}

type tag struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}
