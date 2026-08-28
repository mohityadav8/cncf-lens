package command

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/cncf-lens/lens/internal/adapter"
	"github.com/cncf-lens/lens/internal/cli"
	"github.com/cncf-lens/lens/internal/correlate"
	"github.com/cncf-lens/lens/internal/render"
	"github.com/cncf-lens/lens/internal/signal"
)

var traceFlags struct {
	traceID string
	follow  bool
}

// Trace builds the `lens trace` command.
func Trace() *cli.Command {
	return &cli.Command{
		Name:    "trace",
		Group:   "Investigate",
		Summary: "Follow one request across spans, logs, metrics and events",
		Usage:   "lens trace --id=TRACEID | --pod=POD | --workload=SERVICE",
		Long: `Trace assembles everything that happened to a single request.

Given a trace ID it pulls the spans from your tracing backend, then finds every
log line and metric sample that carried the same trace ID, and renders them as
one waterfall. Given a pod or workload instead, it finds recent traces for that
service and shows the slowest or most errored one.

The correlation is exact when your services propagate trace context into their
logs. Where they do not, lens falls back to matching on time proximity plus
shared Kubernetes labels.`,
		Examples: []string{
			"lens trace --id=4bf92f3577b34da6a3ce929d0e0e4736",
			"lens trace --workload=checkout --namespace=shop",
			"lens trace --pod=payments-7d4b9c5f8-x2k9p --since=10m",
		},
		SetupFlags: func(fs *flag.FlagSet) {
			fs.StringVar(&traceFlags.traceID, "id", "", "trace ID to follow")
			fs.BoolVar(&traceFlags.follow, "correlate", true, "attach logs and metrics that share the trace ID")
		},
		Run: runTrace,
	}
}

func runTrace(ctx context.Context, _ []string) error {
	if traceFlags.traceID == "" && G.Pod == "" && G.Workload == "" {
		return fmt.Errorf("%w: need one of --id, --pod or --workload", cli.ErrUsage)
	}

	rt, err := Setup(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	q, err := rt.Query()
	if err != nil {
		return err
	}
	q.TraceID = traceFlags.traceID

	results := rt.Registry.FetchAll(ctx, q, rt.FetchOptions())
	all, _ := adapter.Merge(results)

	if len(all) == 0 {
		rt.ReportFailures(results)
		return fmt.Errorf("no signals found — check the trace ID, or widen --since")
	}

	// Pick the trace to display: the requested one, or the most interesting
	// trace present. "Most interesting" means most errors, then most spans,
	// because a trace with a failure is what the user is hunting for.
	groups := correlate.TraceGroups(all)
	targetID := traceFlags.traceID
	if targetID == "" {
		targetID = pickTrace(groups)
	}

	if targetID == "" {
		// No trace context anywhere. Fall back to a plain correlated timeline
		// rather than failing: the user still gets the logs and events.
		tl := correlate.Assemble(all, rt.Config.Defaults.CorrelationWindow)
		if rt.OutputFormat() == "json" {
			j := &render.JSON{Out: os.Stdout}
			return j.Timeline("trace", tl, FailureMap(results))
		}
		fmt.Fprintln(os.Stdout,
			"\nNo trace IDs found in this window. Showing a correlated timeline instead.")
		fmt.Fprintln(os.Stdout,
			"To get true request tracing, propagate trace context into your logs (W3C traceparent).")
		rt.Terminal.Timeline(tl, "Correlated timeline")
		rt.ReportFailures(results)
		return nil
	}

	traceSignals := groups[targetID]

	// Attach non-trace signals that share the ID even if they landed in the
	// empty-ID group because a backend did not populate the field.
	if traceFlags.follow {
		for _, s := range groups[""] {
			if s.TraceID == targetID {
				traceSignals = append(traceSignals, s)
			}
		}
		traceSignals.SortByTime()
	}

	switch rt.OutputFormat() {
	case "json":
		j := &render.JSON{Out: os.Stdout}
		tl := correlate.Assemble(traceSignals, rt.Config.Defaults.CorrelationWindow)
		return j.Timeline("trace", tl, FailureMap(results))
	case "markdown":
		m := &render.Markdown{Out: os.Stdout}
		tl := correlate.Assemble(traceSignals, rt.Config.Defaults.CorrelationWindow)
		return m.Report("Trace "+targetID, nil, nil, tl)
	default:
		rt.Terminal.TraceView(targetID, traceSignals)
		rt.ReportFailures(results)
		return nil
	}
}

// pickTrace selects the trace most worth showing.
func pickTrace(groups map[string]signal.Set) string {
	bestID, bestScore := "", -1
	for id, sigs := range groups {
		if id == "" {
			continue
		}
		score := 0
		for _, s := range sigs {
			if s.Severity >= signal.SevError {
				score += 10
			}
			score++
		}
		if score > bestScore {
			bestID, bestScore = id, score
		}
	}
	return bestID
}
