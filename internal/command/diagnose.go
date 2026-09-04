package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/cli"
	"github.com/mohityadav8/cncf-lens/internal/correlate"
	"github.com/mohityadav8/cncf-lens/internal/render"
	"github.com/mohityadav8/cncf-lens/internal/signal"
)

var diagnoseFlags struct {
	metric   string
	lookback string
	maxCause int
	minScore float64
	learn    bool
}

// Diagnose builds the `lens diagnose` command.
func Diagnose() *cli.Command {
	return &cli.Command{
		Name:    "diagnose",
		Group:   "Investigate",
		Summary: "Find the likely root cause of an anomaly",
		Usage:   "lens diagnose [--metric=PROMQL] [--namespace=NS] [--since=DUR]",
		Long: `Diagnose gathers signals from every configured backend, picks the most
severe anomaly in the window (or evaluates the PromQL you supply), then searches
backwards in time for events that could have caused it.

Candidates are scored by explainable rules — was it a deployment, does it share
Kubernetes labels with the anomaly, how tightly did it precede it — and each
hypothesis is printed with the evidence that produced its score. The ranking is
a starting point for your own judgement, not a verdict.`,
		Examples: []string{
			"lens diagnose --namespace=payments --since=30m",
			"lens diagnose --metric='rate(http_requests_total{code=\"500\"}[5m])' --since=1h",
			"lens diagnose --namespace=payments --output=markdown > postmortem.md",
		},
		SetupFlags: func(fs *flag.FlagSet) {
			fs.StringVar(&diagnoseFlags.metric, "metric", "", "PromQL expression identifying the anomaly")
			fs.StringVar(&diagnoseFlags.lookback, "lookback", "15m", "how far before the anomaly to search for causes")
			fs.IntVar(&diagnoseFlags.maxCause, "max-causes", 5, "maximum hypotheses to report")
			fs.Float64Var(&diagnoseFlags.minScore, "min-score", 0.25, "drop hypotheses scoring below this (0-1)")
			fs.BoolVar(&diagnoseFlags.learn, "learn", true, "record co-occurrences to improve future rankings")
		},
		Run: runDiagnose,
	}
}

func runDiagnose(ctx context.Context, _ []string) error {
	rt, err := Setup(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	q, err := rt.Query()
	if err != nil {
		return err
	}
	q.Expr = diagnoseFlags.metric

	results := rt.Registry.FetchAll(ctx, q, rt.FetchOptions())
	all, _ := adapter.Merge(results)

	if len(all) == 0 {
		rt.ReportFailures(results)
		return fmt.Errorf("no signals returned in the last %s — widen with --since or check `lens doctor`", G.Since)
	}

	anomaly, found := correlate.FindAnomaly(all)
	if !found {
		rt.ReportFailures(results)
		return fmt.Errorf("nothing at warning severity or above in the last %s — the window looks healthy", G.Since)
	}

	lookback, err := time.ParseDuration(diagnoseFlags.lookback)
	if err != nil {
		return fmt.Errorf("%w: --lookback=%q is not a duration", cli.ErrUsage, diagnoseFlags.lookback)
	}

	opts := correlate.DiagnoseOptions{
		Lookback:   lookback,
		MaxResults: diagnoseFlags.maxCause,
		MinScore:   diagnoseFlags.minScore,
		History:    rt.History,
	}
	hyps := correlate.Diagnose(anomaly, all, opts)

	// Feed the outcome back into the history store so the historical
	// co-occurrence rule gets sharper on this specific cluster over time.
	if diagnoseFlags.learn {
		recordOutcome(rt, anomaly, all, hyps)
	}

	switch rt.OutputFormat() {
	case "json":
		j := &render.JSON{Out: os.Stdout}
		return j.Hypotheses("diagnose", anomaly, hyps, FailureMap(results))
	case "markdown":
		m := &render.Markdown{Out: os.Stdout}
		tl := correlate.Assemble(all, rt.Config.Defaults.CorrelationWindow)
		return m.Report("Incident analysis", &anomaly, hyps, tl)
	case "sarif":
		s := &render.SARIF{Out: os.Stdout}
		return s.Write(Version, all.FilterSeverity(signal.SevWarning))
	default:
		rt.Terminal.Hypotheses(anomaly, hyps)
		rt.ReportFailures(results)
		return nil
	}
}

// recordOutcome updates the co-occurrence counters. Causes that scored are
// recorded as co-occurring; everything else in the lookback window increments
// only the denominator, which is what keeps common-but-irrelevant events from
// accumulating a misleadingly high ratio.
func recordOutcome(rt *Runtime, anomaly signal.Signal, all signal.Set, hyps []correlate.Hypothesis) {
	scored := make(map[string]bool, len(hyps))
	for _, h := range hyps {
		key := correlate.CauseKey(h.Cause)
		scored[key] = true
		rt.History.Record(key, correlate.AnomalyKey(anomaly))
	}
	for _, s := range all {
		if !s.Timestamp.Before(anomaly.Timestamp) {
			continue
		}
		if key := correlate.CauseKey(s); !scored[key] {
			rt.History.RecordCauseSeen(key)
		}
	}
}
