package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/cli"
	"github.com/mohityadav8/cncf-lens/internal/correlate"
	sig "github.com/mohityadav8/cncf-lens/internal/signal"
)

var watchFlags struct {
	interval string
	minSev   string
}

// Watch builds the `lens watch` command.
func Watch() *cli.Command {
	return &cli.Command{
		Name:    "watch",
		Group:   "Investigate",
		Summary: "Stream correlated signals live from every backend",
		Usage:   "lens watch --namespace=NS [--interval=5s]",
		Long: `Watch polls every configured backend on an interval and prints newly seen
signals as a single merged stream, so you can see a deployment, its metric
impact and the resulting log errors interleaved in real time.

Only signals not seen in a previous poll are printed, so the output is a true
stream rather than a repeating snapshot. Press Ctrl-C to stop.`,
		Examples: []string{
			"lens watch --namespace=payments",
			"lens watch --namespace=payments --min-severity=warning --interval=10s",
		},
		SetupFlags: func(fs *flag.FlagSet) {
			fs.StringVar(&watchFlags.interval, "interval", "5s", "how often to poll backends")
			fs.StringVar(&watchFlags.minSev, "min-severity", "info", "only show signals at or above this severity")
		},
		Run: runWatch,
	}
}

func runWatch(ctx context.Context, _ []string) error {
	interval, err := time.ParseDuration(watchFlags.interval)
	if err != nil {
		return fmt.Errorf("%w: --interval=%q is not a duration", cli.ErrUsage, watchFlags.interval)
	}
	if interval < time.Second {
		// Polling faster than a second adds load to every backend and gains
		// nothing: Prometheus scrapes at 15s and Kubernetes events are not
		// sub-second either.
		return fmt.Errorf("%w: --interval must be at least 1s", cli.ErrUsage)
	}
	minSev := sig.ParseSeverity(watchFlags.minSev)

	rt, err := Setup(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	// Ctrl-C should stop the loop cleanly, not kill the process mid-write.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stdout, "Watching %s every %s across %d backends. Ctrl-C to stop.\n",
		describeScope(), interval, rt.Registry.Len())

	// seen dedupes across polls. Each poll re-queries an overlapping window, so
	// without this the same event would print on every tick.
	seen := make(map[string]bool)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	first := true
	for {
		if !first {
			select {
			case <-ctx.Done():
				fmt.Fprintln(os.Stdout, "\nstopped")
				return nil
			case <-ticker.C:
			}
		}
		first = false

		q, err := rt.Query()
		if err != nil {
			return err
		}
		// Poll a window slightly wider than the interval so nothing falls
		// between ticks due to backend ingestion lag.
		q.From = time.Now().UTC().Add(-interval * 3)
		q.To = time.Now().UTC()

		results := rt.Registry.FetchAll(ctx, q, rt.FetchOptions())
		all, _ := adapter.Merge(results)

		var fresh sig.Set
		for _, s := range all {
			if s.Severity < minSev {
				continue
			}
			key := dedupKey(s)
			if seen[key] {
				continue
			}
			seen[key] = true
			fresh = append(fresh, s)
		}

		if len(fresh) > 0 {
			tl := correlate.Assemble(fresh, rt.Config.Defaults.CorrelationWindow)
			for _, b := range tl.Buckets {
				printWatchBucket(rt, b)
			}
		}

		// Bound memory on a long-running watch. Beyond this many keys we reset;
		// a rare duplicate line is a better failure mode than unbounded growth
		// during an all-night incident.
		if len(seen) > 50000 {
			seen = make(map[string]bool)
		}
	}
}

func printWatchBucket(rt *Runtime, b correlate.Bucket) {
	for _, s := range b.Signals {
		fmt.Fprintf(os.Stdout, "%s  %-10s  %-8s  %s\n",
			s.Timestamp.Format("15:04:05.000"),
			truncateStr(s.Source, 10),
			s.Severity,
			truncateStr(oneLineStr(s.Title), 90),
		)
	}
	_ = rt
}

func dedupKey(s sig.Signal) string {
	return s.Timestamp.Format(time.RFC3339Nano) + "|" + s.Source + "|" + s.Title + "|" + s.Detail
}

func describeScope() string {
	switch {
	case G.Pod != "":
		return "pod " + G.Pod
	case G.Workload != "":
		return "workload " + G.Workload
	case G.Namespace != "":
		return "namespace " + G.Namespace
	default:
		return "the whole cluster"
	}
}
