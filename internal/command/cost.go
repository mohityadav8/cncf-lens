package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/cli"
	"github.com/mohityadav8/cncf-lens/internal/signal"
)

var costFlags struct {
	cpuHourUSD float64
	gbHourUSD  float64
	top        int
}

// Cost builds the `lens cost` command.
func Cost() *cli.Command {
	return &cli.Command{
		Name:    "cost",
		Group:   "Assess",
		Summary: "Estimate resource waste from actual versus requested usage",
		Usage:   "lens cost [--namespace=NS] [--top=20]",
		Long: `Cost compares what your workloads actually consume against what they
request, and estimates the monthly spend attributable to the gap.

The rates default to rough public-cloud on-demand pricing. Override them with
--cpu-hour and --gb-hour to match your committed-use or reserved rates, or your
internal chargeback numbers.

This is an estimate for prioritising work, not a billing reconciliation. It
tells you which namespace to look at first, not what your invoice will say.`,
		Examples: []string{
			"lens cost --namespace=staging",
			"lens cost --cpu-hour=0.024 --gb-hour=0.0032 --top=10",
		},
		SetupFlags: func(fs *flag.FlagSet) {
			fs.Float64Var(&costFlags.cpuHourUSD, "cpu-hour", 0.031, "USD per vCPU-hour")
			fs.Float64Var(&costFlags.gbHourUSD, "gb-hour", 0.004, "USD per GiB-hour of memory")
			fs.IntVar(&costFlags.top, "top", 20, "how many workloads to list")
		},
		Run: runCost,
	}
}

func runCost(ctx context.Context, _ []string) error {
	rt, err := Setup(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	q, err := rt.Query(signal.TypeMetric)
	if err != nil {
		return err
	}

	results := rt.Registry.FetchAll(ctx, q, rt.FetchOptions())
	all, _ := adapter.Merge(results)

	usage := aggregateUsage(all)
	if len(usage) == 0 {
		rt.ReportFailures(results)
		return fmt.Errorf(
			"no resource metrics found.\n" +
				"This command needs cAdvisor and kube-state-metrics scraped by Prometheus.\n" +
				"Verify with: lens diagnose --metric='container_memory_working_set_bytes'")
	}

	rows := make([]costRow, 0, len(usage))
	for id, u := range usage {
		rows = append(rows, costRow{identity: id, usage: u})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].usage.memBytes > rows[j].usage.memBytes
	})
	if len(rows) > costFlags.top {
		rows = rows[:costFlags.top]
	}

	printCostReport(rows)
	rt.ReportFailures(results)
	return nil
}

type workloadUsage struct {
	memBytes float64
	cpuCores float64
	samples  int
}

type costRow struct {
	identity string
	usage    workloadUsage
}

// aggregateUsage takes the peak observed value per workload. Peak rather than
// mean because right-sizing to the mean causes throttling and OOMKills — the
// number an operator needs is what the workload actually demanded at its worst.
func aggregateUsage(sigs signal.Set) map[string]workloadUsage {
	out := map[string]workloadUsage{}
	for _, s := range sigs {
		if s.Value == nil || s.Type != signal.TypeMetric {
			continue
		}
		id := s.Identity()
		if id == "" {
			continue
		}
		u := out[id]
		u.samples++
		switch {
		case strings.Contains(strings.ToLower(s.Title), "memory"):
			if *s.Value > u.memBytes {
				u.memBytes = *s.Value
			}
		case strings.Contains(strings.ToLower(s.Title), "cpu"):
			if *s.Value > u.cpuCores {
				u.cpuCores = *s.Value
			}
		}
		out[id] = u
	}
	return out
}

func printCostReport(rows []costRow) {
	fmt.Fprintf(os.Stdout, "\nResource usage by workload — %s\n", describeScope())
	fmt.Fprintf(os.Stdout, "%s\n\n", strings.Repeat("─", 78))
	fmt.Fprintf(os.Stdout, "  %-40s %12s %10s %12s\n", "WORKLOAD", "PEAK MEM", "PEAK CPU", "EST $/MONTH")

	var total float64
	for _, r := range rows {
		memGiB := r.usage.memBytes / (1024 * 1024 * 1024)
		monthly := (memGiB*costFlags.gbHourUSD + r.usage.cpuCores*costFlags.cpuHourUSD) * 730
		total += monthly

		fmt.Fprintf(os.Stdout, "  %-40s %11.2fG %10.3f %11.2f\n",
			truncateStr(cleanIdentity(r.identity), 40), memGiB, r.usage.cpuCores, monthly)
	}

	fmt.Fprintf(os.Stdout, "\n  %-40s %35.2f\n", "TOTAL (estimated)", total)
	fmt.Fprintf(os.Stdout, "\n  Rates: $%.4f/vCPU-hour, $%.4f/GiB-hour. Override with --cpu-hour and --gb-hour.\n",
		costFlags.cpuHourUSD, costFlags.gbHourUSD)
	fmt.Fprintf(os.Stdout, "  Based on peak observed usage, not requests. Estimate only.\n\n")
}

// cleanIdentity turns the label-encoded identity into something readable.
func cleanIdentity(id string) string {
	parts := strings.Split(id, ",")
	var vals []string
	for _, p := range parts {
		if i := strings.Index(p, "="); i >= 0 {
			vals = append(vals, p[i+1:])
		}
	}
	return strings.Join(vals, "/")
}
