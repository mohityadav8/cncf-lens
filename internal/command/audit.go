package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cncf-lens/lens/internal/adapter"
	"github.com/cncf-lens/lens/internal/cli"
	"github.com/cncf-lens/lens/internal/correlate"
	"github.com/cncf-lens/lens/internal/render"
	"github.com/cncf-lens/lens/internal/signal"
)

var auditFlags struct {
	minSeverity string
	failOn      string
}

// Audit builds the `lens audit` command.
func Audit() *cli.Command {
	return &cli.Command{
		Name:    "audit",
		Group:   "Assess",
		Summary: "Report security-relevant findings across the stack",
		Usage:   "lens audit [--namespace=NS] [--output=sarif]",
		Long: `Audit collects security signals — Falco alerts, policy violations from OPA
or Kyverno, and the Kubernetes events that indicate a misconfiguration — and
reports them as a single scored list.

With --output=sarif the report is written in the format GitHub Advanced
Security, GitLab and most security dashboards ingest natively, so findings flow
into your existing pipeline without glue code.

Use --fail-on to make this command exit non-zero in CI when findings at or above
a severity are present.`,
		Examples: []string{
			"lens audit --namespace=production",
			"lens audit --output=sarif > lens.sarif",
			"lens audit --fail-on=error   # non-zero exit for CI gating",
		},
		SetupFlags: func(fs *flag.FlagSet) {
			fs.StringVar(&auditFlags.minSeverity, "min-severity", "warning", "lowest severity to report")
			fs.StringVar(&auditFlags.failOn, "fail-on", "", "exit non-zero if findings at or above this severity exist")
		},
		Run: runAudit,
	}
}

func runAudit(ctx context.Context, _ []string) error {
	rt, err := Setup(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	q, err := rt.Query(signal.TypeSecurity, signal.TypeEvent)
	if err != nil {
		return err
	}

	results := rt.Registry.FetchAll(ctx, q, rt.FetchOptions())
	all, _ := adapter.Merge(results)

	minSev := signal.ParseSeverity(auditFlags.minSeverity)
	findings := all.FilterSeverity(minSev)

	// Security signals rank above generic events of equal severity: a Falco
	// alert and a pod restart at "warning" are not equally interesting to
	// someone running an audit.
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		iSec := findings[i].Type == signal.TypeSecurity
		jSec := findings[j].Type == signal.TypeSecurity
		if iSec != jSec {
			return iSec
		}
		return findings[i].Timestamp.After(findings[j].Timestamp)
	})

	switch rt.OutputFormat() {
	case "sarif":
		s := &render.SARIF{Out: os.Stdout}
		if err := s.Write(Version, findings); err != nil {
			return err
		}
	case "json":
		j := &render.JSON{Out: os.Stdout}
		tl := correlate.Assemble(findings, rt.Config.Defaults.CorrelationWindow)
		if err := j.Timeline("audit", tl, FailureMap(results)); err != nil {
			return err
		}
	default:
		printAuditReport(rt, findings)
		rt.ReportFailures(results)
	}

	if auditFlags.failOn != "" {
		threshold := signal.ParseSeverity(auditFlags.failOn)
		if n := len(findings.FilterSeverity(threshold)); n > 0 {
			return fmt.Errorf("%d finding(s) at or above %s severity", n, threshold)
		}
	}
	return nil
}

func printAuditReport(rt *Runtime, findings signal.Set) {
	if len(findings) == 0 {
		fmt.Fprintf(os.Stdout, "\nNo findings at or above %s severity in the last %s.\n",
			auditFlags.minSeverity, G.Since)
		return
	}

	counts := map[signal.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Fprintf(os.Stdout, "\nSecurity audit — %s\n", describeScope())
	fmt.Fprintf(os.Stdout, "%s\n\n", strings.Repeat("─", 60))
	fmt.Fprintf(os.Stdout, "  critical: %-4d  error: %-4d  warning: %-4d\n\n",
		counts[signal.SevCritical], counts[signal.SevError], counts[signal.SevWarning])

	for _, f := range findings {
		fmt.Fprintf(os.Stdout, "  [%s] %s\n", strings.ToUpper(f.Severity.String()[:4]), f.Title)
		fmt.Fprintf(os.Stdout, "         %s · %s\n",
			f.Timestamp.Format("2006-01-02 15:04:05"), f.Source)
		if f.Detail != "" {
			fmt.Fprintf(os.Stdout, "         %s\n", truncateStr(oneLineStr(f.Detail), 90))
		}
		if id := f.Identity(); id != "" {
			fmt.Fprintf(os.Stdout, "         %s\n", id)
		}
		fmt.Fprintln(os.Stdout)
	}
	_ = rt
}
