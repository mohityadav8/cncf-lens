// Package render turns correlated signals into output: an ANSI terminal
// timeline for humans, and JSON / SARIF / Markdown for machines and reports.
package render

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cncf-lens/lens/internal/correlate"
	"github.com/cncf-lens/lens/internal/signal"
)

// ANSI escape codes. Kept as constants rather than a colour library because
// this is the entire surface area we need.
const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	red       = "\033[31m"
	green     = "\033[32m"
	yellow    = "\033[33m"
	blue      = "\033[34m"
	magenta   = "\033[35m"
	cyan      = "\033[36m"
	brightRed = "\033[91m"
)

// Terminal renders signals as a human-readable timeline.
type Terminal struct {
	Out io.Writer
	// Color is disabled automatically when stdout is not a TTY, and can be
	// forced off with --no-color or the NO_COLOR environment variable.
	Color bool
	// Verbose includes info-level signals that are normally filtered out.
	Verbose bool
	// Now is injectable so tests produce stable relative timestamps.
	Now func() time.Time
}

// NewTerminal builds a renderer, auto-detecting colour support.
func NewTerminal(out io.Writer, forceColor bool) *Terminal {
	return &Terminal{
		Out:   out,
		Color: forceColor && supportsColor(),
		Now:   time.Now,
	}
}

// supportsColor applies the conventions users expect: NO_COLOR wins over
// everything, a dumb TERM disables colour, and piping to a file disables it.
func supportsColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (t *Terminal) c(code, s string) string {
	if !t.Color {
		return s
	}
	return code + s + reset
}

// severityColor maps a severity to its ANSI colour and glyph. The glyphs are
// ASCII rather than emoji so output stays aligned in every terminal font and
// remains greppable.
func (t *Terminal) severityMark(s signal.Severity) string {
	switch s {
	case signal.SevCritical:
		return t.c(brightRed+bold, "[!!]")
	case signal.SevError:
		return t.c(red, "[ E]")
	case signal.SevWarning:
		return t.c(yellow, "[ W]")
	case signal.SevDebug:
		return t.c(dim, "[ D]")
	default:
		return t.c(dim, "[ ·]")
	}
}

func (t *Terminal) sourceTag(src string) string {
	// Stable per-source colouring so the eye learns "cyan means Prometheus"
	// within a single session.
	colors := []string{cyan, magenta, blue, green, yellow}
	var sum int
	for _, r := range src {
		sum += int(r)
	}
	return t.c(colors[sum%len(colors)], fmt.Sprintf("%-11s", truncate(src, 11)))
}

// Timeline renders an assembled timeline.
func (t *Terminal) Timeline(tl correlate.Timeline, title string) {
	buckets := tl.Buckets
	if !t.Verbose {
		buckets = tl.Interesting()
	}

	if len(buckets) == 0 {
		t.emptyState(tl)
		return
	}

	t.header(title)
	fmt.Fprintf(t.Out, "%s  %s → %s  (%s window, %s tolerance)\n\n",
		t.c(dim, "window:"),
		tl.From.Format("15:04:05"),
		tl.To.Format("15:04:05 MST"),
		tl.To.Sub(tl.From).Round(time.Second),
		tl.Tolerance,
	)

	for i, b := range buckets {
		t.bucket(b, i == len(buckets)-1)
	}

	total := 0
	for _, b := range tl.Buckets {
		total += len(b.Signals)
	}
	shown := 0
	for _, b := range buckets {
		shown += len(b.Signals)
	}
	fmt.Fprintf(t.Out, "\n%s\n", t.c(dim,
		fmt.Sprintf("%d of %d signals shown across %d moments. Use --verbose for everything.",
			shown, total, len(tl.Buckets))))
}

// bucket renders one correlation bucket as a timeline node.
func (t *Terminal) bucket(b correlate.Bucket, last bool) {
	// Cross-source buckets get a filled marker because they are the ones worth
	// looking at: independent backends agreeing is real signal.
	marker := "○"
	if b.CrossSource() {
		marker = t.c(bold, "●")
	}

	stamp := b.Start.Format("15:04:05.000")
	srcs := strings.Join(b.Sources(), " + ")

	fmt.Fprintf(t.Out, "%s %s  %s\n",
		marker,
		t.c(bold, stamp),
		t.c(dim, srcs),
	)

	pipe := t.c(dim, "│")
	if last {
		pipe = " "
	}

	for _, s := range b.Signals {
		fmt.Fprintf(t.Out, "%s  %s %s %s\n",
			pipe,
			t.severityMark(s.Severity),
			t.sourceTag(s.Source),
			t.title(s),
		)
		if s.Detail != "" && s.Detail != s.Title {
			fmt.Fprintf(t.Out, "%s  %s     %s\n", pipe, "    ", t.c(dim, truncate(oneLine(s.Detail), 100)))
		}
		if s.TraceID != "" {
			fmt.Fprintf(t.Out, "%s  %s     %s\n", pipe, "    ",
				t.c(blue, "trace "+shortTrace(s.TraceID)))
		}
	}
	if !last {
		fmt.Fprintf(t.Out, "%s\n", pipe)
	}
}

func (t *Terminal) title(s signal.Signal) string {
	title := s.Title
	if s.Value != nil {
		title = fmt.Sprintf("%s = %s", title, formatFloat(*s.Value))
	}
	if s.Duration > 0 {
		title = fmt.Sprintf("%s (%s)", title, s.Duration.Round(time.Millisecond))
	}
	if id := s.Identity(); id != "" {
		title += t.c(dim, "  "+compactIdentity(s))
	}
	return title
}

// Hypotheses renders ranked root cause candidates.
func (t *Terminal) Hypotheses(anomaly signal.Signal, hyps []correlate.Hypothesis) {
	t.header("Root cause analysis")

	fmt.Fprintf(t.Out, "%s %s %s\n", t.c(dim, "anomaly:"), t.severityMark(anomaly.Severity), t.c(bold, anomaly.Title))
	fmt.Fprintf(t.Out, "%s %s from %s\n",
		t.c(dim, "        "),
		anomaly.Timestamp.Format("15:04:05.000 MST"),
		anomaly.Source)
	if anomaly.Detail != "" {
		fmt.Fprintf(t.Out, "%s %s\n", t.c(dim, "        "), t.c(dim, truncate(oneLine(anomaly.Detail), 100)))
	}
	fmt.Fprintln(t.Out)

	if len(hyps) == 0 {
		fmt.Fprintf(t.Out, "%s\n\n", t.c(yellow, "No candidate causes scored above the threshold."))
		fmt.Fprintf(t.Out, "%s\n", t.c(dim, "Try widening the search: --lookback=1h, or lower the bar with --min-score=0.1"))
		return
	}

	for i, h := range hyps {
		t.hypothesis(i+1, h)
	}

	fmt.Fprintf(t.Out, "%s\n", t.c(dim,
		"Scores are heuristic. Each line under a hypothesis is the evidence that produced it — check the reasoning, not just the rank."))
}

func (t *Terminal) hypothesis(rank int, h correlate.Hypothesis) {
	conf := h.Confidence()
	color := dim
	switch conf {
	case "likely":
		color = red
	case "possible":
		color = yellow
	}

	fmt.Fprintf(t.Out, "%s %s  %s\n",
		t.c(bold, fmt.Sprintf("%d.", rank)),
		t.c(color+bold, fmt.Sprintf("%-8s", conf)),
		t.c(bold, h.Cause.Title),
	)
	fmt.Fprintf(t.Out, "   %s  %s before the anomaly · score %.2f · via %s\n",
		t.c(dim, h.Cause.Timestamp.Format("15:04:05")),
		h.Lead.Round(time.Second),
		h.Score,
		h.Cause.Source,
	)
	if h.Cause.Detail != "" {
		fmt.Fprintf(t.Out, "   %s\n", t.c(dim, truncate(oneLine(h.Cause.Detail), 100)))
	}
	for _, ev := range h.Evidence {
		fmt.Fprintf(t.Out, "   %s %s\n", t.c(green, "+"), t.c(dim, ev))
	}
	fmt.Fprintln(t.Out)
}

// TraceView renders the spans of one trace as a waterfall, with correlated logs
// and metrics attached to the spans they overlap.
func (t *Terminal) TraceView(traceID string, sigs signal.Set) {
	t.header("Trace " + shortTrace(traceID))

	spans := sigs.FilterType(signal.TypeTrace)
	if len(spans) == 0 {
		fmt.Fprintf(t.Out, "%s\n", t.c(yellow, "No spans found for this trace."))
		return
	}

	from, to, _ := spans.Span()
	// Extend the window by the longest span so the waterfall covers the full
	// request, not just span start times.
	for _, s := range spans {
		if end := s.Timestamp.Add(s.Duration); end.After(to) {
			to = end
		}
	}
	total := to.Sub(from)
	if total <= 0 {
		total = time.Millisecond
	}

	const barWidth = 40
	for _, s := range spans {
		offset := float64(s.Timestamp.Sub(from)) / float64(total)
		width := float64(s.Duration) / float64(total)

		lead := int(offset * barWidth)
		length := int(width * barWidth)
		if length < 1 {
			length = 1
		}
		if lead+length > barWidth {
			length = barWidth - lead
		}

		bar := strings.Repeat(" ", lead) + strings.Repeat("█", length)
		bar += strings.Repeat(" ", barWidth-lead-length)

		barColor := green
		if s.Severity >= signal.SevError {
			barColor = red
		} else if s.Severity >= signal.SevWarning {
			barColor = yellow
		}

		fmt.Fprintf(t.Out, "%s %s %s %s\n",
			t.severityMark(s.Severity),
			t.c(barColor, bar),
			t.c(dim, fmt.Sprintf("%8s", s.Duration.Round(time.Microsecond))),
			truncate(s.Title, 45),
		)
	}

	// Anything in this trace that is not a span: logs and metrics that carried
	// the same trace ID. This is the payoff of the whole design.
	other := sigs.FilterType(signal.TypeLog, signal.TypeMetric, signal.TypeEvent)
	if len(other) > 0 {
		fmt.Fprintf(t.Out, "\n%s\n", t.c(bold, "Correlated signals in this trace"))
		for _, s := range other {
			fmt.Fprintf(t.Out, "  %s %s %s\n",
				t.severityMark(s.Severity),
				t.sourceTag(s.Source),
				truncate(oneLine(s.Detail), 90),
			)
		}
	}
	fmt.Fprintln(t.Out)
}

// Failures reports adapters that errored, so a partial answer is never mistaken
// for a complete one.
func (t *Terminal) Failures(names []string, errs []error) {
	if len(errs) == 0 {
		return
	}
	fmt.Fprintf(t.Out, "\n%s\n", t.c(yellow+bold, "Some backends did not answer:"))
	for i, err := range errs {
		name := "unknown"
		if i < len(names) {
			name = names[i]
		}
		fmt.Fprintf(t.Out, "  %s %s: %s\n", t.c(yellow, "!"), name, err)
	}
	fmt.Fprintf(t.Out, "%s\n", t.c(dim, "  Results above are incomplete."))
}

func (t *Terminal) header(title string) {
	fmt.Fprintf(t.Out, "\n%s\n", t.c(bold, title))
	fmt.Fprintf(t.Out, "%s\n", t.c(dim, strings.Repeat("─", len(title))))
}

func (t *Terminal) emptyState(tl correlate.Timeline) {
	fmt.Fprintf(t.Out, "\n%s\n\n", t.c(yellow, "No signals matched."))
	fmt.Fprintln(t.Out, "Things to try:")
	fmt.Fprintln(t.Out, "  · widen the window with --since=1h")
	fmt.Fprintln(t.Out, "  · check the namespace spelling with --namespace")
	fmt.Fprintln(t.Out, "  · confirm backends are reachable with `lens doctor`")
	fmt.Fprintln(t.Out, "  · add --verbose to include info-level signals")
	_ = tl
}

// --- formatting helpers -----------------------------------------------------

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 1 {
		return string(runes[:n])
	}
	return string(runes[:n-1]) + "…"
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.Join(strings.Fields(s), " ")
}

func shortTrace(id string) string {
	if len(id) <= 16 {
		return id
	}
	return id[:8] + "…" + id[len(id)-4:]
}

func formatFloat(v float64) string {
	switch {
	case v == float64(int64(v)) && v < 1e9:
		return fmt.Sprintf("%d", int64(v))
	case v < 0.001:
		return fmt.Sprintf("%.2e", v)
	default:
		return fmt.Sprintf("%.3f", v)
	}
}

// compactIdentity renders "ns/pod" for inline display, omitting empty parts.
func compactIdentity(s signal.Signal) string {
	if s.Labels == nil {
		return ""
	}
	ns := s.Labels[signal.LabelNamespace]
	pod := s.Labels[signal.LabelPod]
	switch {
	case ns != "" && pod != "":
		return ns + "/" + pod
	case pod != "":
		return pod
	case ns != "":
		return ns
	default:
		return ""
	}
}
