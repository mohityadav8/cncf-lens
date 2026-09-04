package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mohityadav8/cncf-lens/internal/correlate"
	"github.com/mohityadav8/cncf-lens/internal/signal"
)

// JSON emits machine-readable output for piping into other tools.
//
// The schema is versioned so downstream consumers can depend on it. Adding
// fields is a minor change; removing or retyping one bumps schema_version.
type JSON struct {
	Out io.Writer
}

const schemaVersion = "1"

type jsonEnvelope struct {
	SchemaVersion string        `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Command       string        `json:"command"`
	Timeline      *jsonTimeline `json:"timeline,omitempty"`
	Hypotheses    []jsonHypo    `json:"hypotheses,omitempty"`
	Anomaly       *jsonSignal   `json:"anomaly,omitempty"`
	Failures      []jsonFailure `json:"backend_failures,omitempty"`
}

type jsonTimeline struct {
	From    time.Time    `json:"from"`
	To      time.Time    `json:"to"`
	Buckets []jsonBucket `json:"buckets"`
}

type jsonBucket struct {
	Start       time.Time    `json:"start"`
	End         time.Time    `json:"end"`
	Sources     []string     `json:"sources"`
	CrossSource bool         `json:"cross_source"`
	Signals     []jsonSignal `json:"signals"`
}

type jsonSignal struct {
	Timestamp  time.Time         `json:"timestamp"`
	Type       string            `json:"type"`
	Severity   string            `json:"severity"`
	Source     string            `json:"source"`
	Title      string            `json:"title"`
	Detail     string            `json:"detail,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Value      *float64          `json:"value,omitempty"`
	TraceID    string            `json:"trace_id,omitempty"`
	SpanID     string            `json:"span_id,omitempty"`
	DurationMS int64             `json:"duration_ms,omitempty"`
}

type jsonHypo struct {
	Rank       int        `json:"rank"`
	Score      float64    `json:"score"`
	Confidence string     `json:"confidence"`
	LeadMS     int64      `json:"lead_ms"`
	Evidence   []string   `json:"evidence"`
	Cause      jsonSignal `json:"cause"`
}

type jsonFailure struct {
	Adapter string `json:"adapter"`
	Error   string `json:"error"`
}

func toJSONSignal(s signal.Signal) jsonSignal {
	return jsonSignal{
		Timestamp:  s.Timestamp,
		Type:       string(s.Type),
		Severity:   s.Severity.String(),
		Source:     s.Source,
		Title:      s.Title,
		Detail:     s.Detail,
		Labels:     s.Labels,
		Value:      s.Value,
		TraceID:    s.TraceID,
		SpanID:     s.SpanID,
		DurationMS: s.Duration.Milliseconds(),
	}
}

// Timeline writes a timeline as JSON.
func (j *JSON) Timeline(command string, tl correlate.Timeline, failures map[string]string) error {
	env := jsonEnvelope{
		SchemaVersion: schemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Command:       command,
		Timeline: &jsonTimeline{
			From:    tl.From,
			To:      tl.To,
			Buckets: make([]jsonBucket, 0, len(tl.Buckets)),
		},
		Failures: toFailures(failures),
	}
	for _, b := range tl.Buckets {
		jb := jsonBucket{
			Start:       b.Start,
			End:         b.End,
			Sources:     b.Sources(),
			CrossSource: b.CrossSource(),
			Signals:     make([]jsonSignal, 0, len(b.Signals)),
		}
		for _, s := range b.Signals {
			jb.Signals = append(jb.Signals, toJSONSignal(s))
		}
		env.Timeline.Buckets = append(env.Timeline.Buckets, jb)
	}
	return j.write(env)
}

// Hypotheses writes root cause analysis as JSON.
func (j *JSON) Hypotheses(command string, anomaly signal.Signal, hyps []correlate.Hypothesis, failures map[string]string) error {
	a := toJSONSignal(anomaly)
	env := jsonEnvelope{
		SchemaVersion: schemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Command:       command,
		Anomaly:       &a,
		Failures:      toFailures(failures),
	}
	for i, h := range hyps {
		env.Hypotheses = append(env.Hypotheses, jsonHypo{
			Rank:       i + 1,
			Score:      h.Score,
			Confidence: h.Confidence(),
			LeadMS:     h.Lead.Milliseconds(),
			Evidence:   h.Evidence,
			Cause:      toJSONSignal(h.Cause),
		})
	}
	return j.write(env)
}

func toFailures(m map[string]string) []jsonFailure {
	if len(m) == 0 {
		return nil
	}
	out := make([]jsonFailure, 0, len(m))
	for k, v := range m {
		out = append(out, jsonFailure{Adapter: k, Error: v})
	}
	return out
}

func (j *JSON) write(v any) error {
	enc := json.NewEncoder(j.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// --- SARIF ------------------------------------------------------------------

// SARIF emits Static Analysis Results Interchange Format, which is what GitHub
// Advanced Security, GitLab and most security dashboards ingest natively.
//
// Emitting SARIF from `lens audit` means findings flow into an org's existing
// security pipeline with no glue code — that integration is most of the value.
type SARIF struct {
	Out io.Writer
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       sarifRuleProps `json:"properties,omitempty"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    sarifText         `json:"message"`
	Properties map[string]string `json:"properties,omitempty"`
}

// Write emits findings as a SARIF document.
func (s *SARIF) Write(version string, sigs signal.Set) error {
	ruleSet := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(sigs))

	for _, sig := range sigs {
		ruleID := sarifRuleID(sig)
		if _, ok := ruleSet[ruleID]; !ok {
			ruleSet[ruleID] = sarifRule{
				ID:               ruleID,
				Name:             sig.Title,
				ShortDescription: sarifText{Text: sig.Title},
				Properties:       sarifRuleProps{Tags: []string{string(sig.Type), sig.Source}},
			}
		}

		props := map[string]string{
			"timestamp": sig.Timestamp.Format(time.RFC3339Nano),
			"source":    sig.Source,
		}
		for k, v := range sig.Labels {
			props[k] = v
		}

		msg := sig.Detail
		if msg == "" {
			msg = sig.Title
		}

		results = append(results, sarifResult{
			RuleID:     ruleID,
			Level:      sarifLevel(sig.Severity),
			Message:    sarifText{Text: msg},
			Properties: props,
		})
	}

	rules := make([]sarifRule, 0, len(ruleSet))
	for _, r := range ruleSet {
		rules = append(rules, r)
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cncf-lens",
				Version:        version,
				InformationURI: "https://github.com/mohityadav8/cncf-lens",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(s.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifRuleID builds a stable identifier so the same finding deduplicates
// across runs in a security dashboard.
func sarifRuleID(s signal.Signal) string {
	title := strings.ToLower(s.Title)
	if i := strings.Index(title, ":"); i > 0 {
		title = title[:i]
	}
	title = strings.ReplaceAll(strings.TrimSpace(title), " ", "-")
	return fmt.Sprintf("lens/%s/%s", s.Source, title)
}

// sarifLevel maps our severity onto SARIF's smaller vocabulary.
func sarifLevel(sev signal.Severity) string {
	switch sev {
	case signal.SevCritical, signal.SevError:
		return "error"
	case signal.SevWarning:
		return "warning"
	default:
		return "note"
	}
}

// --- Markdown ---------------------------------------------------------------

// Markdown emits an incident-report-shaped document, for pasting into a
// postmortem doc or a GitHub issue.
type Markdown struct {
	Out io.Writer
}

// Report writes a full incident report.
func (m *Markdown) Report(title string, anomaly *signal.Signal, hyps []correlate.Hypothesis, tl correlate.Timeline) error {
	w := m.Out
	fmt.Fprintf(w, "# %s\n\n", title)
	fmt.Fprintf(w, "Generated by cncf-lens at %s\n\n", time.Now().UTC().Format(time.RFC3339))

	if anomaly != nil {
		fmt.Fprintf(w, "## Anomaly\n\n")
		fmt.Fprintf(w, "- **What:** %s\n", anomaly.Title)
		fmt.Fprintf(w, "- **When:** %s\n", anomaly.Timestamp.Format(time.RFC3339))
		fmt.Fprintf(w, "- **Severity:** %s\n", anomaly.Severity)
		fmt.Fprintf(w, "- **Source:** %s\n", anomaly.Source)
		if anomaly.Detail != "" {
			fmt.Fprintf(w, "- **Detail:** %s\n", oneLine(anomaly.Detail))
		}
		fmt.Fprintln(w)
	}

	if len(hyps) > 0 {
		fmt.Fprintf(w, "## Candidate causes\n\n")
		for i, h := range hyps {
			fmt.Fprintf(w, "### %d. %s (%s, score %.2f)\n\n", i+1, h.Cause.Title, h.Confidence(), h.Score)
			fmt.Fprintf(w, "Occurred %s before the anomaly, reported by `%s`.\n\n",
				h.Lead.Round(time.Second), h.Cause.Source)
			if h.Cause.Detail != "" {
				fmt.Fprintf(w, "> %s\n\n", oneLine(h.Cause.Detail))
			}
			fmt.Fprintln(w, "Evidence:")
			for _, e := range h.Evidence {
				fmt.Fprintf(w, "- %s\n", e)
			}
			fmt.Fprintln(w)
		}
	}

	interesting := tl.Interesting()
	if len(interesting) > 0 {
		fmt.Fprintf(w, "## Timeline\n\n")
		fmt.Fprintln(w, "| Time | Sources | Severity | Signal |")
		fmt.Fprintln(w, "|------|---------|----------|--------|")
		for _, b := range interesting {
			for _, s := range b.Signals {
				fmt.Fprintf(w, "| %s | %s | %s | %s |\n",
					s.Timestamp.Format("15:04:05.000"),
					s.Source,
					s.Severity,
					escapePipe(truncate(oneLine(s.Title), 80)),
				)
			}
		}
		fmt.Fprintln(w)
	}
	return nil
}

func escapePipe(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
