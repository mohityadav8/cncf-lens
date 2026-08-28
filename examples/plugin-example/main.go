// Command lens-plugin-example is a reference implementation of the cncf-lens
// plugin protocol.
//
// Build and install it so lens can discover it:
//
//	go build -o lens-plugin-example ./examples/plugin-example
//	mv lens-plugin-example /usr/local/bin/
//	lens doctor      # the plugin now appears in the backend list
//
// The protocol is three subcommands reading JSON on stdin and writing JSON on
// stdout. Any language can implement it; this happens to be Go.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const protocolVersion = 1

type describeResponse struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	ProtocolVersion int      `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"`
	Description     string   `json:"description,omitempty"`
}

type fetchRequest struct {
	ProtocolVersion int               `json:"protocol_version"`
	From            time.Time         `json:"from"`
	To              time.Time         `json:"to"`
	Namespace       string            `json:"namespace,omitempty"`
	Workload        string            `json:"workload,omitempty"`
	Pod             string            `json:"pod,omitempty"`
	TraceID         string            `json:"trace_id,omitempty"`
	Expr            string            `json:"expr,omitempty"`
	Types           []string          `json:"types,omitempty"`
	Limit           int               `json:"limit,omitempty"`
	Settings        map[string]string `json:"settings,omitempty"`
}

type wireSignal struct {
	Timestamp  time.Time         `json:"timestamp"`
	Type       string            `json:"type"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Detail     string            `json:"detail,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Value      *float64          `json:"value,omitempty"`
	TraceID    string            `json:"trace_id,omitempty"`
	SpanID     string            `json:"span_id,omitempty"`
	DurationMS int64             `json:"duration_ms,omitempty"`
}

type fetchResponse struct {
	Signals  []wireSignal `json:"signals"`
	Error    string       `json:"error,omitempty"`
	Warnings []string     `json:"warnings,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: lens-plugin-example <describe|fetch|health>")
	}

	switch os.Args[1] {
	case "describe":
		emit(describeResponse{
			Name:            "example",
			Version:         "0.1.0",
			ProtocolVersion: protocolVersion,
			// Declare only what you can actually produce: lens skips adapters
			// whose capabilities cannot satisfy a query, saving a round trip.
			Capabilities: []string{"event", "security"},
			Description:  "Reference plugin demonstrating the lens protocol",
		})

	case "health":
		// Verify your backend is reachable here. Exit non-zero with a message
		// on stderr to report a problem; lens surfaces it in `lens doctor`.
		emit(map[string]string{"status": "ok"})

	case "fetch":
		var req fetchRequest
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			emit(fetchResponse{Error: fmt.Sprintf("decoding request: %v", err)})
			return
		}
		if req.ProtocolVersion != protocolVersion {
			emit(fetchResponse{Error: fmt.Sprintf(
				"unsupported protocol version %d", req.ProtocolVersion)})
			return
		}
		emit(fetchResponse{Signals: demoSignals(req)})

	default:
		fatal("unknown subcommand %q", os.Args[1])
	}
}

// demoSignals stands in for a real backend query. Replace this with whatever
// your system exposes — an API call, a database read, a file scan.
func demoSignals(req fetchRequest) []wireSignal {
	ns := req.Namespace
	if ns == "" {
		ns = "default"
	}
	mid := req.From.Add(req.To.Sub(req.From) / 2)

	return []wireSignal{
		{
			Timestamp: mid,
			Type:      "security",
			Severity:  "warning",
			Title:     "Privileged container detected",
			Detail:    "Container runs with privileged: true, granting host-level access",
			// Populate the canonical Kubernetes labels. This is what lets the
			// correlation engine link your signal to metrics, logs and traces
			// from every other backend.
			Labels: map[string]string{
				"namespace": ns,
				"pod":       "legacy-agent-x7f2k",
				"container": "agent",
			},
		},
		{
			Timestamp: mid.Add(30 * time.Second),
			Type:      "event",
			Severity:  "info",
			Title:     "Policy scan completed",
			Detail:    "Evaluated 47 workloads against 12 policies",
			Labels:    map[string]string{"namespace": ns},
		},
	}
}

func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(v); err != nil {
		fatal("writing response: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
