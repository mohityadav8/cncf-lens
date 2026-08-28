// Package plugin lets any executable on $PATH act as a lens backend.
//
// The protocol is deliberately the simplest thing that can work: lens executes
// the plugin binary with a subcommand, writes a JSON request on stdin, and
// reads a JSON response from stdout. stderr is passed through for logging.
//
// Why a subprocess and not Go plugins: Go's `plugin` package requires exact
// toolchain and dependency-version matching between host and plugin, which is
// unworkable for a community ecosystem. Subprocesses let a plugin be written in
// any language — Rust, Python, a shell script — and version independently. This
// is the same trade Terraform, containerd and CNI all made, for the same reason.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cncf-lens/lens/internal/adapter"
	"github.com/cncf-lens/lens/internal/signal"
)

// Prefix is the filename prefix lens looks for when discovering plugins.
const Prefix = "lens-plugin-"

// ProtocolVersion is bumped only on breaking changes. Plugins echo the version
// they implement in their describe response so lens can refuse a mismatch
// rather than misparse it.
const ProtocolVersion = 1

// Adapter wraps an external plugin binary.
type Adapter struct {
	path     string
	pluginID string
	caps     []signal.Type
	timeout  time.Duration
	// settings are passed to the plugin verbatim from its config block, so a
	// plugin can be configured without lens knowing its schema.
	settings map[string]string
}

// describeResponse is what a plugin returns from its `describe` subcommand.
type describeResponse struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	ProtocolVersion int      `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"`
	Description     string   `json:"description,omitempty"`
}

// fetchRequest is written to the plugin's stdin for a `fetch` call.
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

// fetchResponse is what the plugin writes to stdout.
type fetchResponse struct {
	Signals []wireSignal `json:"signals"`
	Error   string       `json:"error,omitempty"`
	// Warnings are surfaced to the user but do not fail the fetch, letting a
	// plugin say "I could only see the last hour" without aborting.
	Warnings []string `json:"warnings,omitempty"`
}

// wireSignal is the JSON shape of a Signal. It is a separate type from
// signal.Signal on purpose: the wire format is a public contract that
// third-party plugins depend on, so it must not change just because we
// refactor an internal struct.
type wireSignal struct {
	Timestamp time.Time         `json:"timestamp"`
	Type      string            `json:"type"`
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	Detail    string            `json:"detail,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Value     *float64          `json:"value,omitempty"`
	TraceID   string            `json:"trace_id,omitempty"`
	SpanID    string            `json:"span_id,omitempty"`
	// DurationMS avoids ambiguity about Go duration encoding across languages.
	DurationMS int64 `json:"duration_ms,omitempty"`
}

func (w wireSignal) toSignal(source string) signal.Signal {
	s := signal.Signal{
		Timestamp: w.Timestamp.UTC(),
		Type:      signal.Type(w.Type),
		Severity:  signal.ParseSeverity(w.Severity),
		Source:    source,
		Title:     w.Title,
		Detail:    w.Detail,
		Labels:    w.Labels,
		Value:     w.Value,
		TraceID:   w.TraceID,
		SpanID:    w.SpanID,
		Duration:  time.Duration(w.DurationMS) * time.Millisecond,
	}
	// Guard against a plugin sending an unknown type, which would otherwise
	// silently vanish from every type filter downstream.
	if !validType(s.Type) {
		s.Type = signal.TypeEvent
	}
	return s
}

func validType(t signal.Type) bool {
	for _, known := range signal.AllTypes() {
		if known == t {
			return true
		}
	}
	return false
}

// Discover finds plugin binaries on $PATH and in extraDirs, handshakes with
// each, and returns adapters for the ones that respond correctly.
//
// A plugin that fails its handshake is skipped with a warning rather than
// failing the whole command: one broken third-party plugin must not stop an
// engineer from running lens during an outage.
func Discover(ctx context.Context, extraDirs []string, settings map[string]map[string]string, timeout time.Duration) ([]*Adapter, []error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	seen := make(map[string]bool)
	var found []string

	dirs := append([]string{}, extraDirs...)
	dirs = append(dirs, filepath.SplitList(os.Getenv("PATH"))...)

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, Prefix) || seen[name] {
				continue
			}
			full := filepath.Join(dir, name)
			if !isExecutable(full) {
				continue
			}
			seen[name] = true
			found = append(found, full)
		}
	}
	sort.Strings(found)

	var adapters []*Adapter
	var errs []error
	for _, path := range found {
		id := strings.TrimPrefix(filepath.Base(path), Prefix)
		a, err := handshake(ctx, path, id, settings[id], timeout)
		if err != nil {
			errs = append(errs, fmt.Errorf("plugin %s: %w", filepath.Base(path), err))
			continue
		}
		adapters = append(adapters, a)
	}
	return adapters, errs
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode()&0o111 != 0
}

// handshake runs `<plugin> describe` and validates the response.
func handshake(ctx context.Context, path, id string, settings map[string]string, timeout time.Duration) (*Adapter, error) {
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := run(hctx, path, "describe", nil)
	if err != nil {
		return nil, err
	}

	var desc describeResponse
	if err := json.Unmarshal(out, &desc); err != nil {
		return nil, fmt.Errorf("describe returned invalid JSON: %w", err)
	}
	if desc.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf(
			"implements protocol version %d but this lens build speaks version %d",
			desc.ProtocolVersion, ProtocolVersion)
	}
	if desc.Name == "" {
		return nil, fmt.Errorf("describe returned an empty name")
	}

	caps := make([]signal.Type, 0, len(desc.Capabilities))
	for _, c := range desc.Capabilities {
		t := signal.Type(c)
		if validType(t) {
			caps = append(caps, t)
		}
	}
	if len(caps) == 0 {
		return nil, fmt.Errorf("declares no valid capabilities (got %v)", desc.Capabilities)
	}

	return &Adapter{
		path:     path,
		pluginID: desc.Name,
		caps:     caps,
		timeout:  30 * time.Second,
		settings: settings,
	}, nil
}

func (a *Adapter) Name() string { return a.pluginID }

func (a *Adapter) Capabilities() []signal.Type { return a.caps }

func (a *Adapter) HealthCheck(ctx context.Context) error {
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := run(hctx, a.path, "health", nil); err != nil {
		return err
	}
	return nil
}

// Fetch marshals the query, runs the plugin, and unmarshals the signals.
func (a *Adapter) Fetch(ctx context.Context, q adapter.Query) (signal.Set, error) {
	types := make([]string, 0, len(q.Types))
	for _, t := range q.Types {
		types = append(types, string(t))
	}

	req := fetchRequest{
		ProtocolVersion: ProtocolVersion,
		From:            q.From.UTC(),
		To:              q.To.UTC(),
		Namespace:       q.Namespace,
		Workload:        q.Workload,
		Pod:             q.Pod,
		TraceID:         q.TraceID,
		Expr:            q.Expr,
		Types:           types,
		Limit:           q.Limit,
		Settings:        a.settings,
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}

	out, err := run(ctx, a.path, "fetch", payload)
	if err != nil {
		return nil, err
	}

	var resp fetchResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("fetch returned invalid JSON: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}

	sigs := make(signal.Set, 0, len(resp.Signals))
	for _, ws := range resp.Signals {
		if ws.Timestamp.IsZero() {
			continue // a signal with no time cannot be correlated
		}
		sigs = append(sigs, ws.toSignal(a.pluginID))
	}
	sigs.SortByTime()
	return sigs, nil
}

// run executes the plugin with a subcommand and optional stdin payload.
func run(ctx context.Context, path, subcommand string, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, subcommand)

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Plugins inherit a minimal environment. We pass through the parent env so
	// credential variables work, but explicitly mark the protocol version so a
	// plugin can adapt without parsing argv.
	cmd.Env = append(os.Environ(), fmt.Sprintf("LENS_PROTOCOL_VERSION=%d", ProtocolVersion))

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if ctx.Err() != nil {
			return nil, fmt.Errorf("timed out running %s", subcommand)
		}
		if msg != "" {
			return nil, fmt.Errorf("%s failed: %s", subcommand, truncate(msg, 300))
		}
		return nil, fmt.Errorf("%s failed: %w", subcommand, err)
	}

	// A plugin writing nothing is a bug, and an empty JSON decode error is a
	// confusing way to report it.
	if stdout.Len() == 0 {
		return nil, fmt.Errorf("%s produced no output on stdout", subcommand)
	}
	return stdout.Bytes(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
