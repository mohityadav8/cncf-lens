package plugin

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/signal"
)

// writePlugin creates an executable shell script acting as a plugin. Using a
// script rather than a Go binary keeps the test fast and proves the protocol is
// genuinely language-agnostic — the whole point of the subprocess design.
func writePlugin(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\n" + body
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func skipOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugins are not portable to Windows")
	}
}

const goodPlugin = `
case "$1" in
  describe)
    echo '{"name":"testbackend","version":"1.0.0","protocol_version":1,"capabilities":["event","security"]}'
    ;;
  health)
    echo '{"status":"ok"}'
    ;;
  fetch)
    cat > /dev/null
    echo '{"signals":[{"timestamp":"2026-03-14T15:09:26Z","type":"security","severity":"critical","title":"Privileged container","detail":"runs as root","labels":{"namespace":"payments","pod":"agent-x7f2k"}}]}'
    ;;
esac
`

func TestDiscoverAndFetch(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	writePlugin(t, dir, Prefix+"testbackend", goodPlugin)

	adapters, errs := Discover(context.Background(), []string{dir}, nil, 5*time.Second)
	if len(errs) > 0 {
		t.Fatalf("discovery errors: %v", errs)
	}
	if len(adapters) != 1 {
		t.Fatalf("want 1 discovered plugin, got %d", len(adapters))
	}

	a := adapters[0]
	if a.Name() != "testbackend" {
		t.Errorf("plugin name = %q", a.Name())
	}
	if len(a.Capabilities()) != 2 {
		t.Errorf("capabilities = %v", a.Capabilities())
	}

	if err := a.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}

	sigs, err := a.Fetch(context.Background(), adapter.Query{
		From: time.Now().Add(-time.Hour), To: time.Now(), Namespace: "payments",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("want 1 signal, got %d", len(sigs))
	}

	got := sigs[0]
	if got.Source != "testbackend" {
		t.Errorf("Source = %q, want the plugin name", got.Source)
	}
	if got.Type != signal.TypeSecurity {
		t.Errorf("Type = %q", got.Type)
	}
	if got.Severity != signal.SevCritical {
		t.Errorf("Severity = %v", got.Severity)
	}
	if got.Labels[signal.LabelNamespace] != "payments" {
		t.Errorf("labels not preserved: %v", got.Labels)
	}
}

// A plugin built against a future protocol must be refused, not misparsed.
func TestDiscoverRejectsProtocolMismatch(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	writePlugin(t, dir, Prefix+"future", `
case "$1" in
  describe) echo '{"name":"future","protocol_version":99,"capabilities":["event"]}' ;;
esac
`)

	adapters, errs := Discover(context.Background(), []string{dir}, nil, 5*time.Second)
	if len(adapters) != 0 {
		t.Error("a protocol-mismatched plugin was accepted")
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 discovery error, got %d", len(errs))
	}
}

// One broken plugin must not stop the others from loading — an engineer needs
// lens most when parts of their environment are broken.
func TestDiscoverIsolatesBrokenPlugins(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	writePlugin(t, dir, Prefix+"broken", `exit 1`)
	writePlugin(t, dir, Prefix+"garbage", `echo 'not json at all'`)
	writePlugin(t, dir, Prefix+"testbackend", goodPlugin)

	adapters, errs := Discover(context.Background(), []string{dir}, nil, 5*time.Second)
	if len(adapters) != 1 {
		t.Errorf("the healthy plugin was lost: got %d adapters", len(adapters))
	}
	if len(errs) != 2 {
		t.Errorf("want 2 reported failures, got %d: %v", len(errs), errs)
	}
}

func TestFetchSurfacesPluginError(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	writePlugin(t, dir, Prefix+"erroring", `
case "$1" in
  describe) echo '{"name":"erroring","protocol_version":1,"capabilities":["event"]}' ;;
  fetch) cat > /dev/null; echo '{"error":"upstream API returned 503"}' ;;
esac
`)

	adapters, _ := Discover(context.Background(), []string{dir}, nil, 5*time.Second)
	if len(adapters) != 1 {
		t.Fatal("plugin not discovered")
	}
	_, err := adapters[0].Fetch(context.Background(), adapter.Query{From: time.Now(), To: time.Now()})
	if err == nil {
		t.Fatal("expected the plugin's error to propagate")
	}
}

// Signals with no timestamp cannot be correlated and must be dropped rather
// than silently landing at the zero time, decades before the query window.
func TestFetchDropsTimestamplessSignals(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	writePlugin(t, dir, Prefix+"sloppy", `
case "$1" in
  describe) echo '{"name":"sloppy","protocol_version":1,"capabilities":["event"]}' ;;
  fetch) cat > /dev/null; echo '{"signals":[{"type":"event","title":"no timestamp"},{"timestamp":"2026-03-14T15:09:26Z","type":"event","title":"valid"}]}' ;;
esac
`)

	adapters, _ := Discover(context.Background(), []string{dir}, nil, 5*time.Second)
	sigs, err := adapters[0].Fetch(context.Background(), adapter.Query{From: time.Now(), To: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 || sigs[0].Title != "valid" {
		t.Errorf("timestampless signal was not dropped: %+v", sigs)
	}
}

// The reference plugin shipped in examples/ must actually satisfy the protocol.
// If this fails, our own documentation is wrong.
func TestReferencePluginConformsToProtocol(t *testing.T) {
	skipOnWindows(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}

	dir := t.TempDir()
	out := filepath.Join(dir, Prefix+"example")

	build := exec.Command("go", "build", "-o", out, "../../../examples/plugin-example")
	build.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=mod")
	if combined, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the reference plugin failed: %v\n%s", err, combined)
	}

	adapters, errs := Discover(context.Background(), []string{dir}, nil, 10*time.Second)
	if len(errs) > 0 {
		t.Fatalf("the reference plugin failed handshake: %v", errs)
	}
	if len(adapters) != 1 {
		t.Fatalf("reference plugin not discovered")
	}

	sigs, err := adapters[0].Fetch(context.Background(), adapter.Query{
		From: time.Now().Add(-time.Hour), To: time.Now(), Namespace: "payments",
	})
	if err != nil {
		t.Fatalf("reference plugin Fetch: %v", err)
	}
	if len(sigs) == 0 {
		t.Fatal("reference plugin returned no signals")
	}
	for _, s := range sigs {
		if s.Timestamp.IsZero() {
			t.Error("reference plugin emitted a signal with no timestamp")
		}
		if s.Source != "example" {
			t.Errorf("Source = %q, want the declared plugin name", s.Source)
		}
	}
}
