package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cncf-lens/lens/internal/signal"
)

// fakeAdapter is a configurable test double.
type fakeAdapter struct {
	name    string
	caps    []signal.Type
	sigs    signal.Set
	err     error
	delay   time.Duration
	panics  bool
	fetched chan struct{}
}

func (f *fakeAdapter) Name() string                      { return f.name }
func (f *fakeAdapter) Capabilities() []signal.Type       { return f.caps }
func (f *fakeAdapter) HealthCheck(context.Context) error { return f.err }

func (f *fakeAdapter) Fetch(ctx context.Context, _ Query) (signal.Set, error) {
	if f.panics {
		panic("adapter exploded")
	}
	if f.fetched != nil {
		close(f.fetched)
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.sigs, f.err
}

func newFake(name string, caps ...signal.Type) *fakeAdapter {
	if len(caps) == 0 {
		caps = []signal.Type{signal.TypeEvent}
	}
	return &fakeAdapter{name: name, caps: caps}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(newFake("prometheus")); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(newFake("prometheus")); err == nil {
		t.Error("duplicate registration should error, not silently overwrite")
	}
}

func TestRegisterRejectsNilAndUnnamed(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("nil adapter should be rejected")
	}
	if err := r.Register(newFake("")); err == nil {
		t.Error("unnamed adapter should be rejected")
	}
}

// The central design promise: one failing backend must not lose the data the
// others returned. This is the behaviour an engineer depends on during an
// outage, when the observability stack is itself partly degraded.
func TestFetchAllReturnsPartialResultsOnFailure(t *testing.T) {
	good := newFake("prometheus", signal.TypeMetric)
	good.sigs = signal.Set{{Timestamp: time.Now(), Title: "a metric", Source: "prometheus"}}

	bad := newFake("jaeger", signal.TypeTrace)
	bad.err = errors.New("connection refused")

	r := NewRegistry()
	_ = r.Register(good)
	_ = r.Register(bad)

	results := r.FetchAll(context.Background(), Query{}, FetchOptions{Timeout: time.Second})
	merged, failed := Merge(results)

	if len(merged) != 1 {
		t.Errorf("want 1 signal from the healthy backend, got %d", len(merged))
	}
	if len(failed) != 1 {
		t.Fatalf("want 1 recorded failure, got %d", len(failed))
	}
	if failed[0].Adapter != "jaeger" {
		t.Errorf("wrong adapter reported as failed: %s", failed[0].Adapter)
	}
}

// A third-party plugin must not be able to crash the CLI mid-incident.
func TestFetchAllRecoversFromPanic(t *testing.T) {
	boom := newFake("rogue-plugin")
	boom.panics = true

	ok := newFake("prometheus", signal.TypeMetric)
	ok.sigs = signal.Set{{Timestamp: time.Now(), Title: "survived"}}

	r := NewRegistry()
	_ = r.Register(boom)
	_ = r.Register(ok)

	results := r.FetchAll(context.Background(), Query{}, FetchOptions{Timeout: time.Second})
	merged, failed := Merge(results)

	if len(merged) != 1 {
		t.Errorf("healthy adapter's data lost to a panicking peer: got %d signals", len(merged))
	}
	if len(failed) != 1 {
		t.Fatal("panic should be recorded as a failure")
	}
}

// One slow backend must not stall the whole command.
func TestFetchAllIsolatesTimeouts(t *testing.T) {
	slow := newFake("slow-backend")
	slow.delay = 3 * time.Second

	fast := newFake("prometheus", signal.TypeMetric)
	fast.sigs = signal.Set{{Timestamp: time.Now(), Title: "quick"}}

	r := NewRegistry()
	_ = r.Register(slow)
	_ = r.Register(fast)

	start := time.Now()
	results := r.FetchAll(context.Background(), Query{}, FetchOptions{Timeout: 200 * time.Millisecond})
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("a slow backend blocked the fan-out for %s", elapsed)
	}
	merged, failed := Merge(results)
	if len(merged) != 1 {
		t.Errorf("fast backend's result was lost: %d signals", len(merged))
	}
	if len(failed) != 1 {
		t.Error("the timed-out backend should be reported as failed")
	}
}

func TestFetchAllRunsConcurrently(t *testing.T) {
	// If the fan-out were sequential, three 150ms adapters would take 450ms.
	r := NewRegistry()
	for _, name := range []string{"a", "b", "c"} {
		f := newFake(name)
		f.delay = 150 * time.Millisecond
		_ = r.Register(f)
	}

	start := time.Now()
	r.FetchAll(context.Background(), Query{}, FetchOptions{Timeout: time.Second})
	elapsed := time.Since(start)

	if elapsed > 400*time.Millisecond {
		t.Errorf("adapters appear to run sequentially: took %s", elapsed)
	}
}

func TestFetchAllRespectsOnlyAndSkip(t *testing.T) {
	r := NewRegistry()
	for _, name := range []string{"prometheus", "loki", "jaeger"} {
		_ = r.Register(newFake(name))
	}

	only := r.FetchAll(context.Background(), Query{}, FetchOptions{Only: []string{"loki"}})
	if len(only) != 1 || only[0].Adapter != "loki" {
		t.Errorf("--only did not restrict the fan-out: %d results", len(only))
	}

	skip := r.FetchAll(context.Background(), Query{}, FetchOptions{Skip: []string{"loki"}})
	if len(skip) != 2 {
		t.Errorf("--skip did not exclude: %d results", len(skip))
	}
	for _, res := range skip {
		if res.Adapter == "loki" {
			t.Error("skipped adapter was still queried")
		}
	}
}

// Querying only for traces should not wake up a metrics-only backend.
func TestFetchAllSkipsIncapableAdapters(t *testing.T) {
	metrics := newFake("prometheus", signal.TypeMetric)
	metrics.fetched = make(chan struct{})

	traces := newFake("jaeger", signal.TypeTrace)

	r := NewRegistry()
	_ = r.Register(metrics)
	_ = r.Register(traces)

	results := r.FetchAll(context.Background(),
		Query{Types: []signal.Type{signal.TypeTrace}},
		FetchOptions{Timeout: time.Second})

	if len(results) != 1 || results[0].Adapter != "jaeger" {
		t.Fatalf("capability filtering failed: %+v", results)
	}
	select {
	case <-metrics.fetched:
		t.Error("a metrics-only adapter was queried for traces")
	default:
	}
}

func TestMergeSortsByTime(t *testing.T) {
	now := time.Now()
	results := []Result{
		{Adapter: "a", Signals: signal.Set{{Timestamp: now.Add(2 * time.Second), Title: "third"}}},
		{Adapter: "b", Signals: signal.Set{{Timestamp: now, Title: "first"}}},
		{Adapter: "c", Signals: signal.Set{{Timestamp: now.Add(time.Second), Title: "second"}}},
	}
	merged, _ := Merge(results)
	want := []string{"first", "second", "third"}
	for i, w := range want {
		if merged[i].Title != w {
			t.Errorf("position %d: want %q, got %q", i, w, merged[i].Title)
		}
	}
}

func TestQueryWantsType(t *testing.T) {
	// An empty filter must match everything, so callers can pass nil freely.
	if !(Query{}).WantsType(signal.TypeLog) {
		t.Error("empty type filter should match all types")
	}
	q := Query{Types: []signal.Type{signal.TypeMetric}}
	if q.WantsType(signal.TypeLog) {
		t.Error("type filter should exclude unlisted types")
	}
	if !q.WantsType(signal.TypeMetric) {
		t.Error("type filter should include listed types")
	}
}
