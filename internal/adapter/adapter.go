// Package adapter defines the contract every backend integration implements,
// plus a registry that fans a single Query out to all of them concurrently.
//
// This interface is the leverage point of the whole project: any CNCF project
// can become a first-class lens backend by implementing four methods, either
// compiled in or shipped as an external `lens-plugin-*` binary.
package adapter

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cncf-lens/lens/internal/signal"
)

// Query describes what the caller wants. Adapters translate it into their own
// native query language: PromQL for Prometheus, LogQL for Loki, a field
// selector for the Kubernetes API, and so on.
//
// Adapters must treat every field as a best-effort hint. An adapter that cannot
// honour a filter should return a superset rather than an error — the
// correlation engine filters again downstream, so over-fetching is safe while
// under-fetching silently loses evidence.
type Query struct {
	// From and To bound the time window. Always set; never zero.
	From time.Time
	To   time.Time

	// Namespace and Workload narrow the search to a Kubernetes identity.
	Namespace string
	Workload  string
	Pod       string

	// TraceID, when set, asks for everything associated with one trace.
	TraceID string

	// Expr is a backend-native expression passed through verbatim, used by
	// `lens diagnose --metric=<promql>`. Adapters that do not understand it
	// should ignore it rather than fail.
	Expr string

	// Types restricts which signal types the caller cares about. Empty means
	// all types; adapters should skip work they know is unwanted.
	Types []signal.Type

	// Limit caps how many signals to return per adapter. Zero means no cap.
	Limit int
}

// WantsType reports whether the caller asked for this signal type. Adapters
// call this early to skip expensive fetches they know will be discarded.
func (q Query) WantsType(t signal.Type) bool {
	if len(q.Types) == 0 {
		return true
	}
	for _, want := range q.Types {
		if want == t {
			return true
		}
	}
	return false
}

// Duration is the width of the query window.
func (q Query) Duration() time.Duration { return q.To.Sub(q.From) }

// Adapter is implemented by every backend integration.
type Adapter interface {
	// Name is the stable identifier used in config files, in the Source field
	// of emitted Signals, and in `--only` / `--skip` CLI filters.
	Name() string

	// Capabilities declares which signal types this adapter can produce, so the
	// registry can skip adapters that cannot contribute to a query.
	Capabilities() []signal.Type

	// Fetch retrieves signals matching the query. It must respect ctx
	// cancellation, and must not block past the context deadline.
	Fetch(ctx context.Context, q Query) (signal.Set, error)

	// HealthCheck verifies the backend is reachable and configured correctly.
	// `lens init` and `lens doctor` use this to validate a config.
	HealthCheck(ctx context.Context) error
}

// Result pairs one adapter's output with any error it hit. The registry returns
// these rather than a single error because partial results are genuinely useful
// during an incident: if Jaeger is down but Prometheus and Loki answered, we
// still want to show what we have and say clearly what is missing.
type Result struct {
	Adapter string
	Signals signal.Set
	Err     error
	Elapsed time.Duration
}

// Registry holds the configured adapters and fans queries out to them.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
	order    []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

// Register adds an adapter. Registering the same name twice is an error rather
// than a silent overwrite, so a typo'd config surfaces immediately.
func (r *Registry) Register(a Adapter) error {
	if a == nil {
		return errors.New("adapter: cannot register nil adapter")
	}
	name := a.Name()
	if name == "" {
		return errors.New("adapter: adapter has empty name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.adapters[name]; exists {
		return fmt.Errorf("adapter: %q already registered", name)
	}
	r.adapters[name] = a
	r.order = append(r.order, name)
	sort.Strings(r.order)
	return nil
}

// Get returns a single adapter by name.
func (r *Registry) Get(name string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	return a, ok
}

// Names lists registered adapter names in stable sorted order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// Len reports how many adapters are registered.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.adapters)
}

// FetchOptions tunes a fan-out.
type FetchOptions struct {
	// Only, when non-empty, restricts the fan-out to these adapter names.
	Only []string
	// Skip excludes these adapter names.
	Skip []string
	// Timeout bounds each individual adapter. One slow backend must never
	// stall the whole command, so each adapter gets its own derived context.
	Timeout time.Duration
}

const defaultAdapterTimeout = 20 * time.Second

// FetchAll queries every eligible adapter concurrently and returns one Result
// per adapter, in stable name order.
//
// Design note: we deliberately do not fail fast. During an incident a partially
// degraded observability stack is the norm, and an engineer needs whatever
// evidence is still reachable. Errors travel alongside data, not instead of it.
func (r *Registry) FetchAll(ctx context.Context, q Query, opts FetchOptions) []Result {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultAdapterTimeout
	}

	selected := r.selectAdapters(q, opts)
	results := make([]Result, len(selected))

	var wg sync.WaitGroup
	for i, a := range selected {
		wg.Add(1)
		go func(i int, a Adapter) {
			defer wg.Done()
			// Recover from adapter panics. A third-party adapter must never be
			// able to take down the whole CLI mid-incident.
			defer func() {
				if rec := recover(); rec != nil {
					results[i] = Result{
						Adapter: a.Name(),
						Err:     fmt.Errorf("adapter panicked: %v", rec),
					}
				}
			}()

			actx, cancel := context.WithTimeout(ctx, opts.Timeout)
			defer cancel()

			start := time.Now()
			sigs, err := a.Fetch(actx, q)
			results[i] = Result{
				Adapter: a.Name(),
				Signals: sigs,
				Err:     err,
				Elapsed: time.Since(start),
			}
		}(i, a)
	}
	wg.Wait()
	return results
}

// selectAdapters applies Only/Skip filters and drops adapters whose
// capabilities cannot satisfy the query's requested types.
func (r *Registry) selectAdapters(q Query, opts FetchOptions) []Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	only := toSet(opts.Only)
	skip := toSet(opts.Skip)

	var out []Adapter
	for _, name := range r.order {
		if len(only) > 0 && !only[name] {
			continue
		}
		if skip[name] {
			continue
		}
		a := r.adapters[name]
		if !capabilitiesMatch(a.Capabilities(), q.Types) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// capabilitiesMatch reports whether an adapter can contribute at least one of
// the requested types. An empty want list matches everything.
func capabilitiesMatch(have []signal.Type, want []signal.Type) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}

func toSet(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Merge flattens results into a single time-sorted Set, plus the list of
// adapters that failed. Callers surface the failures to the user so a partial
// answer is never mistaken for a complete one.
func Merge(results []Result) (signal.Set, []Result) {
	var all signal.Set
	var failed []Result
	for _, res := range results {
		if res.Err != nil {
			failed = append(failed, res)
			continue
		}
		all = append(all, res.Signals...)
	}
	all.SortByTime()
	return all, failed
}

// HealthCheckAll runs every adapter's health check concurrently. Used by
// `lens doctor` to tell an operator exactly which backend is misconfigured.
func (r *Registry) HealthCheckAll(ctx context.Context, timeout time.Duration) []Result {
	if timeout <= 0 {
		timeout = defaultAdapterTimeout
	}
	r.mu.RLock()
	names := make([]string, len(r.order))
	copy(names, r.order)
	adapters := make([]Adapter, 0, len(names))
	for _, n := range names {
		adapters = append(adapters, r.adapters[n])
	}
	r.mu.RUnlock()

	results := make([]Result, len(adapters))
	var wg sync.WaitGroup
	for i, a := range adapters {
		wg.Add(1)
		go func(i int, a Adapter) {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					results[i] = Result{Adapter: a.Name(), Err: fmt.Errorf("panicked: %v", rec)}
				}
			}()
			actx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := time.Now()
			err := a.HealthCheck(actx)
			results[i] = Result{Adapter: a.Name(), Err: err, Elapsed: time.Since(start)}
		}(i, a)
	}
	wg.Wait()
	return results
}
