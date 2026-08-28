// Package command implements the lens subcommands. It owns the wiring between
// config, adapters, the correlation engine and the renderers.
package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cncf-lens/lens/internal/adapter"
	"github.com/cncf-lens/lens/internal/adapter/jaeger"
	"github.com/cncf-lens/lens/internal/adapter/kubernetes"
	"github.com/cncf-lens/lens/internal/adapter/loki"
	"github.com/cncf-lens/lens/internal/adapter/plugin"
	"github.com/cncf-lens/lens/internal/adapter/prometheus"
	"github.com/cncf-lens/lens/internal/cache"
	"github.com/cncf-lens/lens/internal/cli"
	"github.com/cncf-lens/lens/internal/config"
	"github.com/cncf-lens/lens/internal/render"
	"github.com/cncf-lens/lens/internal/signal"
)

// Globals holds the flags every command accepts. A single struct keeps flag
// names consistent across commands, which matters more than it sounds: an
// engineer should never have to remember that one command spells it --ns and
// another spells it --namespace.
type Globals struct {
	ConfigPath string
	Context    string
	Namespace  string
	Pod        string
	Workload   string
	Since      string
	Output     string
	NoColor    bool
	NoCache    bool
	Verbose    bool
	Only       string
	Skip       string
	Timeout    string
	Limit      int
}

// G is the process-wide flag state. A package-level value is acceptable here
// because there is exactly one CLI invocation per process.
var G Globals

// Version is stamped at build time.
var Version = "dev"

// RegisterGlobals attaches the shared flags to a flag set.
func RegisterGlobals(fs *flag.FlagSet) {
	fs.StringVar(&G.ConfigPath, "config", "", "path to config file")
	fs.StringVar(&G.Context, "context", "", "context (cluster) to query")
	fs.StringVar(&G.Namespace, "namespace", "", "Kubernetes namespace to scope the query to")
	fs.StringVar(&G.Pod, "pod", "", "pod name to scope the query to")
	fs.StringVar(&G.Workload, "workload", "", "workload or service name to scope the query to")
	fs.StringVar(&G.Since, "since", "15m", "how far back to look (e.g. 5m, 2h)")
	fs.StringVar(&G.Output, "output", "", "output format: terminal, json, sarif, markdown")
	fs.BoolVar(&G.NoColor, "no-color", false, "disable coloured output")
	fs.BoolVar(&G.NoCache, "no-cache", false, "bypass the local cache")
	fs.BoolVar(&G.Verbose, "verbose", false, "show all signals, including info level")
	fs.StringVar(&G.Only, "only", "", "comma-separated list of backends to query exclusively")
	fs.StringVar(&G.Skip, "skip", "", "comma-separated list of backends to skip")
	fs.StringVar(&G.Timeout, "timeout", "", "per-backend timeout (e.g. 10s)")
	fs.IntVar(&G.Limit, "limit", 0, "maximum signals to fetch per backend")
}

// Runtime is the assembled dependency set for one command invocation.
type Runtime struct {
	Config   *config.Config
	Context  *config.Context
	Registry *adapter.Registry
	Cache    *cache.Cache
	History  *cache.History
	Terminal *render.Terminal
	// PluginErrors are non-fatal plugin discovery failures, surfaced at the end
	// of output rather than blocking the command.
	PluginErrors []error
}

// Setup builds the runtime from config and global flags.
func Setup(ctx context.Context) (*Runtime, error) {
	cfg, err := config.Load(G.ConfigPath)
	if err != nil {
		return nil, err
	}

	cctx, err := cfg.Resolve(G.Context)
	if err != nil {
		return nil, err
	}

	c, err := cache.New(cfg.Defaults.CacheDir, G.NoCache)
	if err != nil {
		return nil, err
	}

	rt := &Runtime{
		Config:   cfg,
		Context:  cctx,
		Registry: adapter.NewRegistry(),
		Cache:    c,
		History:  cache.NewHistory(c),
		Terminal: render.NewTerminal(os.Stdout, !G.NoColor && cfg.Defaults.Color),
	}
	rt.Terminal.Verbose = G.Verbose

	if err := rt.buildRegistry(ctx); err != nil {
		return nil, err
	}
	return rt, nil
}

// buildRegistry instantiates one adapter per enabled backend, then discovers
// external plugins.
func (r *Runtime) buildRegistry(ctx context.Context) error {
	timeout := r.adapterTimeout()

	for _, name := range r.Context.EnabledBackends() {
		bc := r.Context.Backends[name]
		var a adapter.Adapter

		// The backend *type* is inferred from its config key. A team running
		// two Prometheus instances names them `prometheus` and
		// `prometheus-thanos`; the prefix is what selects the adapter.
		switch {
		case name == "kubernetes" || strings.HasPrefix(name, "kubernetes"):
			ka, err := kubernetes.FromContext(r.Context, bc, timeout)
			if err != nil {
				// A missing kubeconfig should not stop a metrics-only query.
				r.PluginErrors = append(r.PluginErrors,
					fmt.Errorf("kubernetes backend unavailable: %w", err))
				continue
			}
			a = ka
		case strings.HasPrefix(name, "prometheus"), strings.HasPrefix(name, "thanos"),
			strings.HasPrefix(name, "mimir"), strings.HasPrefix(name, "cortex"):
			a = prometheus.New(name, bc.URL, bc.Token, bc.Insecure, bc.Timeout)
		case strings.HasPrefix(name, "loki"):
			a = loki.New(name, bc.URL, bc.Token, bc.Insecure, bc.Timeout)
		case strings.HasPrefix(name, "jaeger"), strings.HasPrefix(name, "tempo"):
			a = jaeger.New(name, bc.URL, bc.Token, bc.Insecure, bc.Timeout)
		default:
			// Unknown backend names are not an error: they may be handled by an
			// external plugin discovered below.
			continue
		}

		if err := r.Registry.Register(a); err != nil {
			return err
		}
	}

	// Auto-register Kubernetes when no backends are configured at all, so a
	// zero-config `lens watch` still does something useful.
	if r.Registry.Len() == 0 {
		if ka, err := kubernetes.FromContext(r.Context, config.BackendConfig{Enabled: true}, timeout); err == nil {
			_ = r.Registry.Register(ka)
		}
	}

	// External plugins. Settings are passed through from each backend's config.
	settings := map[string]map[string]string{}
	for name, bc := range r.Context.Backends {
		settings[name] = bc.Extra
	}
	plugins, errs := plugin.Discover(ctx, nil, settings, 5*time.Second)
	r.PluginErrors = append(r.PluginErrors, errs...)
	for _, p := range plugins {
		if err := r.Registry.Register(p); err != nil {
			r.PluginErrors = append(r.PluginErrors, err)
		}
	}

	if r.Registry.Len() == 0 {
		return fmt.Errorf(
			"no backends available.\n\n"+
				"Run `lens init` to auto-detect backends in your cluster, or create %s.\n"+
				"See `lens help config` for the file format.",
			config.DefaultPath())
	}
	return nil
}

func (r *Runtime) adapterTimeout() time.Duration {
	if G.Timeout != "" {
		if d, err := time.ParseDuration(G.Timeout); err == nil {
			return d
		}
	}
	return r.Config.Defaults.AdapterTimeout
}

// Query assembles an adapter.Query from the global flags.
func (r *Runtime) Query(types ...signal.Type) (adapter.Query, error) {
	since, err := time.ParseDuration(G.Since)
	if err != nil {
		return adapter.Query{}, fmt.Errorf("%w: --since=%q is not a duration (try 15m, 2h)", cli.ErrUsage, G.Since)
	}
	if since <= 0 {
		return adapter.Query{}, fmt.Errorf("%w: --since must be positive", cli.ErrUsage)
	}

	now := time.Now().UTC()
	limit := G.Limit
	if limit == 0 {
		limit = r.Config.Defaults.MaxSignalsPerFetch
	}

	return adapter.Query{
		From:      now.Add(-since),
		To:        now,
		Namespace: G.Namespace,
		Pod:       G.Pod,
		Workload:  G.Workload,
		Types:     types,
		Limit:     limit,
	}, nil
}

// FetchOptions builds fan-out options from the global flags.
func (r *Runtime) FetchOptions() adapter.FetchOptions {
	return adapter.FetchOptions{
		Only:    splitList(G.Only),
		Skip:    splitList(G.Skip),
		Timeout: r.adapterTimeout(),
	}
}

// OutputFormat resolves the effective output format.
func (r *Runtime) OutputFormat() string {
	if G.Output != "" {
		return G.Output
	}
	return r.Config.Defaults.Output
}

// ReportFailures prints adapter and plugin errors to stderr.
func (r *Runtime) ReportFailures(results []adapter.Result) {
	var names []string
	var errs []error
	for _, res := range results {
		if res.Err != nil {
			names = append(names, res.Adapter)
			errs = append(errs, res.Err)
		}
	}
	for _, err := range r.PluginErrors {
		names = append(names, "plugin")
		errs = append(errs, err)
	}
	if len(errs) > 0 && r.OutputFormat() == "terminal" {
		r.Terminal.Failures(names, errs)
	}
}

// FailureMap converts results into the map shape the JSON renderer wants.
func FailureMap(results []adapter.Result) map[string]string {
	out := map[string]string{}
	for _, res := range results {
		if res.Err != nil {
			out[res.Adapter] = res.Err.Error()
		}
	}
	return out
}

// Close flushes anything that needs persisting.
func (r *Runtime) Close() {
	if r.History != nil {
		_ = r.History.Flush()
	}
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
