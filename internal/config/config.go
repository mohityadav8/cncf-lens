// Package config loads and validates the cncf-lens configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Config is the fully resolved configuration for one invocation.
type Config struct {
	// Contexts maps a context name to its backend configuration. A context is
	// usually one cluster; teams commonly have dev / staging / prod.
	Contexts map[string]*Context

	// DefaultContext is used when --context is not passed.
	DefaultContext string

	// Defaults holds global tunables.
	Defaults Defaults

	// Path records where this config was loaded from, for error messages.
	Path string
}

// Context is one cluster's worth of backend endpoints.
type Context struct {
	Name string

	// Kubeconfig and Kubecontext locate the Kubernetes cluster. Empty
	// Kubeconfig means in-cluster config or the standard ~/.kube/config.
	Kubeconfig  string
	Kubecontext string

	// Backends maps an adapter name to its settings. Adapter-specific keys are
	// kept as a raw map so that third-party plugins can read their own
	// configuration without lens needing to know their schema.
	Backends map[string]BackendConfig
}

// BackendConfig is one adapter's settings.
type BackendConfig struct {
	// Name is the adapter name, matching Adapter.Name().
	Name string

	// Enabled allows disabling a backend without deleting its config block.
	Enabled bool

	// URL is the base endpoint for HTTP backends.
	URL string

	// Endpoint is the host:port for gRPC backends.
	Endpoint string

	// Token is the resolved bearer token. Never logged.
	Token string

	// Insecure disables TLS verification. Off by default, and lens warns when
	// it is on, because an observability tool quietly accepting any cert is a
	// credential-theft vector.
	Insecure bool

	// Timeout bounds requests to this backend.
	Timeout time.Duration

	// Extra carries adapter-specific keys verbatim for plugins.
	Extra map[string]string
}

// Defaults holds global tunables.
type Defaults struct {
	CacheTTL           time.Duration
	CorrelationWindow  time.Duration
	Lookback           time.Duration
	Output             string
	AdapterTimeout     time.Duration
	MaxSignalsPerFetch int
	CacheDir           string
	Color              bool
}

// DefaultDefaults returns the built-in defaults used when a config omits them.
func DefaultDefaults() Defaults {
	return Defaults{
		CacheTTL:           5 * time.Minute,
		CorrelationWindow:  500 * time.Millisecond,
		Lookback:           15 * time.Minute,
		Output:             "terminal",
		AdapterTimeout:     20 * time.Second,
		MaxSignalsPerFetch: 2000,
		CacheDir:           defaultCacheDir(),
		Color:              true,
	}
}

func defaultCacheDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "cncf-lens")
	}
	return ".lens-cache"
}

// DefaultPath returns the standard config location, honouring the
// LENS_CONFIG environment variable and XDG conventions.
func DefaultPath() string {
	if p := os.Getenv("LENS_CONFIG"); p != "" {
		return p
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "cncf-lens", "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(home, ".config", "cncf-lens", "config.yaml")
}

// Load reads and validates a config file. A missing file is not an error: lens
// falls back to a zero-config mode that discovers backends from the current
// kubeconfig, so `lens` works on a fresh machine with no setup.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return zeroConfig(path), nil
		}
		return nil, fmt.Errorf("opening config %s: %w", path, err)
	}
	defer f.Close()

	root, err := ParseYAML(f)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	cfg := &Config{
		Contexts: map[string]*Context{},
		Defaults: DefaultDefaults(),
		Path:     path,
	}

	if err := cfg.loadDefaults(root); err != nil {
		return nil, err
	}
	if err := cfg.loadContexts(root); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// zeroConfig returns a usable config for a machine with no config file.
func zeroConfig(path string) *Config {
	return &Config{
		Contexts: map[string]*Context{
			"default": {
				Name:     "default",
				Backends: map[string]BackendConfig{},
			},
		},
		DefaultContext: "default",
		Defaults:       DefaultDefaults(),
		Path:           path,
	}
}

func (c *Config) loadDefaults(root *Node) error {
	d, ok := root.Child("defaults")
	if !ok {
		return nil
	}
	if v := d.String("context", ""); v != "" {
		c.DefaultContext = v
	}
	if v := d.String("output", ""); v != "" {
		c.Defaults.Output = v
	}
	if v := d.String("cache_dir", ""); v != "" {
		c.Defaults.CacheDir = expandEnv(v)
	}
	c.Defaults.Color = d.Bool("color", c.Defaults.Color)
	c.Defaults.MaxSignalsPerFetch = d.Int("max_signals", c.Defaults.MaxSignalsPerFetch)

	for _, spec := range []struct {
		key    string
		target *time.Duration
	}{
		{"cache_ttl", &c.Defaults.CacheTTL},
		{"correlation_window", &c.Defaults.CorrelationWindow},
		{"lookback", &c.Defaults.Lookback},
		{"adapter_timeout", &c.Defaults.AdapterTimeout},
	} {
		raw := d.String(spec.key, "")
		if raw == "" {
			continue
		}
		dur, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("defaults.%s: %q is not a valid duration (try 30s, 5m, 1h)", spec.key, raw)
		}
		*spec.target = dur
	}
	return nil
}

func (c *Config) loadContexts(root *Node) error {
	ctxs, ok := root.Child("contexts")
	if !ok || ctxs.Map == nil {
		// A config with defaults but no contexts still gets a usable default.
		c.Contexts["default"] = &Context{Name: "default", Backends: map[string]BackendConfig{}}
		if c.DefaultContext == "" {
			c.DefaultContext = "default"
		}
		return nil
	}

	for _, name := range sortedKeys(ctxs.Map) {
		node := ctxs.Map[name]
		cc := &Context{
			Name:        name,
			Kubeconfig:  expandEnv(node.String("kubeconfig", "")),
			Kubecontext: node.String("kubecontext", ""),
			Backends:    map[string]BackendConfig{},
		}

		backends, ok := node.Child("backends")
		if ok && backends.Map != nil {
			for _, bname := range sortedKeys(backends.Map) {
				bc, err := loadBackend(bname, backends.Map[bname], c.Defaults.AdapterTimeout)
				if err != nil {
					return fmt.Errorf("contexts.%s.backends.%s: %w", name, bname, err)
				}
				cc.Backends[bname] = bc
			}
		}
		c.Contexts[name] = cc
	}

	if c.DefaultContext == "" {
		names := sortedKeys(ctxs.Map)
		if len(names) > 0 {
			c.DefaultContext = names[0]
		}
	}
	return nil
}

func loadBackend(name string, node *Node, defTimeout time.Duration) (BackendConfig, error) {
	bc := BackendConfig{
		Name:     name,
		Enabled:  node.Bool("enabled", true),
		URL:      expandEnv(node.String("url", "")),
		Endpoint: expandEnv(node.String("endpoint", "")),
		Insecure: node.Bool("insecure", false),
		Timeout:  defTimeout,
		Extra:    map[string]string{},
	}

	// Tokens can be given inline (discouraged) or, preferably, by naming an
	// environment variable to read. We support both but never echo either.
	if envVar := node.String("token_env", ""); envVar != "" {
		bc.Token = os.Getenv(envVar)
		if bc.Token == "" {
			return bc, fmt.Errorf("token_env names %q but that variable is empty", envVar)
		}
	} else if inline := node.String("token", ""); inline != "" {
		bc.Token = expandEnv(inline)
	}

	// A token file is the third option, matching how service account tokens are
	// projected into pods.
	if tf := expandEnv(node.String("token_file", "")); tf != "" {
		data, err := os.ReadFile(tf)
		if err != nil {
			return bc, fmt.Errorf("reading token_file %s: %w", tf, err)
		}
		bc.Token = strings.TrimSpace(string(data))
	}

	if raw := node.String("timeout", ""); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return bc, fmt.Errorf("timeout: %q is not a valid duration", raw)
		}
		bc.Timeout = d
	}

	// Any key we do not recognise is preserved for plugins.
	known := map[string]bool{
		"enabled": true, "url": true, "endpoint": true, "insecure": true,
		"token": true, "token_env": true, "token_file": true, "timeout": true,
	}
	for _, k := range node.Keys() {
		if known[k] {
			continue
		}
		if child := node.Map[k]; child != nil && child.IsScalar {
			bc.Extra[k] = expandEnv(child.Scalar)
		}
	}

	return bc, nil
}

// Validate checks the config is internally consistent.
func (c *Config) Validate() error {
	if len(c.Contexts) == 0 {
		return fmt.Errorf("config %s defines no contexts", c.Path)
	}
	if c.DefaultContext != "" {
		if _, ok := c.Contexts[c.DefaultContext]; !ok {
			return fmt.Errorf("defaults.context is %q but no such context is defined (have: %s)",
				c.DefaultContext, strings.Join(c.ContextNames(), ", "))
		}
	}
	valid := map[string]bool{"terminal": true, "json": true, "sarif": true, "markdown": true}
	if !valid[c.Defaults.Output] {
		return fmt.Errorf("defaults.output %q is not one of: terminal, json, sarif, markdown", c.Defaults.Output)
	}
	for name, ctx := range c.Contexts {
		for bname, b := range ctx.Backends {
			if !b.Enabled {
				continue
			}
			if b.URL == "" && b.Endpoint == "" && bname != "kubernetes" {
				return fmt.Errorf("contexts.%s.backends.%s: needs either `url` or `endpoint`", name, bname)
			}
		}
	}
	return nil
}

// Resolve returns the named context, or the default when name is empty.
func (c *Config) Resolve(name string) (*Context, error) {
	if name == "" {
		name = c.DefaultContext
	}
	if name == "" {
		return nil, fmt.Errorf("no context specified and no default set in %s", c.Path)
	}
	ctx, ok := c.Contexts[name]
	if !ok {
		return nil, fmt.Errorf("context %q not found (have: %s)", name, strings.Join(c.ContextNames(), ", "))
	}
	return ctx, nil
}

// ContextNames lists context names in stable order.
func (c *Config) ContextNames() []string {
	return sortedKeys(c.Contexts)
}

// EnabledBackends lists the enabled backend names for a context.
func (ctx *Context) EnabledBackends() []string {
	var out []string
	for name, b := range ctx.Backends {
		if b.Enabled {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// expandEnv expands ${VAR} and $VAR references so configs can be committed to
// git without embedding secrets.
func expandEnv(s string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	return os.ExpandEnv(s)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
