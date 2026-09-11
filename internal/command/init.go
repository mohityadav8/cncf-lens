package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mohityadav8/cncf-lens/internal/cli"
	"github.com/mohityadav8/cncf-lens/internal/config"
)

var initFlags struct {
	force  bool
	output string
}

// Init builds the `lens init` command.
func Init() *cli.Command {
	return &cli.Command{
		Name:    "init",
		Group:   "Setup",
		Summary: "Generate a starter config file",
		Usage:   "lens init [--output=PATH] [--force]",
		Long: `Init writes a commented configuration file with the standard CNCF stack
endpoints filled in as port-forward defaults, so you can get running without
reading the docs first.

The generated file uses token_env rather than inline credentials, so it is safe
to commit to a repository. Point the named environment variables at your real
tokens.`,
		Examples: []string{
			"lens init",
			"lens init --output=./lens.yaml",
		},
		SetupFlags: func(fs *flag.FlagSet) {
			fs.BoolVar(&initFlags.force, "force", false, "overwrite an existing config file")
			fs.StringVar(&initFlags.output, "output-file", "", "where to write the config")
		},
		Run: runInit,
	}
}

func runInit(_ context.Context, _ []string) error {
	path := initFlags.output
	if path == "" {
		path = config.DefaultPath()
	}

	if _, err := os.Stat(path); err == nil && !initFlags.force {
		return fmt.Errorf("%s already exists — pass --force to overwrite", path)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(starterConfig), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	fmt.Fprintf(os.Stdout, "Wrote %s\n\n", path)
	fmt.Fprintln(os.Stdout, "Next steps:")
	fmt.Fprintln(os.Stdout, "  1. Edit the file and set the backend URLs for your cluster.")
	fmt.Fprintln(os.Stdout, "  2. If your backends are in-cluster, port-forward them:")
	fmt.Fprintln(os.Stdout, "       kubectl -n monitoring port-forward svc/prometheus 9090:9090 &")
	fmt.Fprintln(os.Stdout, "       kubectl -n monitoring port-forward svc/loki 3100:3100 &")
	fmt.Fprintln(os.Stdout, "  3. Verify connectivity:  lens doctor")
	fmt.Fprintln(os.Stdout, "  4. Try it:               lens diagnose --namespace=default")
	return nil
}

const starterConfig = `# cncf-lens configuration
#
# Safe to commit: credentials are read from environment variables named here,
# never stored inline.

defaults:
  context: local
  output: terminal          # terminal | json | sarif | markdown
  cache_ttl: 5m
  correlation_window: 500ms # how close in time signals must be to correlate
  lookback: 15m             # default causal search window
  adapter_timeout: 20s
  max_signals: 2000
  color: true

contexts:
  local:
    # Leave kubeconfig empty to use $KUBECONFIG or ~/.kube/config.
    kubeconfig: ""
    kubecontext: ""

    backends:
      kubernetes:
        enabled: true

      prometheus:
        enabled: true
        url: http://localhost:9090
        # token_env: PROM_TOKEN
        timeout: 20s

      loki:
        enabled: true
        url: http://localhost:3100
        # token_env: LOKI_TOKEN

      jaeger:
        enabled: true
        url: http://localhost:16686
        # token_env: JAEGER_TOKEN

      # Falco runtime security.
      #
      # "file" is the supported historical alert source for lens and should point
      # at a Falco file_output JSON-lines file.
      #
      # "url" may be used for connectivity checks to an HTTP receiver such as
      # falcosidekick, but Lens cannot query historical alerts from that receiver.
      falco:
        enabled: false
        # url: http://localhost:2801
        # file: /var/log/falco/events.json

  # A second context for production. Note token_env rather than inline tokens.
  #
  # production:
  #   kubecontext: prod-us-east-1
  #   backends:
  #     prometheus:
  #       enabled: true
  #       url: https://thanos.prod.internal
  #       token_env: THANOS_TOKEN
  #     loki:
  #       enabled: true
  #       url: https://loki.prod.internal
  #       token_env: LOKI_TOKEN
`

// Doctor builds the `lens doctor` command.
func Doctor() *cli.Command {
	return &cli.Command{
		Name:    "doctor",
		Group:   "Setup",
		Summary: "Check that every configured backend is reachable",
		Usage:   "lens doctor",
		Long: `Doctor runs each backend's health check and reports exactly which ones are
reachable, which are misconfigured, and why. Run it first whenever a command
returns less data than you expected.`,
		Run: runDoctor,
	}
}

func runDoctor(ctx context.Context, _ []string) error {
	rt, err := Setup(ctx)
	if err != nil {
		// A setup failure is itself diagnostic information, so report it as
		// output rather than as an opaque error.
		fmt.Fprintf(os.Stdout, "\nConfiguration problem:\n  %s\n\n", err)
		return err
	}
	defer rt.Close()

	fmt.Fprintf(os.Stdout, "\ncncf-lens %s\n", Version)
	fmt.Fprintf(os.Stdout, "config:  %s\n", rt.Config.Path)
	fmt.Fprintf(os.Stdout, "context: %s\n", rt.Context.Name)
	fmt.Fprintf(os.Stdout, "cache:   %s\n", rt.Cache.Dir())
	fmt.Fprintf(os.Stdout, "%s\n\n", strings.Repeat("─", 60))

	results := rt.Registry.HealthCheckAll(ctx, rt.adapterTimeout())

	healthy := 0
	for _, res := range results {
		if res.Err == nil {
			healthy++
			fmt.Fprintf(os.Stdout, "  ok    %-16s %s\n", res.Adapter, res.Elapsed.Round(1e6))
			continue
		}
		fmt.Fprintf(os.Stdout, "  FAIL  %-16s %s\n", res.Adapter, res.Err)
	}

	for _, err := range rt.PluginErrors {
		fmt.Fprintf(os.Stdout, "  warn  %-16s %s\n", "plugin", err)
	}

	fmt.Fprintf(os.Stdout, "\n%d of %d backends healthy.\n\n", healthy, len(results))

	if healthy == 0 {
		return fmt.Errorf("no backends are reachable")
	}
	return nil
}
