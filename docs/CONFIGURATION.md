# Configuration

Config lives at `~/.config/cncf-lens/config.yaml` by default. Override with `--config` or the `LENS_CONFIG` environment variable. Run `lens init` to generate a commented starter file.

A missing config is not an error: lens falls back to discovering the cluster from your kubeconfig, so it does something useful on a fresh machine.

## Full example

```yaml
defaults:
  context: local
  output: terminal          # terminal | json | sarif | markdown
  cache_ttl: 5m
  correlation_window: 500ms
  lookback: 15m
  adapter_timeout: 20s
  max_signals: 2000
  color: true

contexts:
  local:
    kubeconfig: ""          # empty means $KUBECONFIG or ~/.kube/config
    kubecontext: ""         # empty means current-context
    backends:
      kubernetes:
        enabled: true
      prometheus:
        enabled: true
        url: http://localhost:9090
        timeout: 20s
      loki:
        enabled: true
        url: http://localhost:3100
      jaeger:
        enabled: true
        url: http://localhost:16686

  production:
    kubecontext: prod-us-east-1
    backends:
      prometheus:
        enabled: true
        url: https://thanos.prod.internal
        token_env: THANOS_TOKEN
      loki:
        enabled: true
        url: https://loki.prod.internal
        token_env: LOKI_TOKEN
```

## Credentials

Three options, in order of preference:

```yaml
token_env: PROM_TOKEN                                    # read from the environment
token_file: /var/run/secrets/.../token                   # read from a file
token: "eyJhbG..."                                       # inline — discouraged
```

`token_env` and `token_file` mean the config file itself contains no secrets and can be committed. If `token_env` names a variable that is empty, lens fails immediately rather than letting you discover the problem as a 401 twenty seconds into an incident.

Values also expand `$VAR` and `${VAR}` anywhere a string is accepted.

## Backend type selection

The adapter is chosen by the prefix of the backend's config key, not by a `type` field. So a team running two metric backends writes:

```yaml
backends:
  prometheus:            # uses the Prometheus adapter
    url: http://localhost:9090
  prometheus-longterm:   # also uses the Prometheus adapter
    url: https://thanos.internal
```

Recognised prefixes: `kubernetes`, `prometheus`, `thanos`, `mimir`, `cortex`, `loki`, `jaeger`, `tempo`, `falco`. Any other key is assumed to belong to an external plugin, and its settings are passed through to that plugin verbatim.

## Falco

Falco has no query API of its own — it is a streaming detector that pushes alerts outward. lens reads them from wherever your cluster collects them, so there are two ways to configure it.

Through falcosidekick, the standard fan-out component:

```yaml
falco:
  enabled: true
  url: http://localhost:2801
```

Or straight from the JSON-lines file Falco's `file_output` writes:

```yaml
falco:
  enabled: true
  file: /var/log/falco/events.json
```

A backend configured with `file` needs no `url`. Alerts below warning priority are dropped by default, because Falco is deliberately chatty at Debug and Informational and an audit report drowning in noise gets ignored.

## Tunables worth understanding

**`correlation_window`** (default 500ms) is how close in time two signals must be to be considered simultaneous. Backends disagree about time — Prometheus timestamps at scrape time on a 15s interval, Kubernetes events carry second precision, Jaeger spans are nanosecond-accurate — and this window absorbs that. Tighten it on a quiet cluster to reduce false grouping; widen it if you see clearly related signals landing in separate buckets.

**`lookback`** (default 15m) is how far before an anomaly `lens diagnose` searches for causes. Widen it for slow-burning problems like a memory leak; narrow it for noisy clusters where 15 minutes returns too many candidates.

**`adapter_timeout`** (default 20s) bounds each backend independently. One slow backend cannot stall a command; it is reported as failed while the others still return.

**`max_signals`** (default 2000) caps how much each backend returns per fetch. Prometheus downsamples evenly across the window rather than truncating, so raising the limit gives you resolution, not just a longer tail.

## TLS

`insecure: true` disables certificate verification for one backend. It exists for self-signed development clusters. An observability tool that quietly accepts any certificate is a credential-theft vector, so leave it off in production and use a proper CA bundle instead.

## Kubernetes authentication

lens resolves the cluster the way kubectl does: an explicit `url` in config, then in-cluster service account credentials, then your kubeconfig.

Client-certificate and exec-plugin auth (`aws eks get-token`, `gke-gcloud-auth-plugin`, and similar) cannot be read directly, because supporting them would require a TLS-config-aware client and a credential-plugin runner. lens tells you this by name rather than failing with an opaque 401. The workaround is one of:

```sh
kubectl proxy                    # then set url: http://127.0.0.1:8001
```

or point the backend at a service account token via `token_env`.

## YAML support

The parser handles the subset a config file needs: nested maps by indentation, lists, scalars, quoted strings, and full-line or trailing comments. It deliberately rejects rather than silently mis-parses anchors, aliases, multi-document streams, block scalars and flow mappings.

Two behaviours worth knowing:

- Tabs are rejected with a clear message. YAML forbids them and a tab-indented file otherwise fails in confusing ways.
- Duplicate keys are an error, not a silent overwrite, so a typo surfaces instead of quietly taking effect.
- `url: https://host:9090` parses correctly. The key/value split requires a space after the colon, which is what keeps the port from being mistaken for a separator.
