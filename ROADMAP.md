# Roadmap

Ordered by how much each item unblocks real use, not by how interesting it is
to build. Nothing here has a date attached.

## v0.1 — usable against a real production cluster

The gaps that currently force a workaround.

- **gRPC transport for Jaeger and OTLP.** Both are reached over HTTP today.
  Many production deployments expose only gRPC, so trace correlation is
  unavailable on those clusters.
- **Client-certificate and exec-plugin kubeconfig auth.** `aws eks get-token`,
  `gke-gcloud-auth-plugin` and cert-based auth all fail today, and lens tells
  the user to run `kubectl proxy` instead. That is a workaround, not support.
- **`lens init` cluster auto-discovery.** It should scan for well-known service
  names (`prometheus-operated`, `loki`, `jaeger-query`, `falcosidekick`) and
  write a working config, rather than emitting a template to fill in by hand.
- **ownerReferences traversal.** `workloadFromPod` strips hash suffixes
  heuristically. Following ownerReferences from pod to ReplicaSet to Deployment
  is authoritative and handles custom controllers correctly.

## v0.2 — the interface people actually want

- **Full-screen TUI for `lens watch`.** Split panes: events, metric sparklines,
  log tail, security alerts, all correlated. Clicking a log line with a trace ID
  focuses the other panes on that moment.
- **Argo CD and Flux adapter.** GitOps events carry the commit SHA. Correlating
  a latency spike to an exact commit is the single highest-value addition for
  teams already running GitOps.
- **`lens diff`.** Compare two time windows side by side. "What is different
  between last Tuesday and right now."
- **Multi-cluster queries.** Config already models several contexts but only one
  is queried at a time. A trace crossing two clusters cannot currently be
  assembled.

## v0.3 — breadth

- OpenTelemetry metrics over OTLP, alongside Prometheus.
- Prometheus alerting rules read directly, instead of recomputing from raw series.
- Kyverno and Gatekeeper policy adapters.
- Loki structured metadata, which newer versions attach to streams.
- A `lens-plugin-*` registry so plugins are discoverable rather than word of mouth.

## Explicitly not planned

- **A cluster-side component.** No operator, no CRDs, no agent. lens stays a
  client-side binary that uses APIs you already expose. This is the main reason
  it is adoptable in an afternoon.
- **Machine-learned root cause scoring.** The rule engine is worse in the tail
  and much better where it counts: it runs in microseconds, needs no training
  data, works on day one in a new cluster, and can explain itself. An
  unexplainable ranking is not useful at 3am.
- **Third-party dependencies**, unless something genuinely cannot be built
  against the standard library. See CONTRIBUTING.md.
- **Writing to backends.** lens reads. A debugging tool that can mutate
  production is a different risk category.

## Contributing to the roadmap

Open an issue describing the problem you hit rather than the feature you want.
The Falco adapter exists because `lens audit` was obviously hollow without a
real security backend, and that was easier to see from the complaint than from
the proposal.