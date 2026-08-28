# Architecture

```
   lens diagnose | trace | watch | audit | cost | doctor | init
                            │
                            ▼
              ┌─────────────────────────────┐
              │     correlation engine      │
              │  router → timeline → causal │
              │        + context cache      │
              └─────────────────────────────┘
                            │
        ┌───────────┬───────┴───────┬───────────┐
        ▼           ▼               ▼           ▼
   kubernetes   prometheus        loki       jaeger      lens-plugin-*
   (REST API)   (HTTP v1)      (LogQL)    (query API)   (subprocess)
```

Three layers, each replaceable without touching the others.

## Layer 1 — CLI

`internal/cli` is a small subcommand framework over the standard library's `flag` package: grouped help, per-command flags, Levenshtein typo suggestions, and consistent exit codes (`0` success, `1` failure, `2` usage error, `130` interrupted). Scripts wrapping lens rely on that distinction between 1 and 2.

`internal/command` owns the wiring. `Setup` loads config, builds the adapter registry, opens the cache and constructs the renderer. Every command shares the same global flags from one struct, so `--namespace` never means something different in one command than another.

## Layer 2 — Correlation engine

### The Signal type

Everything the system handles is a `signal.Signal`: a timestamp, a type, a severity, a source, a title, a detail, identity labels, and optionally a numeric value, a trace ID and a duration. Metrics, spans, log lines, Kubernetes events and Falco alerts all normalise into it.

The `Labels` map is the join key. Adapters are required to populate canonical Kubernetes identity keys (`namespace`, `pod`, `service`, `container`, `node`, `workload`, `cluster`) because relatedness is scored primarily by label overlap. An adapter that emits its own label names produces signals that never join to anything.

### Timeline assembly

`correlate.Assemble` sweeps time-sorted signals into buckets. A signal joins the current bucket if it falls within the tolerance of the bucket's **start**, not of the previous signal.

That distinction is the single most important line in the package. Anchoring to the previous signal lets a dense log stream chain-link: each line is within 500ms of the last, so twenty lines spanning six seconds collapse into one bucket, and the notion of "simultaneous" becomes meaningless. `TestAssembleDoesNotChainLink` guards it.

The default 500ms tolerance comes from how much backends disagree about time. Prometheus timestamps samples at scrape time on a 15s interval, Kubernetes events carry second precision, Jaeger spans are nanosecond-accurate, and container clocks drift. Tighter splits genuinely co-occurring events; much wider starts merging unrelated activity.

`Timeline.Interesting()` then filters to buckets that are either cross-source or contain at least a warning. On a production cluster a five-minute window holds tens of thousands of log lines, and showing all of them is the same as showing none.

### Causal ranking

`correlate.Diagnose` searches backwards from an anomaly and scores candidates against six weighted rules:

| Rule | Weight | Rationale |
|---|---|---|
| change-vector | 0.30 | Deployments and config changes are the overwhelming majority of real Kubernetes root causes. |
| identity-overlap | 0.25 | Shared namespace/pod/workload labels mean the two signals describe the same thing. |
| tight-precedence | 0.20 | Within two minutes: long enough for a rollout to propagate, short enough to be causal. |
| trace-linked | 0.15 | A shared trace ID is a direct causal link, not a correlation. |
| historical-cooccurrence | 0.20 | Has this kind of cause preceded this kind of anomaly on this cluster before. |
| severity | 0.10 | A cause that was itself logged as an error deserves a second look. |

Scores are normalised to 0–1 and bucketed into `likely` / `possible` / `weak`, because a bare `0.62` invites precision the heuristics have not earned.

Two constraints do most of the work. **Strict precedence** — a cause must occur before its anomaly — eliminates most spurious correlations a naive "what else was happening" query would surface. And **every rule returns an explanation string**, which is printed under the hypothesis. An unexplained ranking is useless to someone on call at 3am; they need to be able to disagree with the tool.

There is no machine learning here, deliberately. Rule-based scoring is good enough for the large majority of incidents, runs in microseconds, needs no training data, and can explain itself.

### Historical learning

The `historical-cooccurrence` rule reads from a local counter store. After each `diagnose` run, causes that scored are recorded as co-occurring and every other preceding signal increments only the denominator. Without that second half every cause would show a 100% ratio and the rule would fire on everything.

The rule requires a sample of at least three and a ratio above 0.5 before it contributes. Two out of two looks like a perfect correlation and means nothing.

## Layer 3 — Adapters

The `adapter.Adapter` interface is four methods: `Name`, `Capabilities`, `Fetch`, `HealthCheck`. `Capabilities` lets the registry skip backends that cannot contribute to a query — asking only for traces never wakes a metrics-only backend.

### Fan-out

`Registry.FetchAll` queries every eligible adapter concurrently, each in its own goroutine with its own derived context and timeout, with panic recovery. It returns one `Result` per adapter carrying either signals or an error.

It deliberately does not fail fast. During an incident a partially degraded observability stack is normal, and an engineer needs whatever evidence is still reachable. Errors travel alongside data, never instead of it, and the renderer states clearly which backends did not answer so a partial answer is never mistaken for a complete one.

### Plugins

External plugins are `lens-plugin-*` executables on `$PATH` speaking JSON over stdin/stdout. See [PLUGINS.md](PLUGINS.md). They cross a process boundary, so a plugin that panics, hangs or returns garbage is recorded as a failed backend and nothing more.

## Cross-cutting

**`internal/cache`** is a file-backed JSON store, not a database. Keys are SHA-256 hashed into filenames so a PromQL expression containing slashes is safe on disk, writes are atomic via rename so a concurrent process never sees truncated JSON, and files are mode 0600. A corrupt entry degrades to a cache miss rather than failing the command.

**`internal/render`** has a terminal renderer using raw ANSI codes with the colour conventions users expect (`NO_COLOR`, `TERM=dumb`, and non-TTY output all disable it), plus JSON with a versioned schema, SARIF 2.1.0 for security dashboards, and Markdown shaped like a postmortem.

**`internal/config`** includes a YAML subset parser. The key/value split requires a space after the colon, which is what keeps `url: https://host:9090` from splitting at the port. Tabs and duplicate keys are rejected loudly rather than mis-parsed.

## Why zero dependencies

Every design decision above was constrained by importing nothing outside the standard library. That cost us cobra, a YAML library, bubbletea and client-go, and bought:

- A single static binary with nothing to install.
- Nothing to audit in a supply chain review, which matters for a tool that reads production credentials.
- No `client-go`, which alone would pull roughly 200 transitive modules for the two API endpoints lens uses.

The replacements are each a few hundred lines and live in `internal/cli`, `internal/config/yaml.go` and `internal/render`.
