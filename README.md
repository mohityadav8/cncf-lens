<p align="center">
  <img src="assets/logo.svg" width="300" alt="cncf-lens logo"/>
</p>

<h1 align="center">cncf-lens</h1>

<p align="center">
  A single CLI that correlates Kubernetes, Prometheus, Loki and Jaeger onto one timeline.
</p>

<p align="center">
  <a href="https://github.com/mohityadav8/cncf-lens/actions"><img src="https://github.com/mohityadav8/cncf-lens/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"/></a>
  <img src="https://img.shields.io/badge/go-1.22+-00ADD8.svg" alt="Go version"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen.svg" alt="Zero dependencies"/>
</p>

---

## The problem

A pod starts failing. You run `kubectl describe`, open Grafana for the metric, switch to Jaeger for the slow trace, grep Loki for the log line, then check Falco. Five tools, five browser tabs, and nothing lines them up in time.

`cncf-lens` queries every backend concurrently and assembles one time-correlated view, so you can see the deployment, the latency spike it caused, and the resulting error logs together.

```
$ lens diagnose --namespace=payments --since=30m

Root cause analysis
───────────────────
anomaly: [!!] Request latency p99 = 3.240
         15:09:26.184 UTC from prometheus
         3.24s  pod=checkout-7d4b9c5f8-x2k9p  ns=payments

1. likely    ScalingReplicaSet: checkout-7d4b9c5f8
   15:07:56  1m30s before the anomaly · score 0.75 · via kubernetes
   Scaled up replica set checkout-7d4b9c5f8 from 3 to 6
   + is a deployment or config change — the most common root cause class
   + shares 2 Kubernetes identity label(s) with the anomaly
   + occurred 1m30s before the anomaly

2. possible  connection pool exhausted
   15:08:41  45s before the anomaly · score 0.45 · via loki
   + shares 2 Kubernetes identity label(s) with the anomaly
   + was itself logged at error severity
```

---

## Install

Requires Go 1.22 or later. There are no other dependencies.

```sh
git clone https://github.com/mohityadav8/cncf-lens
cd cncf-lens
make install          # builds and installs to $GOPATH/bin
```

Or build without installing:

```sh
make build            # produces ./bin/lens
```

---

## Quickstart

```sh
lens init             # writes a commented config file
lens doctor           # checks every backend is reachable
lens diagnose --namespace=default --since=30m
```

If your observability stack runs in-cluster, port-forward it first:

```sh
kubectl -n monitoring port-forward svc/prometheus 9090:9090 &
kubectl -n monitoring port-forward svc/loki 3100:3100 &
kubectl -n monitoring port-forward svc/jaeger-query 16686:16686 &
```

---

## Commands

| Command | What it does |
|---|---|
| `lens diagnose` | Finds the most severe anomaly in a window, then searches backwards for what caused it. Each hypothesis is printed with its supporting evidence. |
| `lens trace` | Follows one request across spans, logs, metrics and events, rendered as a waterfall. |
| `lens watch` | Streams newly seen signals from every backend as one merged live feed. |
| `lens audit` | Collects security findings and policy violations. Emits SARIF for GitHub Advanced Security. |
| `lens cost` | Estimates spend from peak observed CPU and memory per workload. |
| `lens doctor` | Reports which backends are reachable and why the others are not. |
| `lens init` | Generates a starter config. |

Run `lens help <command>` for the full flag list.

---

## How correlation works

Every backend adapter normalises its data into a common `Signal` type carrying a timestamp, a severity, and canonical Kubernetes identity labels. Correlation then happens in three stages:

**Timeline assembly** groups signals that occurred within a tolerance window (500ms by default) into buckets. The tolerance exists because backends disagree about time: Prometheus timestamps at scrape time on a 15s interval, Kubernetes events carry second precision, and Jaeger spans are nanosecond-accurate. A bucket touched by more than one backend is flagged, because independent sources agreeing is the cheapest reliable indicator of a real event.

**Causal ranking** searches backwards from an anomaly and scores each candidate against six weighted rules — is it a deployment, does it share identity labels, how tightly did it precede, was it itself severe, does it share a trace ID, and has it preceded this kind of anomaly before on this cluster. Every score is printed with the evidence that produced it, because an unexplained ranking is useless to someone on call at 3am.

**Trace joining** is the strongest link available. When your services propagate trace context into their logs, lens matches log lines to spans exactly rather than by proximity. Where they do not, it falls back to time plus label overlap.

The engine deliberately uses no machine learning. Rule-based scoring is good enough for the large majority of real incidents and, unlike a model score, an engineer can disagree with it.

---

## Backends

Compiled in: Kubernetes, Prometheus (also Thanos, Cortex, Mimir, VictoriaMetrics), Loki, Jaeger (also Tempo).

Anything else integrates through the plugin protocol. A plugin is any executable named `lens-plugin-*` on your `$PATH` that answers three subcommands over stdin/stdout JSON. It can be written in any language. See [docs/PLUGINS.md](docs/PLUGINS.md) and the working reference implementation in [examples/plugin-example](examples/plugin-example).

---

## Zero dependencies

`cncf-lens` imports nothing outside the Go standard library. That is unusual for a tool in this space and it was a deliberate trade:

- One static binary, no runtime, no container needed.
- Nothing to audit in a supply chain review — relevant for a tool that reads production credentials.
- No `client-go`, which alone would pull in roughly 200 transitive modules for the two API endpoints lens actually uses.

The cost is that lens implements its own CLI framework, a small YAML subset parser, and an ANSI renderer. Those are in `internal/cli`, `internal/config/yaml.go` and `internal/render`, and they are each a few hundred lines.

---

## Output formats

```sh
lens diagnose --output=json      # versioned schema for piping into other tools
lens diagnose --output=markdown  # postmortem-shaped report
lens audit --output=sarif        # GitHub Advanced Security, GitLab, most dashboards
```

`lens audit --fail-on=error` exits non-zero, which makes it usable as a CI gate.

---

## Development

```sh
make test             # full suite
make vet lint fmt     # static checks
make build
```

---

## Status

This is a working v0.1. The correlation engine, all four backend adapters, the plugin protocol and every command are implemented and tested. What it does not yet have: gRPC transports (Jaeger and OTel are reached over HTTP), client-certificate kubeconfig auth (use `kubectl proxy` or a service account token), and a full-screen TUI for `lens watch` — it currently streams line by line.

---

## Licence

Apache 2.0. See [LICENSE](LICENSE).
