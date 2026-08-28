# Contributing

## Getting set up

```sh
git clone https://github.com/cncf-lens/lens
cd lens
make all      # fmt, vet, test, build
```

Go 1.22 or later is the only requirement.

## The dependency rule

`cncf-lens` imports nothing outside the Go standard library, and pull requests that add a dependency will be asked to justify it against that.

This is not purism. The tool reads production credentials and runs against production clusters, so a dependency-free supply chain is a feature we sell. If you need functionality that seems to demand a library, first check whether a few hundred lines of standard library code would do — that is how `internal/cli`, `internal/config/yaml.go` and `internal/render` came to exist.

## Adding a backend

You have two options.

**An external plugin** is the right choice for anything not in wide use across the ecosystem. It ships and versions independently of lens, can be written in any language, and needs no changes here at all. See [docs/PLUGINS.md](docs/PLUGINS.md).

**A compiled-in adapter** makes sense for backends most users will have. Implement `adapter.Adapter` in a new package under `internal/adapter/`, then register it in `internal/command/runtime.go`. Four things matter:

- Populate the canonical identity labels from `internal/signal`. Correlation is driven by label overlap, so an adapter that emits its own label names contributes nothing joinable.
- Return a superset rather than an error when you cannot honour a filter. The engine filters again downstream; over-fetching is safe, silently losing evidence is not.
- Respect context cancellation. One slow backend must never stall a command.
- Write actionable errors. `403 forbidden — the token is valid but lacks permission for this query` saves an on-call engineer minutes that `unexpected status 403` does not.

Test against `httptest.Server` with a canned response, as `internal/adapter/prometheus/prometheus_test.go` does. That exercises the real HTTP path and JSON decoding rather than stubbing them.

## Changing the correlation engine

`internal/correlate` is the part most likely to be subtly wrong, so it has the densest tests. Two invariants are load-bearing and have named regression tests:

- Buckets anchor to the bucket start, never the previous signal. Anchoring to the previous signal lets a dense log stream chain-link into one unbounded bucket. See `TestAssembleDoesNotChainLink`.
- A cause must strictly precede its anomaly. See `TestDiagnoseRanksDeploymentHighest`.

If you add a scoring rule, add it to the `rules` slice with a weight and a human-readable explanation string. Every rule must be able to explain itself; a rule that only produces a number does not belong here.

## Before opening a pull request

```sh
make fmt vet test-race
```

Please include a test that fails without your change. Two of the bugs fixed during initial development were caught by tests written before the fix, which is the standard we would like to hold.
