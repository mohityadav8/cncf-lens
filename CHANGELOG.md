# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.0.2]

### Added

- **Falco adapter.** Runtime security alerts are now a first-class backend,
  read either from falcosidekick over HTTP or from the JSON-lines file written
  by Falco's `file_output`. `lens audit` had no real security source before
  this, which made it largely hollow.
  - Priority mapping onto the lens severity scale, with a configurable noise
    floor that drops Debug and Informational alerts by default, since Falco is
    deliberately chatty at those levels.
  - Falco's `output_fields` are mapped onto the canonical Kubernetes identity
    labels, so a container-escape alert correlates against the metric spike and
    the deployment for the same pod.
  - A truncated final line, which happens when Falco is killed mid-write, is
    skipped rather than failing the whole read.
- **Shell completions** for bash, zsh and fish via `lens completion <shell>`.
  Bash completion offers live namespaces when `kubectl` is on `$PATH`.
- **`.gitattributes`** normalising line endings, which removes the CRLF warnings
  Windows contributors saw on checkout.
- **SECURITY.md** with a reporting process and an explicit threat model.
- **ROADMAP.md**, including what is deliberately not planned.
- This changelog.

### Changed

- Config validation accepts a backend configured with `file` instead of `url`
  or `endpoint`, which is what a file-backed Falco source needs.

## [v0.0.1]

Initial release.

### Added

- Correlation engine: timeline assembly with configurable tolerance, and
  explainable rule-based causal ranking over six weighted rules.
- Commands: `diagnose`, `trace`, `watch`, `audit`, `cost`, `doctor`, `init`.
- Backends: Kubernetes, Prometheus (also Thanos, Cortex, Mimir,
  VictoriaMetrics), Loki, Jaeger (also Tempo).
- Plugin protocol over subprocess JSON, with a working reference implementation.
- Output formats: ANSI terminal, versioned JSON, SARIF 2.1.0, Markdown.
- Zero external dependencies.

[v0.0.2]: https://github.com/mohityadav8/cncf-lens/releases/tag/v0.0.2
[v0.0.1]: https://github.com/mohityadav8/cncf-lens/releases/tag/v0.0.1