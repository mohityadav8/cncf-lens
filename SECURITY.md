# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.0.x | Yes |

This project is pre-1.0. Only the latest release receives fixes.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on
https://github.com/mohityadav8/cncf-lens

Include the version, the affected component, reproduction steps, and what an
attacker could achieve. You should get an acknowledgement within 72 hours and
an assessment within 7 days. If a fix is warranted it will ship in the next
patch release, and you will be credited in the release notes unless you ask
otherwise.

## Threat model

`cncf-lens` runs on an operator's workstation or in CI. It reads credentials
for production observability backends and queries them. It never writes to any
backend, and it exposes no listening port.

Things that follow from that:

- **Credentials.** Tokens are read from environment variables or files named in
  the config and are held in memory only. They are never logged, never written
  to the cache, and never included in `--output=json` or SARIF output. Inline
  `token:` in a config file is supported but discouraged for this reason.
- **The cache** lives under the user cache directory with mode 0600 and holds
  correlation history and topology, not credentials. Cache keys are SHA-256
  hashed before becoming filenames, so a crafted PromQL expression cannot
  traverse out of the cache directory.
- **TLS** is verified by default. `insecure: true` exists for self-signed
  development clusters and disables verification for that one backend.
- **Plugins** are subprocesses inheriting the parent environment, which means a
  plugin can read every variable lens can. Treat installing a `lens-plugin-*`
  binary with the same care as installing any other executable on `$PATH`.
- **Backend responses** are capped at 64 MiB and decoded into typed structs, so
  a compromised or hostile backend cannot exhaust memory on the workstation.

## Dependencies

`cncf-lens` imports nothing outside the Go standard library. There is no
third-party dependency tree to audit or to patch, which is a deliberate part of
the security posture for a tool that handles production credentials.
