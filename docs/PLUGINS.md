# Plugin protocol

Any executable on your `$PATH` named `lens-plugin-<name>` becomes a lens backend. The protocol is three subcommands exchanging JSON over stdin and stdout.

## Why subprocesses

Go's `plugin` package requires the host and the plugin to be built with the identical toolchain and identical dependency versions. That is unworkable for a community ecosystem where plugins ship on their own schedule.

Subprocesses let a plugin be written in Rust, Python, or a shell script, and version independently of lens. Terraform, containerd and CNI all made the same trade for the same reason.

## Discovery

At startup lens scans `$PATH` for executables prefixed `lens-plugin-`, runs `describe` on each, and registers the ones that answer correctly. A plugin that fails its handshake is reported as a warning and skipped — one broken plugin must never stop an engineer from running lens during an outage.

## `describe`

Called with no stdin. Write to stdout:

```json
{
  "name": "example",
  "version": "0.1.0",
  "protocol_version": 1,
  "capabilities": ["event", "security"],
  "description": "Reference plugin demonstrating the lens protocol"
}
```

`protocol_version` must equal the version this lens build speaks, currently `1`. A mismatch is refused rather than misparsed.

`capabilities` is any subset of `metric`, `trace`, `log`, `event`, `security`, `deploy`. Declare only what you can actually produce: lens skips adapters whose capabilities cannot satisfy a query, which saves you a round trip.

`name` is what appears in output, in `--only` and `--skip`, and as the `source` on every signal you emit.

## `health`

Called with no stdin. Verify your backend is reachable and write any JSON object to stdout. To report a problem, write a message to stderr and exit non-zero — lens surfaces it in `lens doctor`.

## `fetch`

Receives a request on stdin:

```json
{
  "protocol_version": 1,
  "from": "2026-03-14T15:00:00Z",
  "to": "2026-03-14T15:15:00Z",
  "namespace": "payments",
  "workload": "checkout",
  "pod": "checkout-7d4b9c5f8-x2k9p",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "expr": "",
  "types": ["security"],
  "limit": 2000,
  "settings": {"region": "eu-west-1"}
}
```

Every field except `protocol_version`, `from` and `to` is optional and should be treated as a hint. If you cannot honour a filter, return a superset — lens filters again downstream, so over-fetching is safe while under-fetching silently loses evidence.

`settings` carries any keys from your backend's config block that lens does not recognise, passed through verbatim. This is how a plugin gets configured without lens knowing its schema:

```yaml
contexts:
  prod:
    backends:
      example:              # matches lens-plugin-example
        url: https://api.internal
        region: eu-west-1   # arrives in settings
        tenant: acme        # arrives in settings
```

Write to stdout:

```json
{
  "signals": [
    {
      "timestamp": "2026-03-14T15:09:26Z",
      "type": "security",
      "severity": "warning",
      "title": "Privileged container detected",
      "detail": "Container runs with privileged: true, granting host-level access",
      "labels": {
        "namespace": "payments",
        "pod": "legacy-agent-x7f2k",
        "container": "agent"
      },
      "trace_id": "",
      "value": null,
      "duration_ms": 0
    }
  ],
  "warnings": ["only the last hour was searchable"]
}
```

To report a failure, return `{"error": "upstream API returned 503"}`. Warnings are shown to the user without failing the fetch.

## Signal fields

| Field | Notes |
|---|---|
| `timestamp` | RFC 3339. **Required** — a signal with no timestamp cannot be correlated and is dropped. |
| `type` | One of the capability values. An unrecognised type is coerced to `event`. |
| `severity` | `debug`, `info`, `warning`, `error`, `critical`. Unrecognised values become `info`. |
| `title` | Short summary, shown in timelines. |
| `detail` | Full payload — the log line, the message body. |
| `labels` | See below. This is what makes your signal joinable. |
| `value` | Numeric value, for metric signals only. |
| `trace_id` | The strongest correlation key there is. Populate it whenever you know it. |
| `duration_ms` | Milliseconds, for signals that span time. Not a Go duration string — the wire format has to work from every language. |

## Labels are the whole point

Correlation is driven primarily by label overlap. Use these exact keys:

`cluster`, `namespace`, `service`, `workload`, `pod`, `container`, `node`

A plugin that invents its own label names will emit signals that never join to anything from Prometheus, Loki or Kubernetes, which defeats the purpose of integrating at all. Map your backend's native names onto these before returning.

## Reference implementation

[`examples/plugin-example`](../examples/plugin-example) is a complete, working plugin in about 130 lines of Go. It is compiled and run against the real protocol by `TestReferencePluginConformsToProtocol`, so if it ever stops being correct, our test suite fails.

```sh
make plugin
sudo mv bin/lens-plugin-example /usr/local/bin/
lens doctor       # the plugin now appears in the backend list
```

## Guarantees

The wire format is a public contract. Fields will be added over time; existing fields will not be removed or retyped without bumping `protocol_version`.

Your plugin runs as a subprocess with the parent environment plus `LENS_PROTOCOL_VERSION`. It gets a 30 second timeout for `fetch`, 10 for `health`, 5 for `describe`. If your plugin panics or hangs, lens records the failure and continues with the other backends.
