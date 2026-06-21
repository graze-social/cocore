# @cocore/o11y

The one place OpenTelemetry is configured for the cocore TypeScript services
(appview, infra/services, advisor, console). Traces, metrics, and logs are
exported over OTLP/HTTP. The Rust provider mirrors the same env contract with a
native OTLP layer (see `provider/src/diagnostics.rs`).

## No-op by default

Telemetry is a **hard no-op until `OTEL_EXPORTER_OTLP_ENDPOINT` is set**. With no
OTLP env configured, no exporter is constructed, `Effect.withSpan` degrades to
the default no-op tracer, and metrics/logs stay in-process. Local dev and CI
behave exactly as they did before o11y — no credentials are ever committed.

## Environment variables

These are the **standard OTLP env vars** read by the OTel SDKs themselves, so any
OTLP backend works. Set them on every deployed process (each appview / services /
advisor / console instance, and the Rust provider).

| Var                                  | Required                | Notes                                                              |
| ------------------------------------ | ----------------------- | ------------------------------------------------------------------ |
| `OTEL_EXPORTER_OTLP_ENDPOINT`        | **yes** (turns o11y on) | Base URL; the SDK appends `/v1/traces`, `/v1/metrics`, `/v1/logs`. |
| `OTEL_EXPORTER_OTLP_HEADERS`         | for authed backends     | Comma-separated `key=value` pairs (e.g. an ingest key).            |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | no                      | Override the traces endpoint only.                                 |
| `OTEL_SERVICE_NAME`                  | no                      | Overrides the per-service name baked into code.                    |
| `OTEL_SERVICE_VERSION`               | no                      | Tag a build/release.                                               |

Do **not** set `OTEL_EXPORTER_OTLP_PROTOCOL=grpc` — the exporters are OTLP/HTTP
(protobuf) on both the TS (`exporter-*-otlp-http`) and Rust (`http-proto`) sides.

Service names are baked in per process (`cocore-appview`, `cocore-services`,
`cocore-advisor`, console, and the provider's own name), so each appears as its
own service/dataset without configuration.

## Honeycomb

Honeycomb is OTLP-native — there is no Honeycomb-specific code here. Minimum:

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io       # or https://api.eu1.honeycomb.io
OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=YOUR_INGEST_KEY
```

The ingest key is all you need — **no `x-honeycomb-dataset` header.** An Ingest
key is scoped to a single Honeycomb **environment**, and Honeycomb routes by
that environment automatically: traces and logs land in per-`service.name`
datasets (`cocore-services`, `cocore-appview`, …) and metrics land in the
environment's own auto-managed `metrics` dataset. On Environments & Services
teams `x-honeycomb-dataset` does **not** rename the metrics dataset (verified
empirically — the header is sent but ignored), so we don't set it. The way to
keep prod and dev telemetry apart is **one Honeycomb environment per deploy
environment**, each with its own ingest key (see below) — not dataset names.

Get the ingest key from Honeycomb → Environment settings → API Keys → create an
**Ingest** key. Store it as a deploy secret; never commit it.

### One Honeycomb environment per deploy environment

Mirror the Railway environments (`production`, `dev`) with a Honeycomb
environment of the same name, and put that environment's Ingest key in the
matching Railway environment's `OTEL_EXPORTER_OTLP_HEADERS`. PR/preview
environments are intentionally left uninstrumented (no key → hard no-op).

| Railway env   | Honeycomb env | Where the key goes                                                       |
| ------------- | ------------- | ------------------------------------------------------------------------ |
| `production`  | `production`  | `OTEL_EXPORTER_OTLP_HEADERS` on the prod AppView/Advisor/Client services |
| `dev`         | `dev`         | same, on the dev services                                                |
| `cocore-pr-*` | —             | unset (telemetry stays off)                                              |

## Privacy invariant

Spans/metrics/logs carry IDs, DIDs, sizes, hashes, counts, and durations —
**never** prompt/output bytes, plaintext, secrets, or API keys. This mirrors the
Rust agent's deliberately content-free tracing.
