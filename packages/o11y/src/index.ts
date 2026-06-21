// @cocore/o11y — OpenTelemetry (traces + metrics + logs) for the cocore
// TypeScript services, exported to Honeycomb via OTLP. A no-op until
// OTEL_EXPORTER_OTLP_* is set. See tracing.ts for the design.

export {
  makeRuntime,
  record,
  runTraced,
  runTracedPromise,
  type O11yRuntime,
  type SpanAttributes,
} from "./runtime.ts";
export { logWarn } from "./log.ts";
export * as metrics from "./metrics.ts";
