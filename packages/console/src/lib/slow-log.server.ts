// Structured "this call was slow" logging, usable from anywhere on the server.
//
// Deliberately dependency-free. The main console runtime in `o11y.server.ts`
// is built over `AppviewClient.Default`, and `appview.server.ts` is where that
// service lives — so a slow-log helper hosted there could not be imported by
// the AppView client without a cycle (`appview.server` → `o11y.server` →
// `appview.server`), which resolves to `undefined` at module init rather than
// failing loudly. This module owns its own tiny telemetry runtime instead,
// the same way the appview package does for its fire-and-forget mirror.

import { logWarn, makeRuntime, record } from "@cocore/o11y";

/** Layer-free runtime: this module only ever emits logs, so it needs no
 *  application services. A no-op until OTLP is configured. */
const logRuntime = makeRuntime({
  serviceName: process.env["OTEL_SERVICE_NAME"] ?? "cocore-console",
  serviceVersion: process.env["COCORE_SOFTWARE_VERSION"],
});

/** Emit a structured warning from plain async code (no Effect context).
 *  `logWarn` returns an Effect, so callers outside one need a runtime to run
 *  it; this is that seam. */
export function warnFields(message: string, fields: Record<string, string | number | boolean>) {
  record(logRuntime, logWarn(message, fields));
}

/** A call slower than this almost certainly did real network work rather than
 *  hitting a warm path. Tunable without a deploy — set
 *  COCORE_SLOW_CALL_LOG_MS=0 to capture every call while chasing a latency
 *  problem, then remove the variable to restore the default. */
export function slowCallThresholdMs(): number {
  const raw = Number(process.env["COCORE_SLOW_CALL_LOG_MS"]);
  return Number.isFinite(raw) && raw >= 0 ? raw : 750;
}
