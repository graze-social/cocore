// Structured logging that flows to OTel logs when enabled.
//
// Effect's logging (`Effect.logInfo`, `Effect.logError`, ...) is bridged
// to OTel log records by the NodeSdk layer's `logRecordProcessor` (see
// tracing.ts), so any log emitted inside a traced effect automatically
// carries `trace_id`/`span_id` for correlation. When OTLP is disabled the
// logs still render through Effect's default logger.
//
// These are thin wrappers that take a message plus low-cardinality,
// content-safe annotations (IDs/DIDs/counts/durations — never prompt or
// output bytes, secrets, or API keys). Prefer these over `console.*` in
// migrated code.

import { Effect } from "effect";

export type LogFields = Record<string, string | number | boolean | undefined>;

function annotate<A, E, R>(effect: Effect.Effect<A, E, R>, fields?: LogFields) {
  if (!fields) return effect;
  // `Effect.annotateLogs` takes a record directly; drop undefined values so
  // optional fields don't show up as `undefined` annotations.
  const clean: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined) clean[k] = v;
  }
  return Effect.annotateLogs(effect, clean);
}

export function logWarn(message: string, fields?: LogFields): Effect.Effect<void> {
  return annotate(Effect.logWarning(message), fields);
}
