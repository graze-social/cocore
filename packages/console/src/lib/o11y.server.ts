// Console-side observability boundary.
//
// One telemetry runtime for the whole console server process. Server fns,
// middleware, and route handlers run their effects through `runTraced`,
// which wraps each operation in a root span and (when OTLP is configured)
// exports traces + metrics + logs to Honeycomb. A no-op until
// OTEL_EXPORTER_OTLP_* is set — see @cocore/o11y.
//
// This is `.server.ts` so the runtime (and the OTel SDK it pulls in)
// never reaches the client bundle.

import {
  logWarn,
  makeRuntime,
  record,
  runTraced as runTracedWith,
  type SpanAttributes,
} from "@cocore/o11y";
import type { Effect } from "effect";

import { AppviewClient } from "@/integrations/appview/appview.server.ts";

/** The console's application services, provided by the single runtime. New
 *  Effect services (PDS write, OAuth store, …) get merged in here. */
const AppLayer = AppviewClient.Default;

/** Requirements the runtime satisfies — the union of `AppLayer`'s services.
 *  Effects passed to {@link runTraced} may require any subset of these. */
type AppEnv = AppviewClient;

const runtime = makeRuntime(
  {
    serviceName: process.env["OTEL_SERVICE_NAME"] ?? "cocore-console",
    serviceVersion: process.env["COCORE_SOFTWARE_VERSION"],
  },
  AppLayer,
);

// Don't let one stray promise take the site down. Node's default for an
// unhandled rejection is to kill the process, so a single unguarded `await`
// anywhere in the server — in our code or a dependency's — turns into a
// site-wide outage plus a crash loop. The advisor and the services process
// have had this guard since their first deploy (infra/advisor/src/main.ts,
// infra/services/src/main.ts); the console never got one, and on 2026-08-11 a
// mid-body fetch abort in appview.server.ts crash-looped cocore.dev for it.
//
// Log loudly and keep serving: a genuinely wedged process is caught by the
// Railway healthcheck, and the console is a read-mostly cache over the PDS —
// staying up degraded beats a restart loop that 500s every request in flight.
// This module hosts it because it's server-only and every server I/O path
// imports it, so the handler is installed once, early, without a custom entry.
//
// Registered under a symbol so a double module-eval (dev HMR, or the same
// module loaded through two specifiers) doesn't stack duplicate listeners and
// trip Node's MaxListenersExceededWarning.
const GUARDS_INSTALLED = Symbol.for("cocore.console.processGuards");

if (typeof process !== "undefined" && !(GUARDS_INSTALLED in globalThis)) {
  Object.defineProperty(globalThis, GUARDS_INSTALLED, { value: true });
  process.on("unhandledRejection", (reason) => {
    const e = reason instanceof Error ? reason : new Error(String(reason));
    console.error(`console: unhandledRejection — ${e.message}\n${e.stack ?? ""}`);
  });
  process.on("uncaughtException", (e) => {
    console.error(`console: uncaughtException — ${e.message}\n${e.stack ?? ""}`);
  });
}

/** Run a server-side effect wrapped in a root span named for the
 *  operation. Drop-in replacement for `Effect.runPromise(effect)`; the
 *  effect may require any service the runtime provides ({@link AppEnv}). */
export function runTraced<A, E>(
  name: string,
  effect: Effect.Effect<A, E, AppEnv>,
  attributes?: SpanAttributes,
): Promise<A> {
  return runTracedWith(runtime, name, effect, attributes);
}

/** Emit a structured warning from plain async code (no Effect context).
 *  `logWarn` returns an Effect, so callers outside an effect need the
 *  runtime to run it; this is that seam. */
export function warnFields(message: string, fields: Record<string, string | number | boolean>) {
  record(runtime, logWarn(message, fields));
}

/** A call slower than this almost certainly did real network work rather
 *  than hitting a warm path. Tunable without a deploy so the threshold can
 *  be dropped to 0 to capture every call while chasing a latency problem. */
export function slowCallThresholdMs(): number {
  const raw = Number(process.env["COCORE_SLOW_CALL_LOG_MS"]);
  return Number.isFinite(raw) && raw >= 0 ? raw : 750;
}
