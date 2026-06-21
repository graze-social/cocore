// Shared, cross-cutting metric instruments.
//
// Plain Effect `Metric`s. When a service runs effects through a runtime
// whose layer includes the OTLP `metricReader` (see tracing.ts), Effect
// exports them automatically; otherwise they accumulate in-process and are
// never read — a no-op cost.
//
// Record by piping an effect through `Metric.increment(...)` /
// `Metric.update(...)`. Tag dimensions (`outcome`, `direction`) must stay
// low-cardinality — never tag with a DID, URI, or anything per-request.

import { Metric } from "effect";

/** Receipts observed and indexed off the firehose. */
export const receiptsIndexed = Metric.counter("cocore.receipts.indexed", {
  description: "dev.cocore.compute.receipt records indexed",
});

/** Settlement attempts, tagged by outcome. Use `settlementOutcome(tag)`. */
const settlements = Metric.counter("cocore.settlements", {
  description: "settlement attempts by outcome",
});

/** Counter for settlement attempts tagged with a low-cardinality outcome
 *  (e.g. "settled", "rejected", "deferred"). */
export function settlementOutcome(outcome: string) {
  return settlements.pipe(Metric.tagged("outcome", outcome));
}

/** Tokens moved through the ledger, split by direction ("in" | "out"). */
const tokens = Metric.counter("cocore.tokens", {
  description: "tokens accounted, by direction",
  incremental: true,
});

/** Counter for tokens accounted, tagged by direction. */
export function tokenThroughput(direction: "in" | "out") {
  return tokens.pipe(Metric.tagged("direction", direction));
}
