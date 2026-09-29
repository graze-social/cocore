#!/usr/bin/env node --experimental-strip-types
//
// Verify a decision receipt by re-running the decision yourself.
//
//   node --experimental-strip-types scripts/verify-decision.ts \
//     at://did:plc:…/dev.cocore.compute.receipt/abc \
//     --request ./the-request-i-sent.json \
//     --server http://127.0.0.1:11435
//
// What this proves, and what it doesn't:
//
//   * The job really commits to the request you pass in — so the provider was
//     asked what you think it was asked.
//   * Re-running the decision on YOUR OWN model server reproduces the exact
//     bytes the provider signed. An autoregressive completion can never offer
//     this; a System-One decision is deterministic, so it can.
//   * With --digest, that the artifact you ran is the one the receipt named.
//
// It does NOT prove confidentiality. A decision is served by an out-of-process
// engine, so the machine operator could read your state. Nothing here changes
// that.
//
// The point of `--server` being yours: re-running against the provider that
// issued the receipt proves nothing at all.

import { readFileSync } from "node:fs";

import {
  systemOneRunner,
  verifyDecisionReceipt,
  type DecisionRequest,
} from "../packages/sdk/src/decision.ts";
import { resolveRecordOverPds } from "../packages/sdk/src/resolve.ts";
import type { JobRecord, ReceiptRecord } from "../packages/sdk/src/types.ts";

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? undefined : process.argv[i + 1];
}

function usage(message: string): never {
  console.error(`error: ${message}

usage: verify-decision <receipt-at-uri> --request <file.json> [options]

  --request <file>   The { state, questions } you sent. Required — you are the
                     only party who has it, which is what makes this checkable
                     without anyone's cooperation.
  --server <url>     YOUR OWN System-One server to re-run against (e.g.
                     http://127.0.0.1:11435 for \`ollaya serve\`). Without it,
                     only the input commitment is checked.
  --digest <sha256>  SHA-256 of the weights you ran, compared with the
                     artifact the receipt claims.
  --key <token>      Bearer token, if your server wants one.`);
  process.exit(2);
}

const receiptUri = process.argv[2];
if (!receiptUri || receiptUri.startsWith("--")) usage("a receipt at:// URI is required");

const requestPath = flag("request");
if (!requestPath) usage("--request <file.json> is required");

let request: DecisionRequest;
try {
  request = JSON.parse(readFileSync(requestPath, "utf-8")) as DecisionRequest;
} catch (e) {
  usage(`could not read ${requestPath}: ${(e as Error).message}`);
}
if (!request.state || !request.questions) {
  usage(`${requestPath} must be a JSON object with "state" and "questions"`);
}

const receiptRecord = await resolveRecordOverPds(receiptUri);
if (!receiptRecord) {
  console.error(`error: no receipt found at ${receiptUri}`);
  process.exit(1);
}
const receipt = receiptRecord.value as ReceiptRecord;

// The receipt strong-refs its job; fetch it from the requester's own repo so
// the input commitment being checked is the one that was published, not one
// the provider hands us.
const jobRecord = await resolveRecordOverPds(receipt.job.uri);
if (!jobRecord) {
  console.error(`error: the job this receipt references is unreachable: ${receipt.job.uri}`);
  process.exit(1);
}
const job = jobRecord.value as JobRecord;

const server = flag("server");
const report = await verifyDecisionReceipt({
  receipt,
  job,
  request,
  ...(server ? { runner: systemOneRunner(server, flag("key")) } : {}),
  ...(flag("digest") ? { ranDigest: flag("digest")! } : {}),
});

console.log(`receipt   ${receiptUri}`);
console.log(`model     ${receipt.model}`);
console.log(`artifact  ${report.claimedDigest ?? "(the receipt names none)"}`);
console.log(`replayed  ${report.replayed ? "yes" : "no — output NOT verified"}`);
if (report.recomputedOutputCommitment) {
  console.log(`committed ${receipt.outputCommitment}`);
  console.log(`recomputed ${report.recomputedOutputCommitment}`);
}
for (const f of report.findings) {
  console.log(`${f.severity === "error" ? "FAIL" : "warn"}  [${f.code}] ${f.message}`);
}

if (!report.ok) {
  console.log("\nNOT VERIFIED");
  process.exit(1);
}
if (!report.replayed) {
  // Deliberately not "verified": the input commitment matching only says the
  // provider was asked the right question, not that it answered honestly.
  console.log("\nINPUT VERIFIED — pass --server to check the answer itself");
  process.exit(0);
}
console.log("\nVERIFIED — this provider ran the decision it signed for");
