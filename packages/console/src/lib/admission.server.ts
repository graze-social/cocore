// Admission floor for paid dispatch (co/core terms, "Admission floor").
//
// The exchange's ledger has always had `checkAdmission` (balance must cover
// the job's price ceiling AND leave `tokenFloor` headroom), and the terms
// promise that a job under the floor is refused — but nothing called it before
// dispatch, so balances could be pushed negative at settlement. This module is
// that call, inserted ahead of `runDispatch` for the paid routes (v1/chat,
// v1/private, v1/verified; pro bono is zero-price and skips it).
//
// Rollout is gated on `COCORE_ENFORCE_ADMISSION` (unset/"0" = observe only:
// the check runs, a refusal is LOGGED but the job still dispatches; "1"/"true"
// = refuse with HTTP 402). Fail-open on a ledger outage either way: an
// unreachable bridge is not "under the floor", and refusing every job because
// the ledger blinked would be an outage of our own making.
import { checkAdmission, type AdmissionResponse } from "@/lib/exchange-balance.server.ts";
import { jsonError } from "@/lib/openai-chat-completions.server.ts";

/** The OpenAI-style error `code` a refused requester sees. Clients (Graze's
 *  Feed Pulse among them) switch on it to park the account instead of retrying. */
export const INSUFFICIENT_CREDITS = "insufficient_credits";

export function admissionEnforced(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env["COCORE_ENFORCE_ADMISSION"] ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

export interface AdmissionDecision {
  /** null = dispatch; a Response = return it to the caller instead. */
  refusal: Response | null;
  /** The ledger's verdict, when it answered. */
  result: AdmissionResponse | null;
  /** Why we let the job through despite no `ok` (observe mode / ledger down). */
  note: string | null;
}

/** Decide whether `did` may dispatch a job priced up to `priceCeilingTokens`. */
export async function admit(
  did: string,
  priceCeilingTokens: number,
  opts: {
    enforce?: boolean;
    check?: (did: string, priceCeilingTokens: number) => Promise<AdmissionResponse>;
    log?: (line: string) => void;
  } = {},
): Promise<AdmissionDecision> {
  const enforce = opts.enforce ?? admissionEnforced();
  const check = opts.check ?? checkAdmission;
  const log = opts.log ?? ((line: string) => console.error(line));

  let result: AdmissionResponse;
  try {
    result = await check(did, priceCeilingTokens);
  } catch (e) {
    const note = `admission: ledger unreachable for ${did}, dispatching anyway (${(e as Error).message})`;
    log(note);
    return { refusal: null, result: null, note };
  }
  if (result.ok) return { refusal: null, result, note: null };

  const summary =
    `balance ${result.balance.toLocaleString("en-US")} CC, ` +
    `needs ${result.required.toLocaleString("en-US")} CC ` +
    `(price ceiling ${priceCeilingTokens.toLocaleString("en-US")} + admission floor), ` +
    `short by ${result.shortBy.toLocaleString("en-US")}`;
  if (!enforce) {
    const note = `admission: would refuse ${did} — ${summary} (COCORE_ENFORCE_ADMISSION off)`;
    log(note);
    return { refusal: null, result, note };
  }
  log(`admission: refused ${did} — ${summary}`);
  return {
    refusal: jsonError(
      402,
      `Not enough co/core credits: ${summary}. Credits refresh weekly, and serving on your own Mac earns more.`,
      "insufficient_credits_error",
      INSUFFICIENT_CREDITS,
    ),
    result,
    note: null,
  };
}
