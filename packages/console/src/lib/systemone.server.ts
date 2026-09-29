// System-One (`/v1/systemone`) request/response handling.
//
// The wire format TypeSafe's Jev defines and that every open decision-model
// server speaks — `ollaya serve`, `laya serve`, Unsloth Desktop. A caller
// points an existing Jev client at cocore by changing one base URL:
//
//   TYPESAFE_BASE_URL=https://cocore.dev
//
// and their `state` + typed `questions` are dispatched to a provider running
// a System-One model, answered in one encoder pass, and receipted like any
// other job.
//
// This module is deliberately pure — parsing, validation, canonicalization,
// and response shaping, no auth and no network — so the whole contract is
// unit-testable. The request handler that wires it to `runDispatch` lives in
// `openai-routes.server.ts` alongside its chat-completions siblings, so
// authentication stays in one place.
//
// ## Why validation happens twice
//
// `provider/src/engines/decision.rs` validates the same things again before
// it will publish a receipt. That is not redundancy: the console's copy
// turns a malformed request into a 422 the caller can fix, while the
// provider's copy is what stops a misbehaving *server* from producing a
// signed receipt for a malformed decision. Neither can stand in for the
// other — they defend against different parties.

import type { DispatchErrorCode } from "@/lib/inference-dispatch.server.ts";
import { dispatchErrorToHttpResponse } from "@/lib/openai-chat-completions.server.ts";

/** Documented System-One limits (docs.typesafe.ai/api). */
const MAX_CHOICE_OPTIONS = 255;
const MIN_SCORE_LEVELS = 2;
const MAX_SCORE_LEVELS = 10;

/** Model ids every Jev client hardcodes, resolved to whichever System-One
 *  model is actually on the network. `jev-latest` is the SDK default and
 *  `laya` is what the local servers call it; neither is a repo id. */
export const DECISION_MODEL_ALIASES = ["jev-latest", "jev", "laya", "laya:multilingual"];

/** The System-One models published as open weights today, in the order we
 *  prefer them when a caller asks for an alias. Multilingual leads because it
 *  is the default in the local servers and has the longer context (1024 vs
 *  512). Extend without a release via `COCORE_DECISION_MODELS`.
 *
 *  This list exists only because nothing in the provider Register frame
 *  distinguishes a decision model from a chat model yet — once it does, the
 *  advisor knows, and this becomes a fallback rather than the source. */
const BUILTIN_DECISION_MODELS = [
  "convaiinnovations/laya-multilingual",
  "convaiinnovations/laya",
  "convaiinnovations/laya-typed-decisions",
];

export function knownDecisionModels(): string[] {
  const extra = (process.env["COCORE_DECISION_MODELS"] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return [...new Set([...extra, ...BUILTIN_DECISION_MODELS])];
}

export type QuestionType = "noul" | "choice" | "score";

export interface ParsedQuestion {
  type: QuestionType;
  /** Option keys for a `choice`, used to validate the answer. */
  options?: string[];
}

export interface ParsedSystemOneRequest {
  /** What the caller asked for, before alias resolution. */
  requestedModel: string;
  questions: Record<string, ParsedQuestion>;
  /** Canonical `{model, state, questions}` bytes — what gets sealed, and so
   *  what `inputCommitment` covers. Model is filled in after resolution. */
  state: unknown;
  rawQuestions: Record<string, unknown>;
}

export interface SystemOneError {
  status: number;
  message: string;
  code: string;
}

/** A validation failure. 422 is what the System-One API documents for a
 *  malformed request (not 400), and what its SDKs surface as a validation
 *  error rather than a retryable fault. */
function invalid(message: string): SystemOneError {
  return { status: 422, message, code: "validation_error" };
}

/**
 * Parse and validate a System-One request body.
 *
 * Returns the parsed request or a ready-to-send error. Every message names
 * the field at fault, because the caller's next move is to fix their request
 * and a generic "invalid body" costs them a round of guessing.
 */
export function parseSystemOneRequest(raw: unknown): ParsedSystemOneRequest | SystemOneError {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return invalid("Body must be a JSON object with `state` and `questions`.");
  }
  const body = raw as Record<string, unknown>;

  const model = body["model"];
  if (model !== undefined && typeof model !== "string") {
    return invalid("`model` must be a string.");
  }

  if (!("state" in body)) {
    return invalid("`state` is required: the situation the questions are asked about.");
  }
  const state = body["state"];
  if (state === null || state === undefined) {
    return invalid("`state` must not be null.");
  }
  if (typeof state === "string" && state.trim() === "") {
    return invalid("`state` must not be empty.");
  }

  const rawQuestions = body["questions"];
  if (typeof rawQuestions !== "object" || rawQuestions === null || Array.isArray(rawQuestions)) {
    return invalid("`questions` is required and must be an object of question id → question.");
  }
  const entries = Object.entries(rawQuestions as Record<string, unknown>);
  if (entries.length === 0) {
    return invalid("`questions` must contain at least one question.");
  }

  const questions: Record<string, ParsedQuestion> = {};
  for (const [id, q] of entries) {
    const parsed = parseQuestion(id, q);
    if ("status" in parsed) return parsed;
    questions[id] = parsed;
  }

  return {
    requestedModel: typeof model === "string" ? model : "jev-latest",
    questions,
    state,
    rawQuestions: rawQuestions as Record<string, unknown>,
  };
}

function parseQuestion(id: string, q: unknown): ParsedQuestion | SystemOneError {
  if (typeof q !== "object" || q === null || Array.isArray(q)) {
    return invalid(`Question ${JSON.stringify(id)} must be an object.`);
  }
  const obj = q as Record<string, unknown>;
  const type = obj["type"];
  if (type !== "noul" && type !== "choice" && type !== "score") {
    return invalid(
      `Question ${JSON.stringify(id)} has type ${JSON.stringify(type)}; expected "noul", "choice", or "score".`,
    );
  }
  const instructions = obj["instructions"];
  if (instructions === undefined || instructions === null) {
    return invalid(`Question ${JSON.stringify(id)} is missing \`instructions\`.`);
  }
  if (typeof instructions === "string" && instructions.trim() === "") {
    return invalid(`Question ${JSON.stringify(id)} has empty \`instructions\`.`);
  }

  const criteria = obj["criteria"];
  if (type === "choice") {
    if (typeof criteria !== "object" || criteria === null || Array.isArray(criteria)) {
      return invalid(
        `Choice question ${JSON.stringify(id)} needs \`criteria\` as an object of option → description.`,
      );
    }
    const options = Object.keys(criteria as Record<string, unknown>);
    if (options.length === 0) {
      return invalid(`Choice question ${JSON.stringify(id)} has no options in \`criteria\`.`);
    }
    if (options.length > MAX_CHOICE_OPTIONS) {
      return invalid(
        `Choice question ${JSON.stringify(id)} has ${options.length} options; the limit is ${MAX_CHOICE_OPTIONS}.`,
      );
    }
    return { type, options };
  }
  if (type === "score") {
    if (!Array.isArray(criteria)) {
      return invalid(
        `Score question ${JSON.stringify(id)} needs \`criteria\` as an ordered array of level descriptions.`,
      );
    }
    if (criteria.length < MIN_SCORE_LEVELS || criteria.length > MAX_SCORE_LEVELS) {
      return invalid(
        `Score question ${JSON.stringify(id)} has ${criteria.length} levels; the range is ${MIN_SCORE_LEVELS}–${MAX_SCORE_LEVELS}.`,
      );
    }
    return { type };
  }
  return { type };
}

/**
 * Resolve the model a caller named to one that is actually on the network.
 *
 * A Jev client sends `jev-latest` and a local-server user sends `laya` —
 * neither is a repo id, so both are resolved against the known System-One
 * set, preferring the order in {@link knownDecisionModels}. A caller who
 * names a concrete repo id gets it verbatim (they may be running something
 * we don't know about, and refusing would be worse than routing and letting
 * the dispatch layer report "no provider serves it").
 */
export function resolveDecisionModel(
  requested: string,
  onlineModels: readonly string[],
): string | SystemOneError {
  if (!DECISION_MODEL_ALIASES.includes(requested)) return requested;

  const known = knownDecisionModels();
  const online = new Set(onlineModels);
  const match = known.find((m) => online.has(m));
  if (match) return match;

  return {
    status: 404,
    code: "model_not_found",
    message:
      `No provider is currently serving a System-One decision model, so \`${requested}\` ` +
      `cannot be resolved. Known decision models: ${known.join(", ")}. ` +
      `Name a concrete model id to route to one directly.`,
  };
}

/**
 * The exact bytes sealed for the provider — and therefore what
 * `inputCommitment` covers.
 *
 * Keys are sorted recursively so the same logical request always produces the
 * same commitment no matter how the caller's JSON serializer ordered its
 * object keys. Arrays keep their order: a score question's `criteria` levels
 * are ordered, and reordering them would change the question.
 */
export function canonicalDecisionPrompt(
  parsed: ParsedSystemOneRequest,
  resolvedModel: string,
): string {
  return canonicalJson({
    model: resolvedModel,
    state: parsed.state,
    questions: parsed.rawQuestions,
  });
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value !== "object" || value === null) return value;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(value as Record<string, unknown>).sort()) {
    out[k] = sortKeys((value as Record<string, unknown>)[k]);
  }
  return out;
}

export interface DecisionAnswers {
  model: string;
  answers: Record<string, unknown>;
  inputTokens: number;
  outputTokens: number;
}

/**
 * Parse what the provider returned.
 *
 * The engine emits a canonical `{model, answers, usage}` envelope, already
 * validated against the questions asked. We re-check that every question is
 * answered because the thing on the other end is a provider, not a library:
 * an answer set that doesn't match the questions is a failed job, not a 200.
 */
export function parseDecisionCompletion(
  text: string,
  questions: Record<string, ParsedQuestion>,
  fallbackModel: string,
): DecisionAnswers | SystemOneError {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      status: 502,
      code: "malformed_decision",
      message: "The provider returned something that is not a decision. Please retry.",
    };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return {
      status: 502,
      code: "malformed_decision",
      message: "The provider's decision was not a JSON object. Please retry.",
    };
  }
  const obj = parsed as Record<string, unknown>;
  const answers = obj["answers"];
  if (typeof answers !== "object" || answers === null || Array.isArray(answers)) {
    return {
      status: 502,
      code: "malformed_decision",
      message: "The provider's decision carried no `answers`. Please retry.",
    };
  }
  const answerMap = answers as Record<string, unknown>;
  for (const id of Object.keys(questions)) {
    if (!(id in answerMap)) {
      return {
        status: 502,
        code: "malformed_decision",
        message: `The provider did not answer question ${JSON.stringify(id)}. Please retry.`,
      };
    }
  }

  const usage = obj["usage"] as Record<string, unknown> | undefined;
  return {
    model: typeof obj["model"] === "string" ? obj["model"] : fallbackModel,
    answers: answerMap,
    inputTokens: typeof usage?.["input_tokens"] === "number" ? usage["input_tokens"] : 0,
    // A System-One model is non-autoregressive: it generates no tokens, so
    // this is 0 for an honest provider and carried through rather than
    // inferred.
    outputTokens: typeof usage?.["output_tokens"] === "number" ? usage["output_tokens"] : 0,
  };
}

/**
 * Map a dispatch failure to a System-One status.
 *
 * Mostly the chat mapping, with one deliberate difference: capacity-shaped
 * failures answer **529**, which is the status the System-One API documents
 * for "overloaded" and the one its SDKs retry with exponential backoff. A 503
 * would be equally true and would not be retried by a Jev client, so the
 * caller would see a hard failure where the network just wanted a moment.
 */
export function dispatchErrorToSystemOneResponse(code: DispatchErrorCode): {
  status: number;
  code: string;
} {
  const mapped = dispatchErrorToHttpResponse(code);
  switch (code) {
    case "no-providers-connected":
    case "no-providers-for-country":
    case "no-providers-for-version":
    case "no-friends-available":
    case "target-provider-not-connected":
    case "no-capacity":
      return { status: 529, code: mapped.code };
    default:
      return { status: mapped.status, code: mapped.code };
  }
}

/** System-One error envelope. Same shape as the chat surface's so a caller
 *  hitting both sees one error contract; the status is what Jev clients
 *  switch on. */
export function systemOneError(err: SystemOneError): Response {
  return new Response(
    JSON.stringify({
      error: { message: err.message, type: "invalid_request_error", code: err.code, param: null },
    }),
    { status: err.status, headers: { "content-type": "application/json" } },
  );
}

/** The 200 body: `{ model, answers, usage }` per the System-One API, plus
 *  cocore's `x_cocore` block naming who ran it and where the receipt is. */
export function systemOneResponse(
  result: DecisionAnswers,
  extra: Record<string, unknown> | undefined,
): Response {
  return new Response(
    JSON.stringify({
      model: result.model,
      answers: result.answers,
      usage: { input_tokens: result.inputTokens, output_tokens: result.outputTokens },
      ...extra,
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}
