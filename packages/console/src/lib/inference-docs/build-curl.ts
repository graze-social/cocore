import type { InferenceApiCatalogEntry } from "./catalog.ts";

export function resolveInferenceApiBody(
  entry: InferenceApiCatalogEntry,
  values: Record<string, string>,
): Record<string, unknown> | undefined {
  if (entry.method !== "POST") return undefined;
  const base = entry.example.body ?? {};
  const model = values.model?.trim() || String((base.model as string | undefined) ?? "stub");

  // A decision request has no `messages` and no `max_tokens` — the chat
  // assembly below would rewrite it into something the endpoint rejects.
  if (entry.id === "inference-api-systemone") {
    const baseQuestions = (base.questions ?? {}) as Record<string, { instructions?: string }>;
    const [firstId, firstQuestion] = Object.entries(baseQuestions)[0] ?? ["is_urgent", {}];
    const state = values.state?.trim() || String((base.state as string | undefined) ?? "");
    const statement = values.statement?.trim() || String(firstQuestion.instructions ?? "");
    return {
      ...base,
      model,
      state,
      questions: { [firstId]: { type: "noul", instructions: statement } },
    };
  }

  const message =
    values.message?.trim() ||
    String(
      ((base.messages as Array<{ content?: string }> | undefined)?.[0]?.content as
        | string
        | undefined) ?? "Hello",
    );
  const maxTokensRaw = values.max_tokens?.trim();
  const max_tokens = maxTokensRaw ? Number.parseInt(maxTokensRaw, 10) : (base.max_tokens as number);
  return {
    ...base,
    model,
    messages: [{ role: "user", content: message }],
    max_tokens: Number.isFinite(max_tokens) ? max_tokens : 256,
  };
}

export function resolveInferenceApiQuery(
  entry: InferenceApiCatalogEntry,
  values: Record<string, string>,
): Record<string, string> {
  const query = { ...entry.example.query };
  if (entry.id === "inference-api-models") {
    const view = values.view?.trim();
    if (view && view !== "default") query.view = view;
    else delete query.view;
  }
  return query;
}

export function buildInferenceApiCurl(
  entry: InferenceApiCatalogEntry,
  baseUrl: string,
  values: Record<string, string>,
  options?: { apiKeyPlaceholder?: boolean },
): string {
  const url = new URL(`${baseUrl.replace(/\/$/, "")}${entry.path}`);
  for (const [key, value] of Object.entries(resolveInferenceApiQuery(entry, values))) {
    if (value) url.searchParams.set(key, value);
  }
  const authFlag =
    entry.auth === "required" || options?.apiKeyPlaceholder
      ? " -H 'Authorization: Bearer $COCORE_API_KEY'"
      : "";
  if (entry.method === "GET") {
    return `curl -sS${authFlag} '${url.toString()}'`;
  }
  const body = resolveInferenceApiBody(entry, values) ?? {};
  const json = JSON.stringify(body);
  return `curl -sS -X POST${authFlag} '${url.toString()}' -H 'Content-Type: application/json' -d '${json}'`;
}

export function buildInferenceApiRequest(
  entry: InferenceApiCatalogEntry,
  baseUrl: string,
  values: Record<string, string>,
  apiKey?: string,
): { url: string; init: RequestInit } {
  const url = new URL(`${baseUrl.replace(/\/$/, "")}${entry.path}`);
  for (const [key, value] of Object.entries(resolveInferenceApiQuery(entry, values))) {
    if (value) url.searchParams.set(key, value);
  }
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (entry.auth === "required" && apiKey) {
    headers.Authorization = `Bearer ${apiKey}`;
  }
  if (entry.method === "POST") {
    headers["Content-Type"] = "application/json";
    return {
      url: url.toString(),
      init: {
        method: "POST",
        headers,
        body: JSON.stringify(resolveInferenceApiBody(entry, values)),
      },
    };
  }
  return { url: url.toString(), init: { method: "GET", headers } };
}
