// Device-pair HTTP handlers.
//
// When COCORE_APPVIEW_INTERNAL_URL is set, these forward to the AppView,
// which owns the pair-store:
//   * start/poll → the AppView's public XRPC endpoints (agent-facing).
//   * confirm    → the AppView's public, service-auth'd confirm. The
//     console mints a service-auth JWT from the signed-in user's OAuth
//     session (com.atproto.server.getServiceAuth) so the AppView can
//     verify the approver's DID and mint the scoped key itself.
//
// Without the env they fall back to the console's in-process pair-store
// (legacy), so a deploy without it behaves exactly as before.

import type { Did } from "@atcute/lexicons";
import { Effect, Either } from "effect";

import { runTraced } from "@/lib/o11y.server.ts";
import { getAtprotoSessionForRequest } from "@/middleware/auth.server.ts";
import { PairError, sharedStore } from "./pair-store.ts";
import {
  providerSessionForDidEffect,
  type ProviderSessionWire,
} from "./provider-session-from-oauth.server.ts";

function json(body: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
}

function appviewBase(): string | null {
  return process.env["COCORE_APPVIEW_INTERNAL_URL"]?.replace(/\/$/, "") || null;
}

/** Re-wrap an AppView response as a JSON Response to return verbatim. */
async function passthrough(r: Response): Promise<Response> {
  return new Response(await r.text(), {
    status: r.status,
    headers: { "content-type": "application/json" },
  });
}

export async function devicePairStartResponse(): Promise<Response> {
  const base = appviewBase();
  if (base) {
    return passthrough(await fetch(`${base}/xrpc/dev.cocore.devicePair.start`, { method: "POST" }));
  }
  const r = sharedStore().start();
  return json(
    {
      deviceId: r.deviceId,
      userCode: r.userCode,
      verificationUri: r.verificationUri,
      pollIntervalSecs: r.pollIntervalSecs,
      expiresInSecs: r.expiresInSecs,
    },
    200,
  );
}

/** `search` is `url.search` (e.g. `?deviceId=...`). */
export async function devicePairPollResponse(search: string): Promise<Response> {
  const base = appviewBase();
  if (base) {
    const qs = search.startsWith("?") ? search : `?${search}`;
    return passthrough(await fetch(`${base}/xrpc/dev.cocore.devicePair.poll${qs}`));
  }
  const deviceId = new URLSearchParams(search).get("deviceId");
  if (!deviceId) return json({ error: "missing deviceId" }, 400);
  const r = sharedStore().poll(deviceId);
  switch (r.kind) {
    case "unknown":
      return json({ status: "unknown" }, 404);
    case "pending":
      return json({ status: "pending" }, 200);
    case "denied":
      return json({ status: "denied" }, 403);
    case "expired":
      return json({ status: "expired" }, 410);
    case "consumed":
      return json({ status: "consumed" }, 410);
    case "session":
      return json({ status: "session", session: r.session }, 200);
  }
}

interface ConfirmBody {
  userCode: string;
  decision: "approve" | "deny";
}

export async function devicePairConfirmResponse(request: Request): Promise<Response> {
  const base = appviewBase();
  const appviewDid = process.env["COCORE_APPVIEW_DID"];
  if (base && appviewDid) {
    const auth = await getAtprotoSessionForRequest(request);
    if (!auth) return json({ error: "not authenticated" }, 401);

    let body: ConfirmBody;
    try {
      body = (await request.json()) as ConfirmBody;
    } catch {
      return json({ error: "bad json" }, 400);
    }

    let providerSession: ProviderSessionWire | null = null;
    if (body.decision === "approve") {
      providerSession = await runTraced(
        "devicePair.mintSession",
        providerSessionForDidEffect(auth.did as Did),
      );
      if (!providerSession) return json({ error: "could not mint provider session" }, 500);
    }

    // Mint a service-auth JWT bound to this method so the AppView can
    // verify the approver's DID without the console asserting it.
    let token: string;
    try {
      const r = await auth.oauthSession.handle(
        `/xrpc/com.atproto.server.getServiceAuth?aud=${encodeURIComponent(appviewDid)}&lxm=dev.cocore.devicePair.confirm`,
        { method: "GET" },
      );
      if (!r.ok) return json({ error: `getServiceAuth returned ${r.status}` }, 502);
      token = ((await r.json()) as { token: string }).token;
    } catch (e) {
      return json({ error: `service-auth mint failed: ${(e as Error).message}` }, 502);
    }

    // M6: authenticate the pre-minted `providerSession` we're forwarding with
    // the shared internal secret. The AppView honors a caller-supplied session
    // (apiKey/apiBase) ONLY behind this secret; without it the AppView ignores
    // our session and mints its own — so a public confirm can't inject an
    // attacker key/endpoint. When the secret is unset we still forward, but the
    // AppView will (correctly) mint server-side.
    const internalSecret = process.env["COCORE_INTERNAL_SECRET"];
    return passthrough(
      await fetch(`${base}/xrpc/dev.cocore.devicePair.confirm`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
          ...(internalSecret ? { "x-cocore-internal-secret": internalSecret } : {}),
        },
        body: JSON.stringify({
          userCode: body.userCode,
          decision: body.decision,
          ...(providerSession ? { providerSession } : {}),
        }),
      }),
    );
  }
  return runTraced("devicePair.confirmLocal", devicePairConfirmLocalEffect(request));
}

function requestJsonEffect<T>(request: Request): Effect.Effect<T, unknown> {
  return Effect.async((resume) => {
    void (request.json() as Promise<T>).then(
      (v) => resume(Effect.succeed(v)),
      (e) => resume(Effect.fail(e)),
    );
  });
}

const devicePairConfirmLocalEffect = (request: Request): Effect.Effect<Response> =>
  Effect.gen(function* () {
    const parsed = yield* Effect.either(requestJsonEffect<ConfirmBody>(request));
    if (Either.isLeft(parsed)) return json({ error: "bad json" }, 400);
    const body = parsed.right;

    const code = (body.userCode ?? "").trim().toUpperCase();
    if (!code) return json({ error: "missing userCode" }, 400);
    const store = sharedStore();

    if (body.decision === "deny") {
      const denied = yield* Effect.either(
        Effect.try({ try: () => store.deny(code), catch: (e) => e }),
      );
      if (Either.isLeft(denied)) return json({ error: "unknown code" }, 404);
      return json({ ok: true, status: "denied" }, 200);
    }

    if (body.decision !== "approve") {
      return json({ error: "decision must be approve|deny" }, 400);
    }

    // Derive the scoped ProviderSession server-side from the signed-in
    // user's OAuth session (mirrors the AppView path, which mints it from
    // the verified service-auth DID).
    const auth = yield* Effect.promise(() => getAtprotoSessionForRequest(request));
    if (!auth) return json({ error: "not authenticated" }, 401);
    const session = yield* providerSessionForDidEffect(auth.did as Did);
    if (!session) return json({ error: "could not mint provider session" }, 500);

    const approved = yield* Effect.either(
      Effect.try({ try: () => store.approve(code, session), catch: (e) => e }),
    );
    if (Either.isLeft(approved)) {
      const e = approved.left;
      if (e instanceof PairError) return json({ error: e.message }, 409);
      return json({ error: e instanceof Error ? e.message : String(e) }, 409);
    }
    return json({ ok: true, status: approved.right.status }, 200);
  });
