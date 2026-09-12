// "Sign in with co/core" for applications: the requester side of device pairing.
//
// An app that wants to act on a user's co/core account (run inference billed
// to their credits) does not ask them to copy keys around. It starts a
// pairing, sends the user to co/core to approve "Connect <app> to co/core",
// and collects a key scoped to that user. The app is identified by a
// `dev.cocore.app.registration` record on its own account (`appDid`), and
// the user is returned to one of that record's `returnUrls` — provided the
// return host serves `/.well-known/cocore-app.json` naming the app's DID.
//
// Server-side only: the `deviceId` returned by `start` is the credential
// that collects the key, so it must never reach a browser.

export const DEFAULT_CONSOLE_URL = "https://cocore.dev";

export interface StartAppPairingInput {
  /** The application's DID; it must have published a registration record. */
  appDid: string;
  /** Name for the minted key, so the user can recognise and revoke it. */
  keyName?: string;
  /** Where the approve screen sends the browser afterwards. Must match one of
   *  the registration's `returnUrls` on origin + path. */
  returnUrl?: string;
  consoleUrl?: string;
  fetch?: typeof fetch;
}

export interface AppPairing {
  deviceId: string;
  userCode: string;
  verificationUri: string;
  pollIntervalSecs: number;
  expiresInSecs: number;
}

export interface PairedSession {
  did: string;
  handle: string;
  apiKey: string;
  apiBase: string;
}

export type AppPairingPoll =
  | { status: "pending" }
  | { status: "session"; session: PairedSession }
  | { status: "denied" | "expired" | "consumed" | "unknown" };

export class AppPairingError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "AppPairingError";
    this.status = status;
  }
}

async function readError(res: Response): Promise<string> {
  try {
    const b = (await res.json()) as { message?: string; error?: string };
    return b.message ?? b.error ?? `HTTP ${res.status}`;
  } catch {
    return `HTTP ${res.status}`;
  }
}

/** Begin a pairing. Send the user to `verificationUri`; keep `deviceId` on the server. */
export async function startAppPairing(input: StartAppPairingInput): Promise<AppPairing> {
  const f = input.fetch ?? fetch;
  const base = (input.consoleUrl ?? DEFAULT_CONSOLE_URL).replace(/\/$/, "");
  const res = await f(`${base}/api/xrpc/dev.cocore.devicePair.start`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      appDid: input.appDid,
      ...(input.keyName ? { keyName: input.keyName } : {}),
      ...(input.returnUrl ? { returnUrl: input.returnUrl } : {}),
    }),
  });
  if (!res.ok) throw new AppPairingError(res.status, await readError(res));
  return (await res.json()) as AppPairing;
}

/** One poll. `session` arrives exactly once; after that the attempt is `consumed`. */
export async function pollAppPairing(
  deviceId: string,
  opts: { consoleUrl?: string; fetch?: typeof fetch } = {},
): Promise<AppPairingPoll> {
  const f = opts.fetch ?? fetch;
  const base = (opts.consoleUrl ?? DEFAULT_CONSOLE_URL).replace(/\/$/, "");
  const res = await f(
    `${base}/api/xrpc/dev.cocore.devicePair.poll?deviceId=${encodeURIComponent(deviceId)}`,
  );
  const body = (await res.json().catch(() => ({}))) as { status?: string; session?: PairedSession };
  if (res.ok && body.status === "session" && body.session) {
    return { status: "session", session: body.session };
  }
  if (res.ok && body.status === "pending") return { status: "pending" };
  if (res.status === 403) return { status: "denied" };
  if (res.status === 404) return { status: "unknown" };
  if (res.status === 410) return { status: body.status === "consumed" ? "consumed" : "expired" };
  throw new AppPairingError(res.status, await readError(res));
}

/** Poll until the user acts or the attempt expires. Resolves with the session
 *  on approval; throws AppPairingError otherwise. */
export async function waitForAppPairing(
  pairing: Pick<AppPairing, "deviceId" | "pollIntervalSecs" | "expiresInSecs">,
  opts: { consoleUrl?: string; fetch?: typeof fetch; signal?: AbortSignal } = {},
): Promise<PairedSession> {
  const intervalMs = Math.max(1000, pairing.pollIntervalSecs * 1000);
  const deadline = Date.now() + pairing.expiresInSecs * 1000 + 5000;
  while (Date.now() < deadline) {
    if (opts.signal?.aborted) throw new AppPairingError(0, "aborted");
    const r = await pollAppPairing(pairing.deviceId, opts);
    if (r.status === "session") return r.session;
    if (r.status !== "pending") throw new AppPairingError(0, `pairing ${r.status}`);
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new AppPairingError(0, "pairing expired");
}
