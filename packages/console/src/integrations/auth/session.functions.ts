import type { Did } from "@atcute/lexicons";
import { mutationOptions, queryOptions } from "@tanstack/react-query";
import { createServerFn } from "@tanstack/react-start";
import { getRequest, setCookie } from "@tanstack/react-start/server";
import { Effect, Either } from "effect";

import { revokeAppSession } from "@/integrations/auth/app-session-store.server.ts";
import { AUTH_SESSION_TOKEN_COOKIE } from "@/integrations/auth/constants.ts";
import { authCookieDomain } from "@/integrations/auth/cookie-domain.ts";
import { readAuthSessionToken } from "@/integrations/auth/cookie-parse.ts";
import { ensureMyProfile } from "@/lib/account-profile.server.ts";
import { deriveChatStorageKey } from "@/lib/chat-storage-key.server.ts";
import { fetchBlueskyPublicProfileFieldsEffect } from "@/lib/bluesky-public-profile.server.ts";
import {
  type ProviderSessionWire,
  providerSessionForDidEffect,
} from "@/lib/provider-session-from-oauth.server.ts";
import { atprotoSessionForRequestEffect } from "@/middleware/auth.server.ts";

const getSessionServerFn = createServerFn({ method: "GET" }).handler(() =>
  Effect.runPromise(
    Effect.gen(function* () {
      const request = getRequest();
      const ctx = yield* atprotoSessionForRequestEffect(request);
      if (!ctx) return null;

      // Prefer the user's cocore profile over their bsky profile so
      // edits made in /account (display name, uploaded avatar blob)
      // surface everywhere the session is consumed — the navbar, etc.
      // `ensureMyProfile` is the source of truth: it provisions from
      // bsky on first sign-in, then preserves cocore-side overrides
      // forever. Wrap in `Either` so a profile-fetch failure (e.g.
      // legacy token missing the profile scope) falls back to the
      // bsky public profile instead of breaking the whole session.
      const cocoreEither = yield* Effect.either(
        Effect.tryPromise(() => ensureMyProfile(ctx.oauthSession)),
      );
      const cocore = Either.isRight(cocoreEither) ? cocoreEither.right : null;
      const bsky = yield* fetchBlueskyPublicProfileFieldsEffect(ctx.did);

      const displayName = cocore?.displayName ?? bsky?.displayName?.trim() ?? null;
      const handle = cocore?.handle ?? bsky?.handle?.trim() ?? null;
      const image = cocore?.avatarUrl ?? bsky?.avatarUrl ?? null;
      const name = displayName || handle || ctx.did;

      return {
        user: {
          did: ctx.did,
          name,
          handle,
          image,
        },
        chatStorageKey: deriveChatStorageKey(ctx.did),
      };
    }),
  ),
);

export const getSessionQueryOptions = queryOptions({
  queryKey: ["session"] as const,
  queryFn: getSessionServerFn,
  staleTime: 60_000,
});

// Sign out clears the cookie + drops the app-session row, but
// deliberately does NOT call revokeAtprotoSessionEffect. The OAuth
// session in oauth_sessions is referenced by any API keys the user
// has minted, which need to keep working across browser logouts. To
// revoke OAuth credentials at the auth server, the user can revoke
// each API key (and we can add a "Sign out everywhere" affordance
// later that clears the oauth_sessions row + revokes all keys).
const signOutServerFn = createServerFn({ method: "POST" }).handler(() =>
  Effect.runPromise(
    Effect.sync(() => {
      const request = getRequest();
      const token = readAuthSessionToken(request.headers.get("cookie"));
      if (token) {
        revokeAppSession(token);
      }

      const isHttps = request.url.startsWith("https://");
      // Must match the Domain used when the cookie was set (oauth-callback),
      // or the browser won't clear the .cocore.dev-scoped cookie on sign-out.
      const cookieDomain = authCookieDomain(new URL(request.url).host);
      setCookie(AUTH_SESSION_TOKEN_COOKIE, "", {
        path: "/",
        httpOnly: true,
        sameSite: "lax",
        maxAge: 0,
        ...(isHttps ? { secure: true } : {}),
        ...(cookieDomain ? { domain: cookieDomain } : {}),
      });

      return { success: true } as const;
    }),
  ),
);

export const signOutMutationOptions = mutationOptions({
  mutationFn: () => signOutServerFn(),
});

// Used by /devices/new — converts the cookie's OAuth session into the
// JSON-serializable ProviderSession shape that
// `dev.cocore.devicePair.confirm` expects. Returns null if the user
// is not signed in.
const getProviderSessionForPairingServerFn = createServerFn({ method: "GET" }).handler(
  (): Promise<ProviderSessionWire | null> =>
    Effect.runPromise(
      Effect.gen(function* () {
        const request = getRequest();
        const ctx = yield* atprotoSessionForRequestEffect(request);
        if (!ctx) return null;
        return yield* providerSessionForDidEffect(ctx.did as Did);
      }),
    ),
);

export const getProviderSessionForPairingQueryOptions = queryOptions({
  queryKey: ["session", "provider-for-pairing"] as const,
  queryFn: getProviderSessionForPairingServerFn,
  // Always refetch — the access token rotates on use; we want the
  // freshest one stamped into the agent's session.json.
  staleTime: 0,
  gcTime: 0,
});
