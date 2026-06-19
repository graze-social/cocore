import { Effect, Either } from "effect";

import { ensureMyProfile } from "@/lib/account-profile.server.ts";
import { issueAppSession } from "@/integrations/auth/app-session-store.server.ts";
import { atprotoOAuthCallbackEffect } from "@/integrations/auth/atproto.server.ts";
import { AUTH_SESSION_TOKEN_COOKIE } from "@/integrations/auth/constants.ts";
import { authCookieDomain } from "@/integrations/auth/cookie-domain.ts";
import { fetchBlueskyPublicProfileFieldsEffect } from "@/lib/bluesky-public-profile.server.ts";
import { sanitizeAuthRedirectTarget } from "@/utils/auth-redirect.ts";

/** Success path only; failures become `Either.Left`. */
function oauthCallbackResponseEffect(request: Request): Effect.Effect<Response, unknown> {
  return Effect.gen(function* () {
    const callbackUrl = new URL(request.url);
    const callbackError = callbackUrl.searchParams.get("error");
    if (callbackError) {
      yield* Effect.sync(() => {
        console.warn("OAuth callback error param:", callbackError);
      });
    }

    const { session: oauthSession, state } = yield* atprotoOAuthCallbackEffect(
      callbackUrl.searchParams,
    );

    const did = oauthSession.did;
    const stateData = state as
      | { redirect?: string; returnTo?: string; handle?: string }
      | undefined;
    const requestedReturnTo = stateData?.redirect ?? stateData?.returnTo;
    const returnTo = sanitizeAuthRedirectTarget(requestedReturnTo, request.url);
    const publicProfile = yield* fetchBlueskyPublicProfileFieldsEffect(did);
    const handle = stateData?.handle || publicProfile?.handle || "";
    // Best-effort: provision the user's `dev.cocore.account.profile`
    // record from their bsky public profile so /account renders
    // something on first visit instead of an empty card. Idempotent;
    // safe to retry on every login. Failures here (e.g. PDS hiccup)
    // never block the user from finishing sign-in — the lazy
    // ensureMyProfile call from the /account page picks it up.
    yield* Effect.either(
      Effect.tryPromise(() => ensureMyProfile(oauthSession)).pipe(
        Effect.tapError((e) =>
          Effect.sync(() => {
            console.warn("[oauth-callback] ensureMyProfile failed:", e);
          }),
        ),
      ),
    );
    const sessionToken = issueAppSession(did);
    const isSecure = request.url.startsWith("https://");
    const cookieDomain = authCookieDomain(new URL(request.url).host);
    const cookieAttributes = [
      `Path=/`,
      `HttpOnly`,
      `SameSite=Lax`,
      ...(isSecure ? ["Secure"] : []),
      ...(cookieDomain ? [`Domain=${cookieDomain}`] : []),
      `Max-Age=${30 * 24 * 60 * 60}`,
    ].join("; ");

    const headers = new Headers();
    const baseUrl = new URL(request.url);
    const redirectUrl = returnTo.startsWith("http")
      ? new URL(returnTo)
      : new URL(returnTo, `${baseUrl.protocol}//${baseUrl.host}`);

    redirectUrl.searchParams.set("loginSuccess", "true");
    if (handle) {
      redirectUrl.searchParams.set("handle", handle);
    }
    const avatar = typeof publicProfile?.avatarUrl === "string" ? publicProfile.avatarUrl : "";
    redirectUrl.searchParams.set("avatar", avatar);

    headers.set("Location", redirectUrl.toString());
    headers.append(
      "Set-Cookie",
      `${AUTH_SESSION_TOKEN_COOKIE}=${sessionToken}; ${cookieAttributes}`,
    );

    return new Response(null, {
      status: 302,
      headers,
    });
  });
}

export type OAuthCallbackOutcome =
  | { readonly _tag: "response"; readonly response: Response }
  | { readonly _tag: "redirect"; readonly href: string };

export function oauthCallbackOutcomeEffect(request: Request): Effect.Effect<OAuthCallbackOutcome> {
  return Effect.gen(function* () {
    const outcome = yield* Effect.either(oauthCallbackResponseEffect(request));
    if (Either.isLeft(outcome)) {
      yield* Effect.sync(() => console.error("Atproto OAuth callback error:", outcome.left));
      return { _tag: "redirect", href: "/login?error=oauth_failed" } as const;
    }
    return { _tag: "response", response: outcome.right } as const;
  });
}
