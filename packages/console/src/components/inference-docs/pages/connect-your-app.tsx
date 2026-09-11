"use client";

import * as stylex from "@stylexjs/stylex";

import { docsStyles } from "@/components/docs/docs-page.stylex.tsx";
import { InferenceDocLink } from "@/components/inference-docs/inference-doc-link.tsx";
import { InferenceDocsPage } from "@/components/inference-docs/inference-docs-page.tsx";
import {
  HighlightedBlock,
  inferenceDocsSharedStyles,
} from "@/components/inference-docs/shared.tsx";

/**
 * "Sign in with co/core" — the device-pairing flow an application uses to let
 * its own users connect their co/core account in one click. Every request the
 * app then makes runs on the user's credits and leaves a signed receipt; the
 * app never sees the user's password and never holds their session.
 */
export function ConnectYourAppPage({ baseUrl }: { baseUrl: string }) {
  // baseUrl is the inference origin (e.g. https://cocore.dev/v1); the pairing
  // endpoints live one level up, under /api/xrpc on the same host.
  const apiOrigin = baseUrl.replace(/\/v1\/?$/, "");
  return (
    <InferenceDocsPage
      kicker="Build with co/core"
      title="Sign in with co/core"
      description="Let your users connect their own co/core account to your app in one click. Jobs run on their credits, with a signed receipt for every one."
    >
      <p {...stylex.props(docsStyles.prose)}>
        Some apps want inference on <em>their user&apos;s</em> co/core account, not their own — a
        feed reader that summarizes each user&apos;s feed, an assistant that bills each user&apos;s
        balance. co/core&apos;s device pairing is the primitive for that: your app starts a pairing,
        sends the user to co/core to approve it, and receives a scoped API key bound to the
        user&apos;s DID. You never see their password, and the key only ever spends their credits.
      </p>
      <p {...stylex.props(docsStyles.prose)}>
        The whole flow is four HTTP calls against{" "}
        <code {...stylex.props(docsStyles.codeInline)}>
          {apiOrigin}/api/xrpc/dev.cocore.devicePair.*
        </code>
        . No SDK required.
      </p>

      <h2 {...stylex.props(docsStyles.h2, docsStyles.h2First)}>1. Start a pairing</h2>
      <p {...stylex.props(docsStyles.prose)}>
        From your server, begin a pairing.{" "}
        <code {...stylex.props(docsStyles.codeInline)}>appName</code> and{" "}
        <code {...stylex.props(docsStyles.codeInline)}>appDid</code> name your app on the approval
        screen; <code {...stylex.props(docsStyles.codeInline)}>keyName</code> labels the key in the
        user&apos;s account; <code {...stylex.props(docsStyles.codeInline)}>returnUrl</code> is
        where co/core sends the browser back after approval (its host must be allowlisted — see step
        4).
      </p>
      <HighlightedBlock
        lang="bash"
        code={`curl -X POST ${apiOrigin}/api/xrpc/dev.cocore.devicePair.start \\
  -H 'content-type: application/json' \\
  -d '{
    "appName": "Your App",
    "appDid": "did:plc:your-app-did",
    "keyName": "Your App",
    "returnUrl": "https://yourapp.example/connected"
  }'

# → {
#   "deviceId": "…",            # secret; keep it on your server
#   "userCode": "HB8G7HX7",     # show this to the user
#   "verificationUri": "${apiOrigin}/devices/new?code=HB8G7HX7",
#   "pollIntervalSecs": 3,
#   "expiresInSecs": 600
# }`}
      />
      <p {...stylex.props(docsStyles.prose)}>
        Keep <code {...stylex.props(docsStyles.codeInline)}>deviceId</code> on your server — it is
        the secret that later reads the key. Send the user to{" "}
        <code {...stylex.props(docsStyles.codeInline)}>verificationUri</code>.
      </p>

      <h2 {...stylex.props(docsStyles.h2)}>2. The user approves</h2>
      <p {...stylex.props(docsStyles.prose)}>
        At <code {...stylex.props(docsStyles.codeInline)}>verificationUri</code> the user signs in
        to co/core (once) and sees a consent screen naming your app. On approve, co/core mints an
        API key scoped to their DID and sends the browser back to your{" "}
        <code {...stylex.props(docsStyles.codeInline)}>returnUrl</code>. If you never showed the
        user the code,{" "}
        <code {...stylex.props(docsStyles.codeInline)}>devicePair.describe?userCode=…</code> echoes
        back your app name so a second screen can confirm who is asking.
      </p>

      <h2 {...stylex.props(docsStyles.h2)}>3. Poll for the key</h2>
      <p {...stylex.props(docsStyles.prose)}>
        While the user is approving, poll from your server with the{" "}
        <code {...stylex.props(docsStyles.codeInline)}>deviceId</code> every{" "}
        <code {...stylex.props(docsStyles.codeInline)}>pollIntervalSecs</code>. Until they act it
        returns <code {...stylex.props(docsStyles.codeInline)}>pending</code>; on approve it returns{" "}
        <code {...stylex.props(docsStyles.codeInline)}>session</code> carrying the scoped key.
      </p>
      <HighlightedBlock
        lang="bash"
        code={`curl "${apiOrigin}/api/xrpc/dev.cocore.devicePair.poll?deviceId=DEVICE_ID"

# pending: { "status": "pending" }
# denied:  { "status": "denied" }   (410 expired / consumed are terminal too)
# ready:   {
#   "status": "session",
#   "session": {
#     "did":    "did:plc:the-user",
#     "handle": "user.example.com",
#     "apiKey": "cocore-…",         # store encrypted; spends the user's credits
#     "apiBase": "${baseUrl}"
#   }
# }`}
      />
      <p {...stylex.props(docsStyles.prose)}>
        Store <code {...stylex.props(docsStyles.codeInline)}>apiKey</code> encrypted, keyed to the
        user. Then it is an ordinary co/core key: call{" "}
        <code {...stylex.props(docsStyles.codeInline)}>{baseUrl}/v1/chat/completions</code> with it
        (see the <InferenceDocLink slug="quickstart">quickstart</InferenceDocLink>). Each response
        carries an <code {...stylex.props(docsStyles.codeInline)}>x_cocore</code> block with the
        provider and a receipt URI, and the job is billed to the user, not to you.
      </p>

      <h2 {...stylex.props(docsStyles.h2)}>4. Register your app (recommended)</h2>
      <p {...stylex.props(docsStyles.prose)}>
        Two things make the flow feel first-class instead of anonymous:
      </p>
      <ol {...stylex.props(inferenceDocsSharedStyles.list)}>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          <strong>An app registration record.</strong> Publish a{" "}
          <code {...stylex.props(docsStyles.codeInline)}>dev.cocore.app.registration</code> record
          on your app&apos;s own repo with your{" "}
          <code {...stylex.props(docsStyles.codeInline)}>name</code>,{" "}
          <code {...stylex.props(docsStyles.codeInline)}>website</code>,{" "}
          <code {...stylex.props(docsStyles.codeInline)}>iconUrl</code>, and{" "}
          <code {...stylex.props(docsStyles.codeInline)}>returnUrls</code>. The consent screen reads
          it to show your name and icon rather than a bare DID.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          <strong>A verified return host.</strong> co/core only sends the browser back to a{" "}
          <code {...stylex.props(docsStyles.codeInline)}>returnUrl</code> whose host you control.
          Prove it by serving{" "}
          <code {...stylex.props(docsStyles.codeInline)}>/.well-known/cocore-app.json</code> listing
          your app DID(s), so an attacker can&apos;t point the redirect at their own site.
        </li>
      </ol>
      <HighlightedBlock
        lang="json"
        code={`// dev.cocore.app.registration (rkey "self") on your app's repo
{
  "$type": "dev.cocore.app.registration",
  "name": "Your App",
  "website": "https://yourapp.example",
  "iconUrl": "https://yourapp.example/icon.svg",
  "description": "What your app does with the user's co/core account.",
  "returnUrls": ["https://yourapp.example/connected"]
}

// https://yourapp.example/.well-known/cocore-app.json
{ "did": "did:plc:your-app-did" }`}
      />
      <p {...stylex.props(docsStyles.prose)}>
        Both are optional — pairing works without them — but together they turn &ldquo;an unknown
        DID wants access&rdquo; into &ldquo;Your App wants access,&rdquo; with the redirect locked
        to a host you own.
      </p>

      <h2 {...stylex.props(docsStyles.h2)}>Notes</h2>
      <ol {...stylex.props(inferenceDocsSharedStyles.list)}>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          The <code {...stylex.props(docsStyles.codeInline)}>deviceId</code> is a bearer secret for
          the pending pairing; keep it server-side and never put it in the browser.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          A pairing expires after{" "}
          <code {...stylex.props(docsStyles.codeInline)}>expiresInSecs</code>. If the user never
          approves, start a new one.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          The key stops working if the user revokes it in their co/core account or their underlying
          session lapses — handle a <code {...stylex.props(docsStyles.codeInline)}>401</code> by
          asking them to reconnect.
        </li>
      </ol>
    </InferenceDocsPage>
  );
}
