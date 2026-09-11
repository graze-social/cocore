"use client";

import * as stylex from "@stylexjs/stylex";
import { Link } from "@tanstack/react-router";

import { docsStyles } from "@/components/docs/docs-page.stylex.tsx";
import { InferenceApiDocLink } from "@/components/inference-docs/inference-doc-link.tsx";
import { InferenceDocsPage } from "@/components/inference-docs/inference-docs-page.tsx";
import {
  HighlightedBlock,
  inferenceDocsSharedStyles,
} from "@/components/inference-docs/shared.tsx";

/**
 * "Sign in with co/core" for applications: how an app connects its users'
 * co/core accounts in one click via device pairing. Mirrors
 * docs/connect-with-cocore.md in the repo; Graze's "Connect co/core" is the
 * reference implementation.
 */
export function InferenceConnectYourAppPage({ baseUrl }: { baseUrl: string }) {
  const consoleUrl = baseUrl.replace(/\/v1\/?$/, "").replace(/\/api\/v1\/?$/, "");
  return (
    <InferenceDocsPage
      kicker="Getting started"
      title="Connect your app"
      description="Let users connect their co/core account to your application in one click, so it can run inference on their credits."
    >
      <h2 {...stylex.props(docsStyles.h2, docsStyles.h2First)}>What the user sees</h2>
      <ol {...stylex.props(inferenceDocsSharedStyles.list)}>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          They press <strong>Connect co/core</strong> in your app.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Their browser lands on the co/core approve screen. If they are not signed in they sign in
          first with their Bluesky handle.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          The screen reads{" "}
          <em>
            &ldquo;Connect Your App to co/core &middot; Verified application: @yourapp.example
            &middot; yourapp.example&rdquo;
          </em>
          , explains that the key can run inference on their credits and nothing else, and offers{" "}
          <strong>Allow Your App</strong>.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Approval sends them straight back to your app. Your server already holds the key.
        </li>
      </ol>
      <p {...stylex.props(docsStyles.prose)}>
        No OAuth client registration with us, no scopes to negotiate, no key copying. It is the same
        device-pairing flow <code {...stylex.props(docsStyles.codeInline)}>cocore agent pair</code>{" "}
        uses, with your app&apos;s identity attached.
      </p>

      <h2 {...stylex.props(docsStyles.h2)}>Once: register your app</h2>
      <h3 {...stylex.props(docsStyles.h2)}>1. Publish a registration record</h3>
      <p {...stylex.props(docsStyles.prose)}>
        Your app is identified by a DID that has a repo &mdash; usually the Bluesky account you run
        the app from. Publish one{" "}
        <code {...stylex.props(docsStyles.codeInline)}>dev.cocore.app.registration</code> record at
        rkey <code {...stylex.props(docsStyles.codeInline)}>self</code>. There is no central
        registry: the record on your account is the registration, and you can change or delete it
        whenever you like.
      </p>
      <HighlightedBlock
        lang="json"
        code={`{
  "$type": "dev.cocore.app.registration",
  "name": "Your App",
  "description": "What the connection is used for, in one sentence.",
  "website": "https://yourapp.example",
  "iconUrl": "https://yourapp.example/icon.png",
  "returnUrls": ["https://yourapp.example/settings/connections"],
  "createdAt": "2026-09-11T00:00:00Z"
}`}
      />
      <HighlightedBlock
        lang="bash"
        code={`curl -sS -X POST "$PDS/xrpc/com.atproto.repo.putRecord" \\
  -H "authorization: Bearer $ACCESS_JWT" -H 'content-type: application/json' \\
  -d '{"repo":"did:plc:yourapp","collection":"dev.cocore.app.registration","rkey":"self","record":{ ...the record above... }}'`}
      />
      <p {...stylex.props(docsStyles.prose)}>
        <code {...stylex.props(docsStyles.codeInline)}>name</code> is what users see.{" "}
        <code {...stylex.props(docsStyles.codeInline)}>returnUrls</code> are the only places the
        approve screen will ever send a browser; a requested return URL must match one of them on
        origin and path, and its query string is yours to use.
      </p>

      <h3 {...stylex.props(docsStyles.h2)}>2. Prove you control the return host</h3>
      <p {...stylex.props(docsStyles.prose)}>
        Serve <code {...stylex.props(docsStyles.codeInline)}>/.well-known/cocore-app.json</code> on
        each return host, naming your DID:
      </p>
      <HighlightedBlock lang="json" code={`{ "did": "did:plc:yourapp" }`} />
      <p {...stylex.props(docsStyles.prose)}>
        (<code {...stylex.props(docsStyles.codeInline)}>{`{ "dids": [...] }`}</code> is accepted
        when one host fronts several apps.) This is what stops a record on a stranger&apos;s account
        from borrowing your domain. Without it users can still connect &mdash; the approve screen
        just labels your app <strong>unverified</strong> and does not redirect them back.
      </p>

      <h2 {...stylex.props(docsStyles.h2)}>Per user: start, redirect, poll</h2>
      <h3 {...stylex.props(docsStyles.h2)}>3. Start a pairing, server-side</h3>
      <HighlightedBlock
        lang="bash"
        code={`curl -sS -X POST ${consoleUrl}/api/xrpc/dev.cocore.devicePair.start \\
  -H 'content-type: application/json' \\
  -d '{"appDid":"did:plc:yourapp","keyName":"Your App","returnUrl":"https://yourapp.example/settings/connections?cocore=connected"}'`}
      />
      <HighlightedBlock
        lang="json"
        code={`{
  "deviceId": "…32 hex…",
  "userCode": "K7PX2M4Q",
  "verificationUri": "${consoleUrl}/devices/new?code=K7PX2M4Q",
  "pollIntervalSecs": 3,
  "expiresInSecs": 600
}`}
      />
      <p {...stylex.props(docsStyles.prose)}>
        Keep <code {...stylex.props(docsStyles.codeInline)}>deviceId</code> on your server: it is
        the credential that collects the key, so it must never reach a browser. Start pairings from
        your backend, not from page JavaScript.
      </p>

      <h3 {...stylex.props(docsStyles.h2)}>4. Send the user to the verification URI</h3>
      <p {...stylex.props(docsStyles.prose)}>
        A plain top-level navigation to{" "}
        <code {...stylex.props(docsStyles.codeInline)}>verificationUri</code>. Same-tab works best:
        co/core returns them to your <code {...stylex.props(docsStyles.codeInline)}>returnUrl</code>{" "}
        afterwards.
      </p>

      <h3 {...stylex.props(docsStyles.h2)}>5. Poll for the key</h3>
      <HighlightedBlock
        lang="bash"
        code={`curl -sS "${consoleUrl}/api/xrpc/dev.cocore.devicePair.poll?deviceId=…"`}
      />
      <HighlightedBlock
        lang="json"
        code={`{ "status": "pending" }

{ "status": "session",
  "session": { "did": "did:plc:…", "handle": "alice.bsky.social",
               "apiKey": "cocore-…", "apiBase": "${consoleUrl}" } }`}
      />
      <p {...stylex.props(docsStyles.prose)}>
        <code {...stylex.props(docsStyles.codeInline)}>pending</code> until they act, then{" "}
        <code {...stylex.props(docsStyles.codeInline)}>session</code> exactly once. Terminal states:{" "}
        <code {...stylex.props(docsStyles.codeInline)}>denied</code> (403),{" "}
        <code {...stylex.props(docsStyles.codeInline)}>expired</code> /{" "}
        <code {...stylex.props(docsStyles.codeInline)}>consumed</code> (410),{" "}
        <code {...stylex.props(docsStyles.codeInline)}>unknown</code> (404 &mdash; the attempt is
        gone, start again).{" "}
        <strong>
          Check that <code {...stylex.props(docsStyles.codeInline)}>session.did</code> is the user
          you expected
        </strong>{" "}
        before storing <code {...stylex.props(docsStyles.codeInline)}>apiKey</code>: the key belongs
        to whoever was signed in at co/core. Store it encrypted; it is shown once.
      </p>

      <h3 {...stylex.props(docsStyles.h2)}>6. Use the key</h3>
      <p {...stylex.props(docsStyles.prose)}>
        Point any OpenAI-compatible client at{" "}
        <code {...stylex.props(docsStyles.codeInline)}>{baseUrl}</code> with the key as the bearer
        token, exactly as in the{" "}
        <Link
          to="/docs/inference/$slug"
          params={{ slug: "quickstart" }}
          {...stylex.props(docsStyles.proseLink)}
        >
          quickstart
        </Link>
        . Jobs are billed to the user&apos;s credits, and every response&apos;s{" "}
        <code {...stylex.props(docsStyles.codeInline)}>x_cocore</code> block names the provider and
        the signed receipt.
      </p>

      <h2 {...stylex.props(docsStyles.h2)}>SDK helpers</h2>
      <HighlightedBlock
        lang="bash"
        code={`# TypeScript (@cocore/sdk)
const pairing = await startAppPairing({ appDid, keyName: "Your App", returnUrl });
// redirect the user to pairing.verificationUri, then:
const session = await waitForAppPairing(pairing);

# Python (cocore)
pairing = start_app_pairing("did:plc:yourapp", key_name="Your App", return_url=return_url)
# redirect the user to pairing.verification_uri, then:
session = wait_for_app_pairing(pairing)`}
      />

      <h2 {...stylex.props(docsStyles.h2)}>Limits and behaviour</h2>
      <ul {...stylex.props(inferenceDocsSharedStyles.list)}>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          <code {...stylex.props(docsStyles.codeInline)}>start</code>,{" "}
          <code {...stylex.props(docsStyles.codeInline)}>describe</code> and{" "}
          <code {...stylex.props(docsStyles.codeInline)}>confirm</code> are rate-limited per client
          IP (30 / 120 / 30 per ten minutes).
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Pairings expire after ten minutes and are held in memory; a co/core deploy drops them (
          <code {...stylex.props(docsStyles.codeInline)}>unknown</code>). Start again.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          <code {...stylex.props(docsStyles.codeInline)}>
            dev.cocore.devicePair.describe?userCode=
          </code>{" "}
          is the public read the approve screen uses; it echoes your registration and never the{" "}
          <code {...stylex.props(docsStyles.codeInline)}>deviceId</code>.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          A <code {...stylex.props(docsStyles.codeInline)}>start</code> with an{" "}
          <code {...stylex.props(docsStyles.codeInline)}>appName</code> but no{" "}
          <code {...stylex.props(docsStyles.codeInline)}>appDid</code> still works (for CLIs and
          prototypes) but is shown as an <strong>unregistered request</strong>.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Full request and response shapes:{" "}
          <InferenceApiDocLink fragment="inference-api-http-errors">
            API reference
          </InferenceApiDocLink>{" "}
          and the{" "}
          <Link to="/docs/lexicons" {...stylex.props(docsStyles.proseLink)}>
            lexicons
          </Link>
          .
        </li>
      </ul>
    </InferenceDocsPage>
  );
}
