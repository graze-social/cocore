"use client";

import * as stylex from "@stylexjs/stylex";
import { useEffect, useState } from "react";

import { Button } from "@/design-system/button";
import { Flex } from "@/design-system/flex";
import { TextField } from "@/design-system/text-field";
import { fontFamily } from "@/design-system/theme/typography.stylex";
import { Body, Heading1, InlineCode } from "@/design-system/typography";

const styles = stylex.create({
  codeInput: {
    fontFamily: fontFamily.mono,
    fontSize: "1.5rem",
    letterSpacing: "0.2em",
    width: "12ch",
  },
});

interface Props {
  initialCode: string;
}

/** What `dev.cocore.devicePair.describe` says about the code: who is asking. */
interface DescribedApp {
  did: string;
  handle?: string;
  name: string;
  website?: string;
  iconUrl?: string;
  verified: boolean;
  verifiedHost?: string;
}

interface Described {
  status: "pending" | "approved" | "denied" | "expired" | "consumed";
  appName?: string;
  keyName?: string;
  returnUrl?: string;
  /** Present when the requester is a registered application (`appDid`). */
  app?: DescribedApp;
  expiresInSecs: number;
}

type Status = "idle" | "approving" | "approved" | "denying" | "denied" | "error";

const RETURN_DELAY_MS = 1200;

/**
 * The approve screen for a pairing code.
 *
 * Two requesters share it. A provider machine (`cocore agent pair`) has no
 * name, so the copy talks about pairing a machine. An application connecting
 * on the user's behalf (Graze's "Connect co/core") sent `appName`, `keyName`
 * and a `returnUrl` at `start`: the copy then reads as a consent screen — who
 * is asking, what they get, how to take it back — and approval sends the
 * browser back to the app.
 */
export function PairConfirm({ initialCode }: Props) {
  const [code, setCode] = useState(initialCode);
  const [status, setStatus] = useState<Status>("idle");
  const [errMsg, setErrMsg] = useState<string | null>(null);
  const [described, setDescribed] = useState<Described | null>(null);
  const [returnUrl, setReturnUrl] = useState<string | null>(null);

  // Ask who is behind the code as soon as it is complete. Best-effort: a
  // failed describe just leaves the generic machine-pairing copy in place.
  useEffect(() => {
    if (code.length !== 8) {
      setDescribed(null);
      return;
    }
    let cancelled = false;
    void fetch(`/api/xrpc/dev.cocore.devicePair.describe?userCode=${encodeURIComponent(code)}`)
      .then(async (res) => (res.ok ? ((await res.json()) as Described) : null))
      .then((d) => {
        if (!cancelled) setDescribed(d);
      })
      .catch(() => {
        if (!cancelled) setDescribed(null);
      });
    return () => {
      cancelled = true;
    };
  }, [code]);

  // After an approval that asked to go back somewhere, go there.
  useEffect(() => {
    if (status !== "approved" || !returnUrl) return;
    const t = setTimeout(() => {
      window.location.assign(returnUrl);
    }, RETURN_DELAY_MS);
    return () => clearTimeout(t);
  }, [status, returnUrl]);

  const appName = described?.appName;
  const app = described?.app;

  async function approve() {
    setStatus("approving");
    setErrMsg(null);
    try {
      // The session (scoped API key) is minted server-side on approve; the
      // browser only asserts the user_code + decision.
      const res = await fetch("/api/xrpc/dev.cocore.devicePair.confirm", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userCode: code, decision: "approve" }),
      });
      const body = (await res.json().catch(() => ({}))) as { error?: string; returnUrl?: string };
      if (!res.ok) {
        throw new Error(body.error ?? `${res.status}`);
      }
      if (typeof body.returnUrl === "string" && body.returnUrl) setReturnUrl(body.returnUrl);
      setStatus("approved");
    } catch (e) {
      setStatus("error");
      setErrMsg((e as Error).message);
    }
  }

  async function deny() {
    setStatus("denying");
    setErrMsg(null);
    try {
      await fetch("/api/xrpc/dev.cocore.devicePair.confirm", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userCode: code, decision: "deny" }),
      });
      setStatus("denied");
    } catch (e) {
      setStatus("error");
      setErrMsg((e as Error).message);
    }
  }

  if (status === "approved") {
    return (
      <Flex direction="column" gap="xl">
        <Heading1>Approved</Heading1>
        <Body>
          {returnUrl
            ? `Taking you back to ${appName ?? "the app"}…`
            : appName
              ? `${appName} can now use your co/core account. You can close this tab.`
              : "You can close this tab; the provider agent will pick up the session."}
        </Body>
        {returnUrl && (
          <Body>
            Not redirected? <a href={returnUrl}>Return to {appName ?? "the app"}</a>.
          </Body>
        )}
      </Flex>
    );
  }
  if (status === "denied") {
    return (
      <Flex direction="column" gap="xl">
        <Heading1>Denied</Heading1>
        <Body>
          {appName
            ? `${appName} was not given access. Nothing was created on your account.`
            : "The provider agent will stop polling."}
        </Body>
      </Flex>
    );
  }

  const settled = described && described.status !== "pending";

  return (
    <Flex direction="column" gap="xl">
      {appName ? (
        <>
          <Heading1>Connect {appName} to co/core</Heading1>
          {app ? (
            <Body>
              {app.verified ? (
                <>
                  Verified application: {app.handle ? `@${app.handle}` : app.did}
                  {app.verifiedHost ? ` · ${app.verifiedHost}` : ""}
                  {app.website ? (
                    <>
                      {" "}
                      · <a href={app.website}>{new URL(app.website).host}</a>
                    </>
                  ) : null}
                </>
              ) : (
                <>
                  <strong>Unverified application</strong> ({app.handle ? `@${app.handle}` : app.did}
                  ). co/core could not confirm this app controls a website, so it will not be sent
                  your browser afterwards. Only continue if you started this from {appName}{" "}
                  yourself.
                </>
              )}
            </Body>
          ) : (
            <Body>
              <strong>Unregistered request.</strong> This name was typed by whoever started the
              pairing and has not been checked. Only continue if you started this yourself.
            </Body>
          )}
          <Body>
            <strong>{appName}</strong> is asking for an API key on your co/core account
            {described?.keyName ? (
              <>
                , named <InlineCode>{described.keyName}</InlineCode>
              </>
            ) : null}
            . With it, {appName} can run inference jobs that are billed to your co/core credits, and
            every job leaves a signed receipt on the provider&apos;s account. It cannot change your
            account or see your other keys.
          </Body>
          <Body>
            You can take this back at any time under Account → API keys. Make sure you are signed in
            as the identity you want {appName} to act for.
          </Body>
        </>
      ) : (
        <>
          <Heading1>Pair a new provider machine</Heading1>
          <Body>
            Enter the 8-character code shown by your <InlineCode>cocore agent pair</InlineCode>{" "}
            command. Make sure you signed in with the ATProto identity you want the machine to
            publish receipts under.
          </Body>
        </>
      )}
      {settled && (
        <Body>
          This code is already {described.status}. Ask {appName ?? "the requester"} to start again.
        </Body>
      )}
      <TextField
        label="Code"
        value={code}
        onChange={(value) => setCode(value.toUpperCase())}
        maxLength={8}
        size="lg"
        inputStyle={styles.codeInput}
        validationState={errMsg ? "invalid" : undefined}
        errorMessage={errMsg ? `Error: ${errMsg}` : undefined}
      />
      <Flex direction="row" gap="md" wrap>
        <Button
          onPress={approve}
          isDisabled={status === "approving" || code.length !== 8 || Boolean(settled)}
        >
          {appName ? `Allow ${appName}` : "Approve"}
        </Button>
        <Button
          variant="secondary"
          onPress={deny}
          isDisabled={status === "denying" || code.length !== 8 || Boolean(settled)}
        >
          Deny
        </Button>
      </Flex>
    </Flex>
  );
}
