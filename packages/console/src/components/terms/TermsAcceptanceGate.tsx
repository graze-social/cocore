"use client";

// Terms re-acceptance UI for signed-in users whose most recent
// `dev.cocore.compute.termsAcceptance` doesn't match the active
// exchange's `termsVersion`. Rendered from `/accept-terms` (see
// `_header-layout.accept-terms.tsx`); the header layout redirects
// there with a `redirect` query param when the user tries to use the
// app while out-of-date.

import * as stylex from "@stylexjs/stylex";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";

import { clearChatStoreMemory } from "@/components/chat/chat-store.ts";
import {
  acceptTermsMutationOptions,
  getMyTermsStateQueryOptions,
} from "@/components/terms/terms.functions.ts";
import { Alert } from "@/design-system/alert";
import { Button } from "@/design-system/button";
import {
  Card,
  CardBody,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/design-system/card";
import { Flex } from "@/design-system/flex";
import { Page } from "@/design-system/page/index.tsx";
import { fontFamily, fontSize } from "@/design-system/theme/typography.stylex";
import { Body } from "@/design-system/typography";
import {
  getSessionQueryOptions,
  signOutMutationOptions,
} from "@/integrations/auth/session.functions.ts";
import { isSessionExpiredError } from "@/lib/session-expired.ts";
import type { TermsState } from "@/lib/terms-acceptance.server.ts";

const styles = stylex.create({
  list: {
    margin: "0.75rem 0 0",
    paddingLeft: "1.25rem",
    fontFamily: fontFamily.sans,
    fontSize: "0.95rem",
    lineHeight: 1.55,
  },
  bullet: {
    marginBottom: "0.65rem",
  },
  link: {
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
  },
});

interface Props {
  /** The terms state from `getMyTermsStateQueryOptions`. We've
   *  already verified `accepted === false && activePolicy != null`
   *  on the caller's side; this component can rely on those
   *  invariants. */
  state: TermsState & { activePolicy: NonNullable<TermsState["activePolicy"]> };
  /** Called after acceptance is recorded and the terms-state query is invalidated. */
  onAccepted?: () => void;
}

export function TermsAcceptanceGate({ state, onAccepted }: Props) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const acceptM = useMutation(acceptTermsMutationOptions);
  // The underlying ATProto session died (refresh token expired/revoked):
  // the write can never succeed from here, so instead of showing the raw
  // 401, sign out and send the user through login, landing back on this
  // page. Same teardown as the navbar logout so no stale user-scoped cache
  // survives.
  const signOutM = useMutation({
    ...signOutMutationOptions,
    onSettled: async () => {
      clearChatStoreMemory();
      queryClient.setQueryData(getSessionQueryOptions.queryKey, null);
      const here = `${window.location.pathname}${window.location.search}`;
      await navigate({ to: "/login", search: { redirect: here } });
      queryClient.clear();
      queryClient.setQueryData(getSessionQueryOptions.queryKey, null);
    },
  });
  const sessionExpired = acceptM.isError && isSessionExpiredError(acceptM.error);
  const policy = state.activePolicy;
  const termsUri = policy.termsUri ?? "/terms";
  const termsVersion = policy.termsVersion ?? "v1";
  // Only frame this as a CHANGE when the user actually agreed to an
  // earlier version. A first-time user has nothing that "changed" — they
  // just need to review and accept.
  const changed = state.hasPriorAcceptance;

  const onAgree = () => {
    if (!policy.termsUri || !policy.termsVersion) return;
    acceptM.mutate(
      {
        policyUri: policy.uri,
        policyCid: policy.cid,
        termsVersion: policy.termsVersion,
        termsUri: policy.termsUri,
      },
      {
        onSuccess: async () => {
          await queryClient.invalidateQueries({ queryKey: getMyTermsStateQueryOptions.queryKey });
          onAccepted?.();
        },
        onError: (e) => {
          if (isSessionExpiredError(e)) signOutM.mutate();
        },
      },
    );
  };

  return (
    <Page.Root variant="small">
      <Page.Header>
        <Page.Title>{changed ? "Updated terms" : "Terms of Service"}</Page.Title>
      </Page.Header>
      <Card size="md">
        <CardHeader hasBorder>
          <CardTitle>
            {changed ? "Heads up — the terms have changed" : "Review the terms before you start"}
          </CardTitle>
          <CardDescription>
            {changed ? (
              <>
                The active exchange has published an updated <code>exchangePolicy</code> with a new{" "}
                <code>termsVersion</code> ({termsVersion}). To keep using co/core, please review and
                accept the updated terms.
              </>
            ) : (
              <>
                To use co/core, please review and accept the terms of service (version{" "}
                <code>{termsVersion}</code>).
              </>
            )}
          </CardDescription>
        </CardHeader>
        <CardBody>
          <Flex direction="column" gap="6xl">
            <ul {...stylex.props(styles.list)}>
              <li {...stylex.props(styles.bullet)}>
                <strong>This software has not been independently security-audited.</strong> A lot of
                it was written with help from a generative AI. There may be bugs, including ones
                that affect your machine.
              </li>
              <li {...stylex.props(styles.bullet)}>
                <strong>Installing the provider agent is at your own risk.</strong> The co/core
                maintainers disclaim responsibility for damage, data loss, or downtime that results
                from running it.
              </li>
              <li {...stylex.props(styles.bullet)}>
                <strong>Don't try to harm other machines.</strong> Submitting prompts that try to
                attack the provider's host, exfiltrate data, or break the protocol's integrity will
                get you banned.
              </li>
              <li {...stylex.props(styles.bullet)}>
                <strong>Your acceptance is recorded on your PDS.</strong> Clicking "I agree"
                publishes a <code>dev.cocore.compute.termsAcceptance</code> record under your DID.
                Future co/core-aware clients can verify you accepted this version.
              </li>
            </ul>
            <Body style={styles.link}>
              Full text:{" "}
              <a href={termsUri} target="_blank" rel="noreferrer">
                Terms of Service
              </a>{" "}
              ·{" "}
              <a href="/privacy" target="_blank" rel="noreferrer">
                Privacy Policy
              </a>{" "}
              · version <code>{termsVersion}</code>
            </Body>
            {sessionExpired ? (
              <Alert variant="warning" title="Your session expired">
                <Body>Signing you out so you can sign back in and accept the terms…</Body>
              </Alert>
            ) : acceptM.isError ? (
              <Alert variant="critical" title="Could not record acceptance">
                <Body>
                  {acceptM.error instanceof Error ? acceptM.error.message : String(acceptM.error)}
                </Body>
              </Alert>
            ) : null}
          </Flex>
        </CardBody>
        <CardFooter>
          <Button
            variant="primary"
            size="lg"
            isDisabled={acceptM.isPending || signOutM.isPending || sessionExpired}
            onPress={onAgree}
          >
            {acceptM.isPending ? "Recording acceptance…" : "I agree"}
          </Button>
        </CardFooter>
      </Card>
    </Page.Root>
  );
}
