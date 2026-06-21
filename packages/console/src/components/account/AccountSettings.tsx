"use client";

import * as stylex from "@stylexjs/stylex";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { CircleHelp } from "lucide-react";
import { useMemo, useState } from "react";

import { highlightCodeQueryOptions } from "@/components/account/account.functions.ts";
import {
  deleteMyApiKeyMutationOptions,
  listMyApiKeysQueryOptions,
  resetConnectionMutationOptions,
  revokeMyApiKeyMutationOptions,
  wipeMyDataMutationOptions,
} from "@/components/api-keys/api-keys.functions.ts";
import { clearChatStoreMemory } from "@/components/chat/chat-store.ts";
import { CreateApiKeyButton } from "@/components/api-keys/CreateApiKeyButton.tsx";
import { ProfileCard } from "@/components/account/ProfileCard.tsx";
import { TokenBalanceCard } from "@/components/account/TokenBalanceCard.tsx";
import {
  type SnippetLang,
  SNIPPET_LANGS,
  SNIPPET_LANG_LABELS,
  buildSnippet,
} from "@/components/api-docs/snippets.ts";
import { useThemeMode } from "@/components/theme-mode.ts";
import { Alert } from "@/design-system/alert";
import { Button } from "@/design-system/button";
import {
  Card,
  CardBody,
  CardDescription,
  CardHeader,
  CardHeaderAction,
  CardTitle,
} from "@/design-system/card";
import { CopyToClipboardButton } from "@/design-system/copy-to-clipboard-button";
import {
  Dialog,
  DialogBody,
  DialogDescription,
  DialogFooter,
  DialogHeader,
} from "@/design-system/dialog";
import { Flex } from "@/design-system/flex";
import { IconButton } from "@/design-system/icon-button";
import { Page } from "@/design-system/page/index.tsx";
import { SegmentedControl, SegmentedControlItem } from "@/design-system/segmented-control";
import {
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@/design-system/table";
import { uiColor } from "@/design-system/theme/color.stylex";
import { horizontalSpace, verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import {
  fontFamily,
  fontSize,
  fontWeight,
  lineHeight,
} from "@/design-system/theme/typography.stylex";
import { toasts } from "@/design-system/toast";
import { Body, Heading1, Heading2, InlineCode, LabelText } from "@/design-system/typography";
import { getSessionQueryOptions } from "@/integrations/auth/session.functions.ts";

const styles = stylex.create({
  header: {
    marginBottom: 0,
  },
  root: {
    display: "flex",
    flexDirection: "column",
    fontFamily: fontFamily.mono,
    gap: verticalSpace["2xl"],
    marginLeft: "auto",
    marginRight: "auto",
    maxWidth: "1600px",
    paddingBottom: verticalSpace["12xl"],
    width: "100%",
  },
  headingMono: {
    fontFamily: fontFamily.mono,
  },
  titlePrompt: {
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  metaRow: {
    fontFamily: fontFamily.mono,
    opacity: 0.7,
    fontSize: "0.875rem",
    lineHeight: lineHeight["lg"],
  },
  sections: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["8xl"],
  },
  profileRow: {
    alignItems: "center",
    display: "flex",
    gap: horizontalSpace["2xl"],
  },
  profileText: {
    minWidth: 0,
  },
  didText: {
    color: uiColor.text1,
    overflowWrap: "anywhere",
  },
  cardTitleMono: {
    fontSize: fontSize.base,
    fontWeight: fontWeight.medium,
    color: uiColor.text2,
    textTransform: "lowercase",
  },
  cardDescription: {
    fontSize: fontSize.xs,
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  cardTitleCount: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.normal,
    marginLeft: horizontalSpace.sm,
  },
  cardHeaderNoMargin: {
    marginBottom: 0,
  },
  tableEmptyCell: {
    paddingBottom: verticalSpace["6xl"],
    paddingTop: verticalSpace["6xl"],
    textAlign: "center",
  },
  usage: {
    fontFamily: fontFamily.mono,
    fontSize: "0.8125rem",
    whiteSpace: "pre",
    overflowX: "auto",
    padding: "1rem 1.25rem",
    borderRadius: "0.5rem",
    background: "rgba(0,0,0,0.05)",
    margin: 0,
  },
  highlightedSnippet: {
    flexGrow: 1,
    minWidth: 0,
  },
  usageContainer: {
    paddingTop: verticalSpace["2xl"],
  },
  statusMono: {
    fontFamily: fontFamily.mono,
    fontSize: "0.8125rem",
  },
  statusOk: {
    color: "rgb(38, 122, 70)",
  },
  statusPending: {
    color: "rgb(176, 109, 18)",
  },
  statusOff: {
    opacity: 0.6,
  },
});

const API_KEY_COLUMNS = [
  { id: "name", label: "Name" },
  { id: "prefix", label: "Key" },
  { id: "created", label: "Created" },
  { id: "lastUsed", label: "Last used" },
  { id: "status", label: "Status" },
  { id: "actions", label: "" },
];

const API_KEY_FULL_COLUMN = [{ id: "full", label: "" }];

type ApiKeyBodyRow = { kind: "key"; id: string; row: ApiKeyRow } | { kind: "empty"; id: string };

interface ApiKeyRow {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  expiresAt: string | null;
}

function showToast(title: string) {
  toasts.add({ title }, { timeout: 2400 });
}

function formatRelative(iso: string | null): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const ms = Date.now() - t;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function statusOf(row: {
  revokedAt: string | null;
  expiresAt: string | null;
}): "active" | "revoked" | "expired" {
  if (row.revokedAt) return "revoked";
  if (row.expiresAt && Date.parse(row.expiresAt) <= Date.now()) return "expired";
  return "active";
}

export function AccountSettings() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { data: session } = useQuery(getSessionQueryOptions);
  const { mode, setMode } = useThemeMode();

  const apiKeysQuery = useQuery(listMyApiKeysQueryOptions);
  const revokeM = useMutation(revokeMyApiKeyMutationOptions);
  const deleteM = useMutation(deleteMyApiKeyMutationOptions);
  const wipeM = useMutation(wipeMyDataMutationOptions);
  const resetM = useMutation(resetConnectionMutationOptions);

  const [wipeOpen, setWipeOpen] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);

  const onRevoke = (id: string, name: string) => {
    revokeM.mutate(
      { id },
      {
        onSuccess: () => {
          showToast(`${name}: revoked`);
          queryClient.invalidateQueries({ queryKey: listMyApiKeysQueryOptions.queryKey });
        },
        onError: (e) => showToast(e instanceof Error ? e.message : "Could not revoke"),
      },
    );
  };

  const onDelete = (id: string, name: string) => {
    deleteM.mutate(
      { id },
      {
        onSuccess: () => {
          showToast(`${name}: deleted`);
          queryClient.invalidateQueries({ queryKey: listMyApiKeysQueryOptions.queryKey });
        },
        onError: (e) => showToast(e instanceof Error ? e.message : "Could not delete"),
      },
    );
  };

  const onWipe = () => {
    wipeM.mutate(undefined, {
      onSuccess: (report) => {
        const pdsCount = Object.values(report.pdsDeletedByCollection).reduce((a, b) => a + b, 0);
        const parts = [
          `${pdsCount} PDS records`,
          `${report.appviewRemoved} indexed rows`,
          `${report.apiKeysRemoved} keys`,
        ];
        showToast(`Wiped: ${parts.join(" · ")}`);
        setWipeOpen(false);
        queryClient.invalidateQueries({ queryKey: listMyApiKeysQueryOptions.queryKey });
      },
      onError: (e) => showToast(e instanceof Error ? e.message : "Wipe failed"),
    });
  };

  const onReset = () => {
    resetM.mutate(undefined, {
      onSuccess: async () => {
        // The server fn cleared the auth cookie, so the browser is now
        // signed out. Send the user through a fresh login — that OAuth
        // handshake is what re-establishes a working write session.
        // Mirror the navbar logout teardown so no stale user-scoped
        // cache lingers.
        showToast("Connection reset — sign in again to finish");
        setResetOpen(false);
        clearChatStoreMemory();
        queryClient.setQueryData(getSessionQueryOptions.queryKey, null);
        await navigate({ to: "/login", search: { redirect: "/account" } });
        queryClient.clear();
        queryClient.setQueryData(getSessionQueryOptions.queryKey, null);
      },
      onError: (e) => showToast(e instanceof Error ? e.message : "Reset failed"),
    });
  };

  const user = session?.user;

  const keys = (apiKeysQuery.data?.keys ?? []) as ApiKeyRow[];
  const keyBodyItems: ApiKeyBodyRow[] =
    keys.length === 0
      ? [{ kind: "empty", id: "api-keys-empty" }]
      : keys.map((row) => ({ kind: "key", id: row.id, row }));

  const baseUrl = typeof window !== "undefined" ? `${window.location.origin}/api/v1` : "/api/v1";

  const [usageOpen, setUsageOpen] = useState(false);
  const [snippetLang, setSnippetLang] = useState<SnippetLang>("python");

  const snippetsByLang = useMemo<Record<SnippetLang, string>>(() => {
    const out = {} as Record<SnippetLang, string>;
    for (const l of SNIPPET_LANGS) out[l] = buildSnippet(l, baseUrl, "stub");
    return out;
  }, [baseUrl]);

  // Prefetch every language in parallel as soon as the usage dialog
  // opens, so switching tabs after that point reads from cache and
  // never flickers back to the unhighlighted fallback.
  const highlightResults = useQueries({
    queries: SNIPPET_LANGS.map((lang) => ({
      ...highlightCodeQueryOptions({
        code: snippetsByLang[lang],
        lang: lang === "curl" ? "bash" : lang,
      }),
      enabled: usageOpen,
    })),
  });

  const snippet = snippetsByLang[snippetLang];
  const highlightedHtml = highlightResults[SNIPPET_LANGS.indexOf(snippetLang)]?.data;

  return (
    <Page.Root variant="large" style={styles.root}>
      <Page.Header style={styles.header}>
        <Flex direction="column" gap="xl">
          <Heading1 style={styles.headingMono}>
            <span {...stylex.props(styles.titlePrompt)}>~/</span>account
          </Heading1>
          <div {...stylex.props(styles.metaRow)}>
            Manage how co/core looks, your API keys, and how this browser is signed in.
          </div>
        </Flex>
      </Page.Header>

      <div {...stylex.props(styles.sections)}>
        <Flex direction="column" gap="2xl">
          <Heading2>General</Heading2>
          <ProfileCard did={user?.did ?? null} />
          <Card size="md">
            <CardHeader hasBorder>
              <CardTitle style={styles.cardTitleMono}>Appearance</CardTitle>
              <CardDescription style={styles.cardDescription}>
                Choose how the console looks on this device.
              </CardDescription>
            </CardHeader>
            <CardBody>
              <Flex direction="column" gap="md">
                <LabelText>Theme</LabelText>
                <SegmentedControl
                  aria-label="Theme mode"
                  size="sm"
                  selectedKeys={new Set([mode])}
                  onSelectionChange={(selection) => {
                    const id = selection.values().next().value;
                    if (id === "light" || id === "dark" || id === "auto") setMode(id);
                  }}
                >
                  <SegmentedControlItem id="light">Light</SegmentedControlItem>
                  <SegmentedControlItem id="dark">Dark</SegmentedControlItem>
                  <SegmentedControlItem id="auto">Auto</SegmentedControlItem>
                </SegmentedControl>
              </Flex>
            </CardBody>
          </Card>
        </Flex>

        <Flex direction="column" gap="2xl">
          <Heading2>Balance</Heading2>
          <Alert variant="info" title="How tokens work">
            <Body>
              New members get a one-time grant; the network refreshes active members weekly; the
              treasury redistributes a monthly patronage rebate to everyone who used the system. See
              the{" "}
              <Link to="/blog/$slug" params={{ slug: "hello-world" }}>
                hello-world post
              </Link>{" "}
              for the full mechanics.
            </Body>
          </Alert>
          <TokenBalanceCard did={user?.did ?? null} />
        </Flex>

        <Flex direction="column" gap="2xl">
          <Heading2>Security</Heading2>
          <Card size="md">
            <CardHeader hasBorder style={styles.cardHeaderNoMargin}>
              <CardTitle style={styles.cardTitleMono}>
                API keys
                <span {...stylex.props(styles.cardTitleCount)}>
                  {keys.length} key{keys.length === 1 ? "" : "s"}
                </span>
              </CardTitle>
              <CardHeaderAction>
                <Flex direction="row" align="center" gap="sm">
                  <Dialog
                    isOpen={usageOpen}
                    onOpenChange={setUsageOpen}
                    trigger={
                      <IconButton variant="tertiary" size="sm" label="Show usage example">
                        <CircleHelp size={16} />
                      </IconButton>
                    }
                  >
                    <DialogHeader>Using your API key</DialogHeader>
                    <DialogBody>
                      <DialogDescription>
                        Drop-in replacement for the OpenAI API: any OpenAI SDK works by changing the
                        base URL to <InlineCode>{baseUrl}</InlineCode>. Full reference at{" "}
                        <Link to="/docs/inference">/docs/inference</Link>.
                      </DialogDescription>
                      <Flex direction="column" gap="4xl" style={styles.usageContainer}>
                        <SegmentedControl
                          aria-label="SDK language"
                          size="sm"
                          selectedKeys={new Set([snippetLang])}
                          onSelectionChange={(selection) => {
                            const id = selection.values().next().value;
                            if (typeof id !== "string") return;
                            if ((SNIPPET_LANGS as readonly string[]).includes(id)) {
                              setSnippetLang(id as SnippetLang);
                            }
                          }}
                        >
                          {SNIPPET_LANGS.map((id) => (
                            <SegmentedControlItem key={id} id={id}>
                              {SNIPPET_LANG_LABELS[id]}
                            </SegmentedControlItem>
                          ))}
                        </SegmentedControl>
                        <Flex direction="row" align="start" gap="sm">
                          {highlightedHtml ? (
                            <div
                              {...stylex.props(styles.highlightedSnippet)}
                              dangerouslySetInnerHTML={{ __html: highlightedHtml }}
                            />
                          ) : (
                            <pre {...stylex.props(styles.usage)}>{snippet}</pre>
                          )}
                          <CopyToClipboardButton text={snippet} />
                        </Flex>
                      </Flex>
                    </DialogBody>
                  </Dialog>
                  <CreateApiKeyButton label="+ New API key" />
                </Flex>
              </CardHeaderAction>
              <CardDescription style={styles.cardDescription}>
                OpenAI-compatible. Used to call{" "}
                <InlineCode>POST /api/v1/chat/completions</InlineCode> from any OpenAI SDK.
              </CardDescription>
            </CardHeader>
            {apiKeysQuery.isError ? (
              <CardBody>
                <Alert variant="critical" title="Could not load API keys">
                  <Body>
                    {apiKeysQuery.error instanceof Error
                      ? apiKeysQuery.error.message
                      : String(apiKeysQuery.error)}
                  </Body>
                </Alert>
              </CardBody>
            ) : null}
            <Table aria-label="API keys" size="sm">
              <TableHeader columns={API_KEY_COLUMNS}>
                {(col) => <TableColumn>{col.label}</TableColumn>}
              </TableHeader>
              <TableBody items={keyBodyItems}>
                {(item) => {
                  if (item.kind === "empty") {
                    return (
                      <TableRow columns={API_KEY_FULL_COLUMN} id={item.id}>
                        {() => (
                          <TableCell colSpan={API_KEY_COLUMNS.length} style={styles.tableEmptyCell}>
                            <LabelText variant="secondary">
                              No API keys yet. Create one to call co/core from an OpenAI SDK.
                            </LabelText>
                          </TableCell>
                        )}
                      </TableRow>
                    );
                  }
                  const row = item.row;
                  const status = statusOf(row);
                  return (
                    <TableRow columns={API_KEY_COLUMNS} id={row.id}>
                      {(col) => {
                        if (col.id === "name") return <TableCell>{row.name}</TableCell>;
                        if (col.id === "prefix")
                          return (
                            <TableCell>
                              <InlineCode>{row.prefix}…</InlineCode>
                            </TableCell>
                          );
                        if (col.id === "created")
                          return <TableCell>{formatRelative(row.createdAt)}</TableCell>;
                        if (col.id === "lastUsed")
                          return <TableCell>{formatRelative(row.lastUsedAt)}</TableCell>;
                        if (col.id === "status") return <TableCell>{status}</TableCell>;
                        return (
                          <TableCell>
                            {status === "active" ? (
                              <Button
                                variant="critical"
                                size="sm"
                                isDisabled={revokeM.isPending}
                                onPress={() => onRevoke(row.id, row.name)}
                              >
                                Revoke
                              </Button>
                            ) : (
                              <Button
                                variant="secondary"
                                size="sm"
                                isDisabled={deleteM.isPending}
                                onPress={() => onDelete(row.id, row.name)}
                              >
                                Delete
                              </Button>
                            )}
                          </TableCell>
                        );
                      }}
                    </TableRow>
                  );
                }}
              </TableBody>
            </Table>
          </Card>
          <Card size="md">
            <CardHeader hasBorder>
              <CardTitle style={styles.cardTitleMono}>Reset connection</CardTitle>
              <CardDescription style={styles.cardDescription}>
                Stuck with 401s from your agent? Rebuild your sign-in and keys without touching any
                of your data.
              </CardDescription>
            </CardHeader>
            <CardBody>
              <Dialog
                isOpen={resetOpen}
                onOpenChange={setResetOpen}
                trigger={
                  <Button variant="secondary" size="sm">
                    Reset connection
                  </Button>
                }
              >
                <DialogHeader>Reset your co/core connection?</DialogHeader>
                <DialogBody>
                  <DialogDescription>
                    Revokes every API key you&apos;ve minted and drops your stored ATProto write
                    session, then signs you out so you can sign back in fresh. This fixes a wedged
                    agent (401 <InlineCode>invalid API key</InlineCode> /{" "}
                    <InlineCode>AuthRequired</InlineCode>) — none of your{" "}
                    <InlineCode>dev.cocore.*</InlineCode> PDS records, receipts, or indexed history
                    are touched. Quit any running co/core agents first, then after you sign back in
                    run <InlineCode>cocore agent pair</InlineCode> to re-link your machine.
                  </DialogDescription>
                </DialogBody>
                <DialogFooter>
                  <Flex direction="row" gap="md">
                    <Button
                      variant="secondary"
                      size="sm"
                      onPress={() => setResetOpen(false)}
                      isDisabled={resetM.isPending}
                    >
                      Cancel
                    </Button>
                    <Button
                      variant="primary"
                      size="sm"
                      isDisabled={resetM.isPending}
                      onPress={onReset}
                    >
                      {resetM.isPending ? "Resetting…" : "Reset connection"}
                    </Button>
                  </Flex>
                </DialogFooter>
              </Dialog>
            </CardBody>
          </Card>
          <Card size="md">
            <CardHeader hasBorder>
              <CardTitle style={styles.cardTitleMono}>Danger zone</CardTitle>
              <CardDescription style={styles.cardDescription}>
                Irreversible operations on your co/core data and PDS records.
              </CardDescription>
            </CardHeader>
            <CardBody>
              <Dialog
                isOpen={wipeOpen}
                onOpenChange={setWipeOpen}
                trigger={
                  <Button variant="critical" size="sm">
                    Wipe all my data
                  </Button>
                }
              >
                <DialogHeader>Wipe all your co/core data?</DialogHeader>
                <DialogBody>
                  <DialogDescription>
                    Deletes every <InlineCode>dev.cocore.compute.*</InlineCode> record on your PDS
                    (provider, attestation, job, paymentAuthorization, receipt, settlement, dispute,
                    exchangeAttestation, exchangePolicy, termsAcceptance) and clears their indexed
                    rows on co/core's AppView, and deletes every API key you've minted. Your sign-in
                    stays — you'll just be back to a freshly-paired-from-scratch state. This is
                    irreversible.
                  </DialogDescription>
                </DialogBody>
                <DialogFooter>
                  <Flex direction="row" gap="md">
                    <Button
                      variant="secondary"
                      size="sm"
                      onPress={() => setWipeOpen(false)}
                      isDisabled={wipeM.isPending}
                    >
                      Cancel
                    </Button>
                    <Button
                      variant="critical"
                      size="sm"
                      isDisabled={wipeM.isPending}
                      onPress={onWipe}
                    >
                      {wipeM.isPending ? "Wiping…" : "Wipe everything"}
                    </Button>
                  </Flex>
                </DialogFooter>
              </Dialog>
            </CardBody>
          </Card>
        </Flex>
      </div>
    </Page.Root>
  );
}
