"use client";

import * as stylex from "@stylexjs/stylex";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link as RouterLink } from "@tanstack/react-router";
import { useState } from "react";

import { Button } from "@/design-system/button";
import { Card, CardBody, CardHeader, CardTitle } from "@/design-system/card";
import { CopyToClipboardButton } from "@/design-system/copy-to-clipboard-button";
import { Dialog } from "@/design-system/dialog";
import { Flex } from "@/design-system/flex";
import { Page } from "@/design-system/page/index.tsx";
import { Alert } from "@/design-system/alert";
import {
  criticalColor,
  primaryColor,
  successColor,
  uiColor,
  warningColor,
} from "@/design-system/theme/color.stylex";
import { breakpoints } from "@/design-system/theme/media-queries.stylex";
import { radius } from "@/design-system/theme/radius.stylex";
import { ui } from "@/design-system/theme/semantic-color.stylex";
import { gap, horizontalSpace, verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import {
  fontFamily,
  fontSize,
  fontWeight,
  lineHeight,
} from "@/design-system/theme/typography.stylex";
import { toasts } from "@/design-system/toast";
import { Heading1, Heading4, InlineCode, LabelText, SmallBody } from "@/design-system/typography";

import { Goober } from "@/components/Goober.tsx";
import {
  AdvancedSettingsDialogContent,
  ManageModelsDialogContent,
  RenameMachineDialogContent,
} from "@/components/machines/MachinesDashboard.tsx";
import {
  listMyMachinesQueryOptions,
  myMachineDetailQueryOptions,
  setMyProviderActiveMutationOptions,
  setMyProviderDesiredModelsMutationOptions,
  setMyProviderDesiredTierMutationOptions,
  setMyProviderMachineLabelMutationOptions,
  setMyProviderProBonoMutationOptions,
  setMyProviderShareLocationMutationOptions,
  setMyProviderToolCallsMutationOptions,
} from "@/components/machines/machines.functions.ts";
import type { MachineWorkItem } from "@/components/machines/machines.server.ts";
import {
  NetworkStandingBadge,
  ProBonoBadge,
  RegionFlag,
} from "@/components/machines/MachineBadges.tsx";
import { formatTokens } from "@/lib/token-display.ts";

import { advisorUnreachable, type Machine, machineStateLabel } from "./machines-data.ts";

const styles = stylex.create({
  root: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["2xl"],
    fontFamily: fontFamily.mono,
    maxWidth: "1100px",
    marginLeft: "auto",
    marginRight: "auto",
  },
  back: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    textDecorationLine: {
      default: "none",
      ":hover": "underline",
    },
    width: "fit-content",
  },
  headingRow: {
    alignItems: "center",
    display: "flex",
    flexWrap: "wrap",
    gap: horizontalSpace.lg,
  },
  headingMono: {
    fontFamily: fontFamily.mono,
  },
  titlePrompt: {
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  metaRow: {
    alignItems: "center",
    color: uiColor.text1,
    display: "flex",
    flexWrap: "wrap",
    fontSize: fontSize.sm,
    gap: horizontalSpace.lg,
    lineHeight: lineHeight.lg,
    // Long identifiers (DID, rkey) must wrap rather than push the row wide.
    overflowWrap: "anywhere",
    minWidth: 0,
  },
  metaSep: {
    color: uiColor.border2,
  },
  statusChip: {
    alignItems: "center",
    display: "inline-flex",
    gap: horizontalSpace.sm,
  },
  statusDot: {
    borderRadius: radius.full,
    flexShrink: 0,
    height: 8,
    width: 8,
  },
  statusRunning: { backgroundColor: successColor.solid1 },
  statusProvisioning: { backgroundColor: warningColor.solid1 },
  statusIdle: { backgroundColor: primaryColor.solid2 },
  statusPaused: { backgroundColor: uiColor.solid2 },
  statusOffline: { backgroundColor: criticalColor.solid1 },
  statusFault: { backgroundColor: criticalColor.solid1 },
  controls: {
    display: "flex",
    flexWrap: "wrap",
    gap: gap.sm,
  },
  kvGrid: {
    columnGap: horizontalSpace.lg,
    display: "grid",
    fontSize: fontSize.sm,
    // Stack label/value vertically on narrow screens so long values
    // (model lists) never force horizontal scroll; switch to the
    // two-column key/value layout at >=40rem.
    gridTemplateColumns: {
      default: "1fr",
      [breakpoints.sm]: "140px 1fr",
    },
    rowGap: {
      default: verticalSpace.xs,
      [breakpoints.sm]: verticalSpace.sm,
    },
  },
  kvDt: { color: uiColor.text1 },
  kvDd: { color: uiColor.text2, margin: 0, overflowWrap: "anywhere" },
  metricGrid: {
    display: "grid",
    gap: gap.lg,
    gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
  },
  metricCell: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    padding: horizontalSpace.lg,
  },
  metricVal: {
    fontSize: fontSize.lg,
    fontVariantNumeric: "tabular-nums",
    marginTop: verticalSpace.xs,
  },
  cardTitle: {
    fontSize: fontSize.base,
    fontWeight: fontWeight.medium,
    color: uiColor.text2,
    textTransform: "lowercase",
  },
  timelineList: {
    display: "flex",
    flexDirection: "column",
    listStyle: "none",
    margin: 0,
    padding: 0,
  },
  timelineItem: {
    alignItems: "baseline",
    borderTopColor: uiColor.border1,
    borderTopStyle: "dashed",
    borderTopWidth: 1,
    display: "grid",
    gap: horizontalSpace.lg,
    gridTemplateColumns: {
      default: "1fr",
      [breakpoints.sm]: "180px 1fr auto",
    },
    paddingBottom: verticalSpace.md,
    paddingTop: verticalSpace.md,
  },
  timelineFirst: {
    borderTopWidth: 0,
  },
  tlWhen: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontVariantNumeric: "tabular-nums",
  },
  tlMid: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace.xs,
    minWidth: 0,
  },
  tlModel: {
    color: uiColor.text2,
    fontSize: fontSize.sm,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  // "run by @handle" — links to the requester's profile. Muted so it reads
  // as secondary metadata under the model, brightens + underlines on hover.
  tlWho: {
    color: {
      default: uiColor.text1,
      ":hover": uiColor.text2,
    },
    fontSize: fontSize.xs,
    overflow: "hidden",
    textDecorationLine: {
      default: "none",
      ":hover": "underline",
    },
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
    width: "fit-content",
  },
  tlTokens: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontVariantNumeric: "tabular-nums",
    textAlign: "right",
  },
  tlTokensStrong: {
    color: uiColor.text2,
  },
  empty: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
    paddingBottom: verticalSpace["4xl"],
    paddingTop: verticalSpace["4xl"],
    textAlign: "center",
  },
  hiddenTrigger: {
    height: 0,
    opacity: 0,
    pointerEvents: "none",
    position: "absolute",
    width: 0,
  },
  spark: {
    display: "block",
    marginTop: verticalSpace.sm,
  },
  // Decorative goobie perched on the Hardware card's top-right corner. The
  // card is made position:relative + overflow:visible so the bird can hang
  // off the edge into the page's right margin.
  hwCardRel: {
    position: "relative",
    overflow: "visible",
  },
  hwGoober: {
    top: "-2.9rem",
    right: "1.75rem",
    opacity: 0.95,
  },
});

const STATUS_STYLE: Record<Machine["state"], keyof typeof styles> = {
  running: "statusRunning",
  provisioning: "statusProvisioning",
  idle: "statusIdle",
  paused: "statusPaused",
  offline: "statusOffline",
};

function showToast(title: string) {
  toasts.add({ title }, { timeout: 2400 });
}

/** Compact a DID for display when we couldn't resolve it to a handle:
 *  `did:plc:abc…xyz`. Keeps the method prefix so it's still recognizable. */
function abbrevDid(did: string): string {
  const t = did.trim();
  if (t.length <= 24) return t;
  return `${t.slice(0, 16)}…${t.slice(-4)}`;
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Tiny tokens/day sparkline over the timeline's window. Buckets receipts
 *  into UTC days and draws a polyline; purely decorative, omitted when
 *  there's nothing to show. */
function TokensPerDaySpark({ items }: { items: MachineWorkItem[] }) {
  if (items.length < 2) return null;
  const MS_DAY = 86_400_000;
  const now = Date.now();
  const days = 14;
  const buckets = Array.from({ length: days }, () => 0);
  for (const it of items) {
    const ageDays = Math.floor((now - it.completedMs) / MS_DAY);
    if (ageDays < 0 || ageDays >= days) continue;
    const idx = days - 1 - ageDays;
    buckets[idx] = (buckets[idx] ?? 0) + it.priceTokens;
  }
  const hi = Math.max(1, ...buckets);
  const w = 220;
  const h = 36;
  const denom = Math.max(1, buckets.length - 1);
  const pts = buckets.map((v, i) => `${(i / denom) * w},${h - (v / hi) * (h - 2) - 1}`).join(" ");
  return (
    <svg {...stylex.props(styles.spark)} width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden>
      <polyline points={pts} fill="none" stroke={successColor.solid1} strokeWidth="1.5" />
    </svg>
  );
}

export function MachineDetail({ rkey }: { rkey: string }) {
  const queryClient = useQueryClient();
  const detailQ = useQuery(myMachineDetailQueryOptions(rkey));

  const [manageModelsOpen, setManageModelsOpen] = useState(false);
  const [renameOpen, setRenameOpen] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: myMachineDetailQueryOptions(rkey).queryKey });
    void queryClient.invalidateQueries({ queryKey: listMyMachinesQueryOptions.queryKey });
  };

  const activeM = useMutation({
    ...setMyProviderActiveMutationOptions,
    onSuccess: invalidate,
  });
  const modelsM = useMutation({
    ...setMyProviderDesiredModelsMutationOptions,
    onSuccess: () => {
      invalidate();
      setManageModelsOpen(false);
    },
  });
  const renameM = useMutation({
    ...setMyProviderMachineLabelMutationOptions,
    onSuccess: () => {
      invalidate();
      setRenameOpen(false);
    },
  });
  // Optional, per-machine confidential opt-in. Writes the owner's INTENT
  // (desiredTier) to the provider record; the agent reconciles toward it and
  // only publishes the higher achieved tier once earned. Opting out reverts the
  // machine to exactly its prior behavior — nothing here breaks serving.
  const desiredTierM = useMutation({
    ...setMyProviderDesiredTierMutationOptions,
    onSuccess: invalidate,
  });
  // Advanced, per-machine owner intents. Both write to the provider record;
  // the agent re-derives behavior on its next serve. Share-location toggles
  // the coarse country opt-in; pro-bono sets (or clears, via null) the
  // free-serving policy. Same invalidate-on-success as every control above.
  const shareLocationM = useMutation({
    ...setMyProviderShareLocationMutationOptions,
    onSuccess: invalidate,
  });
  const proBonoM = useMutation({
    ...setMyProviderProBonoMutationOptions,
    onSuccess: invalidate,
  });
  const toolCallsM = useMutation({
    ...setMyProviderToolCallsMutationOptions,
    onSuccess: invalidate,
  });

  const machine = detailQ.data?.machine ?? null;
  const timeline = detailQ.data?.timeline ?? [];
  const appviewError = detailQ.data?.appviewError ?? null;

  if (!machine) {
    return (
      <Page.Root style={styles.root}>
        <RouterLink to="/machines" {...stylex.props(styles.back)}>
          ← back to machines
        </RouterLink>
        <Alert variant="critical" title="Machine not found">
          <SmallBody>
            No machine with record key <InlineCode>{rkey}</InlineCode> belongs to your account, or
            it has been unpaired.
          </SmallBody>
        </Alert>
      </Page.Root>
    );
  }

  const m = machine;
  const errToast = (e: unknown) => showToast(e instanceof Error ? e.message : "Request failed");

  return (
    <Page.Root style={styles.root}>
      <RouterLink to="/machines" {...stylex.props(styles.back)}>
        ← back to machines
      </RouterLink>

      {appviewError ? (
        <Alert variant="critical" title="AppView partial error">
          <SmallBody>{appviewError}</SmallBody>
        </Alert>
      ) : null}

      <Flex direction="column" gap="md">
        <div {...stylex.props(styles.headingRow)}>
          <Heading1 style={styles.headingMono}>
            <span {...stylex.props(styles.titlePrompt)}>~/machines/</span>
            {m.alias}
          </Heading1>
          <span {...stylex.props(styles.statusChip)}>
            <span
              {...stylex.props(
                styles.statusDot,
                styles[m.faultReason ? "statusFault" : STATUS_STYLE[m.state]],
              )}
            />
            <LabelText variant="secondary">
              {m.faultReason ? "fault" : machineStateLabel(m.state)}
            </LabelText>
          </span>
          <RegionFlag region={m.region} />
          <ProBonoBadge mode={m.proBonoMode} />
          <NetworkStandingBadge m={m} />
        </div>
        <div {...stylex.props(styles.metaRow)}>
          <span>{m.gpu}</span>
          <span {...stylex.props(styles.metaSep)}>·</span>
          <span>
            rkey <InlineCode>{m.id}</InlineCode>
            <CopyToClipboardButton text={m.id} />
          </span>
          {detailQ.data?.did ? (
            <>
              <span {...stylex.props(styles.metaSep)}>·</span>
              <span>
                <InlineCode>{detailQ.data.did}</InlineCode>
                <CopyToClipboardButton text={detailQ.data.did} />
              </span>
            </>
          ) : null}
        </div>
      </Flex>

      {m.faultReason ? (
        <Alert variant="critical" title="Inference engine didn't start">
          <Flex direction="column" gap="md">
            <SmallBody>{m.faultReason}</SmallBody>
            {m.faultModels && m.faultModels.length > 0 ? (
              <SmallBody variant="secondary">
                Affected model{m.faultModels.length > 1 ? "s" : ""}:{" "}
                <InlineCode>{m.faultModels.join(", ")}</InlineCode>
              </SmallBody>
            ) : null}
          </Flex>
        </Alert>
      ) : null}

      {/* The agent publishes its record with `provisioning: true` the moment
          serving starts, then spends the next stretch downloading model
          weights (often several GB) before it can register with the network.
          Say so explicitly — a machine that "shows up but isn't under its
          model" on the models page looks broken without this. */}
      {!m.faultReason && m.state === "provisioning" ? (
        <Alert variant="info" title="Preparing — downloading models">
          <SmallBody>
            This machine is downloading its model weights (often several GB) and will start serving
            automatically when the download finishes. It appears under its models on the models page
            only once it's serving — typically a few minutes on a fast connection.
          </SmallBody>
        </Alert>
      ) : null}

      {advisorUnreachable(m) ? (
        <Alert variant="warning" title="Serving locally — can't reach the co/core network">
          <Flex direction="column" gap="md">
            <SmallBody>
              {m.advisorFaultReason ??
                "This machine's record says it's serving, but the network currently holds no live connection to it — no jobs will reach it until it reconnects. It usually rejoins on its own within a minute; if this persists, the connection is likely being blocked."}
            </SmallBody>
            <SmallBody variant="secondary">
              Common causes: a VPN or proxy on the machine's network, a firewall that blocks
              outbound WebSocket (wss) connections, or captive/guest Wi-Fi that filters them. Try a
              different network or allow secure WebSocket traffic, then the machine rejoins
              automatically — no restart needed.
            </SmallBody>
            {m.advisorFaultCode ? (
              <SmallBody variant="secondary">
                Fault code: <InlineCode>{m.advisorFaultCode}</InlineCode>
                {m.advisorFaultAt ? <> · observed {formatWhen(m.advisorFaultAt)}</> : null}
              </SmallBody>
            ) : null}
          </Flex>
        </Alert>
      ) : null}

      <div {...stylex.props(styles.controls)}>
        {(m.state === "idle" || m.state === "running") && (
          <Button
            variant="outline"
            size="sm"
            isDisabled={activeM.isPending}
            onPress={() =>
              activeM.mutate(
                { rkey: m.id, active: false },
                { onSuccess: () => showToast(`${m.alias}: paused`), onError: errToast },
              )
            }
          >
            Pause serving
          </Button>
        )}
        {m.state === "paused" && (
          <Button
            variant="outline"
            size="sm"
            isDisabled={activeM.isPending}
            onPress={() =>
              activeM.mutate(
                { rkey: m.id, active: true },
                { onSuccess: () => showToast(`${m.alias}: resumed`), onError: errToast },
              )
            }
          >
            Resume serving
          </Button>
        )}
        <Button variant="outline" size="sm" onPress={() => setManageModelsOpen(true)}>
          Manage models…
        </Button>
        <Button variant="outline" size="sm" onPress={() => setRenameOpen(true)}>
          Rename…
        </Button>
        <Button variant="outline" size="sm" onPress={() => setAdvancedOpen(true)}>
          Advanced settings…
        </Button>
      </div>

      <Card size="md" style={styles.hwCardRel}>
        <Goober name="bird" size={104} style={styles.hwGoober} />
        <CardHeader hasBorder>
          <CardTitle style={styles.cardTitle}>Hardware</CardTitle>
        </CardHeader>
        <CardBody>
          <dl {...stylex.props(styles.kvGrid)}>
            <dt {...stylex.props(styles.kvDt)}>Chip</dt>
            <dd {...stylex.props(styles.kvDd)}>
              {m.gpu}
              {m.chipMeta ? ` · ${m.chipMeta}` : ""}
            </dd>
            <dt {...stylex.props(styles.kvDt)}>RAM</dt>
            <dd {...stylex.props(styles.kvDd)}>{m.ram}GB</dd>
            <dt {...stylex.props(styles.kvDt)}>Paired</dt>
            <dd {...stylex.props(styles.kvDd)}>{m.pairedAt}</dd>
            {m.trustLevel ? (
              <>
                <dt {...stylex.props(styles.kvDt)}>Attestation</dt>
                <dd {...stylex.props(styles.kvDd)}>
                  {m.trustLevel === "hardware-attested"
                    ? "Hardware-attested (experimental) — genuine Apple hardware, SIP verified"
                    : "Self-attested (software)"}
                </dd>
              </>
            ) : null}
            <dt {...stylex.props(styles.kvDt)}>Confidential tier</dt>
            <dd {...stylex.props(styles.kvDd)}>
              {m.tier === "attested-confidential"
                ? "🔒 Confidential (experimental) — aims to keep prompts unreadable to the operator"
                : m.desiredTier === "attested-confidential"
                  ? "Upgrade pending — opted in; finishing on the next serve"
                  : "Best-effort — fast, but the operator can read prompts"}
            </dd>
            {m.verifiedTierReason ? (
              <>
                <dt {...stylex.props(styles.kvDt)}>Tier capped</dt>
                <dd {...stylex.props(styles.kvDd)}>⚠️ {m.verifiedTierReason}</dd>
              </>
            ) : null}
            <dt {...stylex.props(styles.kvDt)}>Supported models</dt>
            <dd {...stylex.props(styles.kvDd)}>
              {m.supportedModels && m.supportedModels.length > 0
                ? m.supportedModels.join(", ")
                : "—"}
            </dd>
            <dt {...stylex.props(styles.kvDt)}>Pinned models</dt>
            <dd {...stylex.props(styles.kvDd)}>
              {m.desiredModels && m.desiredModels.length > 0
                ? m.desiredModels.join(", ")
                : "not pinned — serving local default"}
            </dd>
          </dl>
          {/* Optional confidential upgrade — per machine, never forced. Opting
              in writes the owner's intent (desiredTier); the agent earns the
              tier and only then does it change anything. Opting out reverts. */}
          <div style={{ marginTop: 14, display: "flex", flexDirection: "column", gap: 8 }}>
            {m.desiredTier === "attested-confidential" ? (
              <>
                <LabelText variant="secondary">
                  Opted into confidential. The machine earns it once it runs the measured native
                  build under a hardware-attested posture; until then it keeps serving best-effort.
                </LabelText>
                <Button
                  variant="secondary"
                  size="sm"
                  isDisabled={desiredTierM.isPending}
                  onClick={() => desiredTierM.mutate({ rkey: m.id, tier: "best-effort" })}
                >
                  Turn off confidential
                </Button>
              </>
            ) : (
              <>
                <LabelText variant="secondary">
                  Optional: upgrade this machine to the confidential tier, which aims to keep
                  prompts unreadable to the operator. It&apos;s experimental and not independently
                  audited, and it won&apos;t change how this machine serves today — you can turn it
                  off anytime.
                </LabelText>
                <Button
                  variant="primary"
                  size="sm"
                  isDisabled={desiredTierM.isPending}
                  onClick={() => desiredTierM.mutate({ rkey: m.id, tier: "attested-confidential" })}
                >
                  Upgrade to confidential…
                </Button>
              </>
            )}
          </div>
        </CardBody>
      </Card>

      <Card size="md">
        <CardHeader hasBorder>
          <CardTitle style={styles.cardTitle}>Earnings (index)</CardTitle>
        </CardHeader>
        <CardBody>
          <div {...stylex.props(styles.metricGrid)}>
            <div {...stylex.props(styles.metricCell)}>
              <LabelText variant="secondary">24h</LabelText>
              <div {...stylex.props(ui.text, styles.metricVal)}>
                {formatTokens(m.earnings24h)} tk
              </div>
            </div>
            <div {...stylex.props(styles.metricCell)}>
              <LabelText variant="secondary">7d</LabelText>
              <div {...stylex.props(ui.text, styles.metricVal)}>
                {formatTokens(m.earnings7d)} tk
              </div>
            </div>
            <div {...stylex.props(styles.metricCell)}>
              <LabelText variant="secondary">Lifetime</LabelText>
              <div {...stylex.props(ui.text, styles.metricVal)}>
                {formatTokens(m.earningsLifetime)} tk
              </div>
            </div>
            <div {...stylex.props(styles.metricCell)}>
              <LabelText variant="secondary">Jobs (index est.)</LabelText>
              <div {...stylex.props(ui.text, styles.metricVal)}>
                {m.jobsCompleted.toLocaleString()}
              </div>
            </div>
          </div>
        </CardBody>
      </Card>

      <Card size="md">
        <CardHeader hasBorder>
          <Flex direction="column" gap="xs">
            <CardTitle style={styles.cardTitle}>Work timeline</CardTitle>
            <SmallBody variant="secondary">
              Receipts this machine served, attributed by attestation · newest first ·{" "}
              {timeline.length} shown
            </SmallBody>
          </Flex>
        </CardHeader>
        <CardBody>
          <TokensPerDaySpark items={timeline} />
          {timeline.length === 0 ? (
            <div {...stylex.props(styles.empty)}>
              No attributed receipts yet. Once this machine serves a job, its receipts appear here.
            </div>
          ) : (
            <ul {...stylex.props(styles.timelineList)}>
              {timeline.map((it, i) => (
                <li
                  key={it.rkey}
                  {...stylex.props(styles.timelineItem, i === 0 && styles.timelineFirst)}
                >
                  <span {...stylex.props(styles.tlWhen)}>{formatWhen(it.completedAt)}</span>
                  <div {...stylex.props(styles.tlMid)}>
                    <Heading4 style={styles.tlModel} title={it.model}>
                      {it.model}
                    </Heading4>
                    {it.requester ? (
                      <RouterLink
                        to="/u/$identifier"
                        params={{ identifier: it.requesterHandle ?? it.requester }}
                        {...stylex.props(styles.tlWho)}
                        title={it.requesterDisplayName ?? it.requesterHandle ?? it.requester}
                      >
                        run by{" "}
                        {it.requesterHandle ? `@${it.requesterHandle}` : abbrevDid(it.requester)}
                      </RouterLink>
                    ) : null}
                  </div>
                  <span {...stylex.props(styles.tlTokens)}>
                    <span {...stylex.props(styles.tlTokensStrong)}>
                      {formatTokens(it.priceTokens)} tk
                    </span>
                    {it.tokensIn + it.tokensOut > 0
                      ? ` · ${it.tokensIn} in / ${it.tokensOut} out`
                      : ""}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>

      <Dialog
        isOpen={manageModelsOpen}
        onOpenChange={setManageModelsOpen}
        trigger={
          <button type="button" {...stylex.props(styles.hiddenTrigger)} tabIndex={-1} aria-hidden />
        }
      >
        <ManageModelsDialogContent
          machine={m}
          isPending={modelsM.isPending}
          onCancel={() => setManageModelsOpen(false)}
          onSave={(updated) =>
            modelsM.mutate(
              { rkey: m.id, models: updated },
              {
                onSuccess: () => showToast(`${m.alias}: models updated`),
                onError: (e) =>
                  showToast(e instanceof Error ? e.message : "Could not update models"),
              },
            )
          }
        />
      </Dialog>

      <Dialog
        isOpen={renameOpen}
        onOpenChange={setRenameOpen}
        trigger={
          <button type="button" {...stylex.props(styles.hiddenTrigger)} tabIndex={-1} aria-hidden />
        }
      >
        <RenameMachineDialogContent
          machine={m}
          isPending={renameM.isPending}
          onCancel={() => setRenameOpen(false)}
          onSave={(label) =>
            renameM.mutate(
              { rkey: m.id, label },
              {
                onSuccess: () => showToast(`${m.alias}: renamed to “${label}”`),
                onError: (e) =>
                  showToast(e instanceof Error ? e.message : "Could not rename machine"),
              },
            )
          }
        />
      </Dialog>

      <Dialog
        isOpen={advancedOpen}
        onOpenChange={setAdvancedOpen}
        trigger={
          <button type="button" {...stylex.props(styles.hiddenTrigger)} tabIndex={-1} aria-hidden />
        }
      >
        <AdvancedSettingsDialogContent
          key={m.id}
          machine={m}
          isSharePending={shareLocationM.isPending}
          isProBonoPending={proBonoM.isPending}
          isToolCallsPending={toolCallsM.isPending}
          onShareLocation={(share) =>
            shareLocationM.mutate(
              { rkey: m.id, share },
              {
                onSuccess: () =>
                  showToast(
                    share
                      ? `${m.alias}: sharing country on the next serve`
                      : `${m.alias}: country sharing off`,
                  ),
                onError: (e) =>
                  showToast(e instanceof Error ? e.message : "Could not update country sharing"),
              },
            )
          }
          onToolCalls={(enabled) =>
            toolCallsM.mutate(
              { rkey: m.id, enabled },
              {
                onSuccess: () =>
                  showToast(
                    enabled
                      ? `${m.alias}: tool calling on for top models on the next serve`
                      : `${m.alias}: tool calling off`,
                  ),
                onError: (e) =>
                  showToast(e instanceof Error ? e.message : "Could not update tool calling"),
              },
            )
          }
          onSaveProBono={(policy) =>
            // mutateAsync so the dialog can await the write and roll its
            // optimistic state back if it rejects.
            proBonoM.mutateAsync(
              { rkey: m.id, policy },
              {
                onSuccess: () =>
                  showToast(
                    policy === null
                      ? `${m.alias}: pro bono off`
                      : policy.mode === "any"
                        ? `${m.alias}: serving everyone pro bono`
                        : `${m.alias}: pro bono updated`,
                  ),
                onError: (e) =>
                  showToast(e instanceof Error ? e.message : "Could not update pro bono"),
              },
            )
          }
          onClose={() => setAdvancedOpen(false)}
        />
      </Dialog>
    </Page.Root>
  );
}
