"use client";

import * as stylex from "@stylexjs/stylex";
import { useMutation, useQuery, type UseMutationResult } from "@tanstack/react-query";
import { useMemo, useState, type ReactNode } from "react";

import {
  getReceiptsAppviewQueryOptions,
  getSettlementsAppviewQueryOptions,
  listProvidersAppviewQueryOptions,
  verifyReceiptAppviewMutationOptions,
  verifySettlementAppviewMutationOptions,
} from "@/integrations/appview/appview.functions.ts";
import type { JsonValue } from "@/integrations/appview/appview.server.ts";
import { getSessionQueryOptions } from "@/integrations/auth/session.functions.ts";
import { explorerLayout, explorerSectionStyles } from "@/components/explorer/explorer.stylex.ts";
import type { AppviewIndexedRecordEnriched } from "@/integrations/appview/appview.functions.ts";
import { Alert } from "@/design-system/alert";
import { Badge } from "@/design-system/badge";
import { Avatar } from "@/design-system/avatar";
import { Button } from "@/design-system/button";
import {
  Dialog,
  DialogBody,
  DialogDescription,
  DialogFooter,
  DialogHeader,
} from "@/design-system/dialog";
import { Flex } from "@/design-system/flex";
import { TextField } from "@/design-system/text-field";
import { uiColor } from "@/design-system/theme/color.stylex";
import { breakpoints } from "@/design-system/theme/media-queries.stylex";
import { radius } from "@/design-system/theme/radius.stylex";
import { gap, verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import {
  fontFamily,
  fontSize,
  fontWeight,
  lineHeight,
} from "@/design-system/theme/typography.stylex";
import { InlineCode } from "@/design-system/typography";

const styles = stylex.create({
  root: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["6xl"],
    minWidth: 0,
    width: "100%",
  },
  configMeta: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    lineHeight: lineHeight.lg,
  },
  section: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["3xl"],
    minWidth: 0,
    width: "100%",
  },
  sectionIntroRow: {
    alignItems: { default: "flex-start", [breakpoints.md]: "center" },
    display: "flex",
    flexDirection: { default: "column", [breakpoints.md]: "row" },
    gap: verticalSpace.lg,
    justifyContent: "space-between",
    width: "100%",
  },
  sectionIntroText: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace.md,
    flex: 1,
    minWidth: 0,
  },
  sectionHeaderAction: {
    flexShrink: 0,
  },
  sectionDescription: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    lineHeight: lineHeight.lg,
  },
  sectionContent: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["2xl"],
    minWidth: 0,
    width: "100%",
  },
  mono: {
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
  },
  accountLink: {
    alignItems: "center",
    color: "inherit",
    display: "flex",
    gap: gap.md,
    minWidth: 0,
    textDecoration: {
      default: "none",
      ":hover": "underline",
    },
  },
  accountText: {
    display: "flex",
    flexDirection: "column",
    minWidth: 0,
  },
  accountName: {
    color: uiColor.text2,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  accountHandle: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  tableWrap: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.lg,
    borderStyle: "solid",
    borderWidth: 1,
    isolation: "isolate",
    maxHeight: explorerLayout.indexedTableMaxHeight,
    overflow: "auto",
    width: "100%",
  },
  table: {
    borderCollapse: "separate",
    borderSpacing: 0,
    minWidth: "100%",
    width: "100%",
  },
  th: {
    backgroundColor: uiColor.bgSubtle,
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "solid",
    borderBottomWidth: 1,
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.medium,
    padding: gap.md,
    position: "sticky",
    textAlign: "left" as const,
    textTransform: "lowercase",
    top: 0,
    zIndex: 2,
  },
  td: {
    backgroundColor: uiColor.bg,
    borderBottomColor: uiColor.border2,
    borderBottomStyle: "solid",
    borderBottomWidth: 1,
    color: uiColor.text2,
    fontSize: fontSize.sm,
    padding: gap.md,
    position: "relative",
    verticalAlign: "middle" as const,
    whiteSpace: "nowrap",
    zIndex: 0,
  },
  filters: {
    alignItems: "flex-end",
    flexWrap: "wrap",
    gap: gap.lg,
  },
  verifyResult: {
    maxHeight: "240px",
    overflow: "auto",
  },
  recordLink: {
    color: "inherit",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    textDecoration: {
      default: "none",
      ":hover": "underline",
    },
  },
  bodyMeta: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    lineHeight: lineHeight.sm,
  },
  badgeRow: {
    alignItems: "center",
    display: "flex",
    flexWrap: "nowrap",
    gap: gap.sm,
  },
});

function AppviewSection({
  id,
  title,
  description,
  headerAction,
  children,
}: {
  id: string;
  title: string;
  description: ReactNode;
  headerAction?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section {...stylex.props(styles.section)} aria-labelledby={id}>
      <div {...stylex.props(styles.sectionIntroRow)}>
        <div {...stylex.props(styles.sectionIntroText)}>
          <h2 id={id} {...stylex.props(explorerSectionStyles.heading)}>
            {title}
          </h2>
          <div {...stylex.props(styles.sectionDescription)}>{description}</div>
        </div>
        {headerAction ? (
          <div {...stylex.props(styles.sectionHeaderAction)}>{headerAction}</div>
        ) : null}
      </div>
      <div {...stylex.props(styles.sectionContent)}>{children}</div>
    </section>
  );
}

function VerifyRecordDialog({
  triggerLabel,
  dialogTitle,
  fieldLabel,
  placeholder,
  description,
  mutation,
}: {
  triggerLabel: string;
  dialogTitle: string;
  fieldLabel: string;
  placeholder: string;
  description: ReactNode;
  mutation: UseMutationResult<unknown, Error, { uri: string }, unknown>;
}) {
  const [open, setOpen] = useState(false);
  const [uri, setUri] = useState("");

  const onVerify = () => {
    const trimmed = uri.trim();
    if (!trimmed) return;
    mutation.mutate({ uri: trimmed });
  };

  return (
    <Dialog
      isOpen={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) mutation.reset();
      }}
      trigger={<Button variant="secondary">{triggerLabel}</Button>}
    >
      <DialogHeader>{dialogTitle}</DialogHeader>
      <DialogBody>
        <DialogDescription>{description}</DialogDescription>
        <Flex direction="column" gap="md">
          <TextField
            label={fieldLabel}
            value={uri}
            onChange={setUri}
            placeholder={placeholder}
            isDisabled={mutation.isPending}
          />
          {mutation.isError ? (
            <Alert variant="critical" title="Request failed">
              {errMessage(mutation.error)}
            </Alert>
          ) : null}
          {mutation.data ? (
            <pre {...stylex.props(styles.mono, styles.verifyResult)}>
              {JSON.stringify(mutation.data, null, 2)}
            </pre>
          ) : null}
        </Flex>
      </DialogBody>
      <DialogFooter>
        <Flex direction="row" gap="md">
          <Button variant="secondary" size="sm" onPress={() => setOpen(false)}>
            Close
          </Button>
          <Button
            variant="primary"
            size="sm"
            onPress={onVerify}
            isDisabled={!uri.trim() || mutation.isPending}
          >
            {mutation.isPending ? "Verifying…" : triggerLabel}
          </Button>
        </Flex>
      </DialogFooter>
    </Dialog>
  );
}

function errMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

export function AppviewExplorer() {
  const { data: session } = useQuery(getSessionQueryOptions);

  const [providerF, setProviderF] = useState("");
  const [requesterF, setRequesterF] = useState("");
  const [jobF, setJobF] = useState("");

  const receiptFilters = useMemo(
    () => ({
      provider: providerF.trim() || undefined,
      requester: requesterF.trim() || undefined,
      job: jobF.trim() || undefined,
    }),
    [providerF, requesterF, jobF],
  );

  const providersQuery = useQuery(listProvidersAppviewQueryOptions);
  const receiptsQuery = useQuery(getReceiptsAppviewQueryOptions(receiptFilters));

  const [settlementReceiptF, setSettlementReceiptF] = useState("");
  const [settlementRequesterF, setSettlementRequesterF] = useState("");

  const settlementFilters = useMemo(
    () => ({
      receipt: settlementReceiptF.trim() || undefined,
      requester: settlementRequesterF.trim() || undefined,
    }),
    [settlementReceiptF, settlementRequesterF],
  );

  const settlementsQuery = useQuery(getSettlementsAppviewQueryOptions(settlementFilters));

  const verifyReceiptMut = useMutation(verifyReceiptAppviewMutationOptions);
  const verifySettlementMut = useMutation(verifySettlementAppviewMutationOptions);

  return (
    <div {...stylex.props(styles.root)}>
      <AppviewSection
        id="providers-heading"
        title="providers"
        description={
          <>
            Indexed <InlineCode>dev.cocore.compute.provider</InlineCode> records (up to 100).
          </>
        }
      >
        {providersQuery.isError ? (
          <Alert variant="critical" title="Could not load providers">
            {errMessage(providersQuery.error)}
          </Alert>
        ) : null}
        {providersQuery.isPending ? (
          <div {...stylex.props(styles.sectionDescription)}>Loading providers…</div>
        ) : null}
        {providersQuery.data ? (
          <IndexedTable
            variant="provider"
            rows={providersQuery.data.providers}
            empty="No providers indexed yet."
          />
        ) : null}
      </AppviewSection>

      <AppviewSection
        id="receipts-heading"
        title="receipts"
        headerAction={
          <VerifyRecordDialog
            triggerLabel="Verify receipt"
            dialogTitle="Verify receipt"
            fieldLabel="Receipt AT URI"
            placeholder="at://…/dev.cocore.compute.receipt/…"
            description={
              <>
                Calls <InlineCode>dev.cocore.appview.verifyReceipt</InlineCode> on the AppView —
                structural, lexicon, signature, and optional MDA checks.
              </>
            }
            mutation={verifyReceiptMut}
          />
        }
        description={
          <>
            Filter <InlineCode>dev.cocore.compute.receipt</InlineCode> rows from the AppView cache.
            Leave fields empty to list recent receipts the indexer holds (up to 200).
          </>
        }
      >
        <Flex direction="row" style={styles.filters}>
          <TextField
            label="Provider DID (repo)"
            value={providerF}
            onChange={setProviderF}
            placeholder="did:plc:…"
          />
          <TextField
            label="Requester DID"
            value={requesterF}
            onChange={setRequesterF}
            placeholder="did:plc:…"
          />
          {session?.user?.did ? (
            <Button variant="secondary" size="sm" onPress={() => setRequesterF(session.user.did)}>
              Use my DID
            </Button>
          ) : null}
          <TextField
            label="Job AT URI"
            value={jobF}
            onChange={setJobF}
            placeholder="at://…/dev.cocore.compute.job/…"
          />
        </Flex>
        {receiptsQuery.isError ? (
          <Alert variant="critical" title="Could not load receipts">
            {errMessage(receiptsQuery.error)}
          </Alert>
        ) : null}
        {receiptsQuery.isPending ? (
          <div {...stylex.props(styles.sectionDescription)}>Loading receipts…</div>
        ) : null}
        {receiptsQuery.data ? (
          <IndexedTable
            variant="receipt"
            rows={receiptsQuery.data.receipts}
            empty="No receipts match these filters."
          />
        ) : null}
      </AppviewSection>

      <AppviewSection
        id="settlements-heading"
        title="settlements"
        headerAction={
          <VerifyRecordDialog
            triggerLabel="Verify settlement"
            dialogTitle="Verify settlement"
            fieldLabel="Settlement AT URI"
            placeholder="at://…/dev.cocore.compute.settlement/…"
            description={
              <>
                Calls <InlineCode>dev.cocore.appview.verifySettlement</InlineCode> — chains receipt,
                authorization, and settlement records indexed by the AppView.
              </>
            }
            mutation={verifySettlementMut}
          />
        }
        description={
          <>
            Filter <InlineCode>dev.cocore.compute.settlement</InlineCode> records by receipt URI or
            requester DID prefix.
          </>
        }
      >
        <Flex direction="row" style={styles.filters}>
          <TextField
            label="Receipt AT URI"
            value={settlementReceiptF}
            onChange={setSettlementReceiptF}
            placeholder="at://…/dev.cocore.compute.receipt/…"
          />
          <TextField
            label="Requester DID"
            value={settlementRequesterF}
            onChange={setSettlementRequesterF}
            placeholder="did:plc:…"
          />
        </Flex>
        {settlementsQuery.isError ? (
          <Alert variant="critical" title="Could not load settlements">
            {errMessage(settlementsQuery.error)}
          </Alert>
        ) : null}
        {settlementsQuery.isPending ? (
          <div {...stylex.props(styles.sectionDescription)}>Loading settlements…</div>
        ) : null}
        {settlementsQuery.data ? (
          <IndexedTable
            variant="settlement"
            rows={settlementsQuery.data.settlements}
            empty="No settlements match these filters."
          />
        ) : null}
      </AppviewSection>
    </div>
  );
}

function pdslsRecordUrl(uri: string): string {
  const path = uri.startsWith("at://") ? uri.slice("at://".length) : uri;
  return `https://pds.ls/at/${path}`;
}

function shortDid(did: string): string {
  return did.length > 22 ? `${did.slice(0, 14)}…${did.slice(-4)}` : did;
}

/** A person/provider as an avatar + display name + handle, linking to
 *  `href`. Falls back to a shortened DID when no profile resolved, so an
 *  unresolved actor still reads as "someone", not a blank cell. */
function ActorChip({
  did,
  displayName,
  handle,
  avatarUrl,
  href,
  title,
}: {
  did: string;
  displayName: string | null;
  handle: string | null;
  avatarUrl: string | null;
  href: string;
  title?: string;
}) {
  const dn = displayName?.trim() || null;
  const h = handle?.trim() || null;
  const label = dn ?? (h ? `@${h}` : shortDid(did));
  const handleLine = dn && h ? `@${h}` : null;
  const fallback = (dn?.[0] ?? h?.[0] ?? did[0] ?? "?").toUpperCase();

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={title ?? did}
      {...stylex.props(styles.accountLink)}
    >
      <Avatar src={avatarUrl ?? undefined} alt={label} fallback={fallback} size="sm" />
      <span {...stylex.props(styles.accountText)}>
        <span {...stylex.props(styles.accountName)}>{label}</span>
        {handleLine ? <span {...stylex.props(styles.accountHandle)}>{handleLine}</span> : null}
      </span>
    </a>
  );
}

/** The provider (the repo the record lives on) — links to the signed
 *  record on pds.ls so the row stays inspectable. */
function RepoAccountCell({ row }: { row: AppviewIndexedRecordEnriched }) {
  return (
    <ActorChip
      did={row.repo}
      displayName={row.repoDisplayName}
      handle={row.repoHandle}
      avatarUrl={row.repoAvatarUrl}
      href={pdslsRecordUrl(row.uri)}
      title={row.uri}
    />
  );
}

/** The requester (who the compute was done *for*) — links to their
 *  profile. Shows "—" only when a record genuinely carries no requester. */
function RequesterCell({ row }: { row: AppviewIndexedRecordEnriched }) {
  if (!row.requesterDid) return <>—</>;
  const identifier = row.requesterHandle?.trim() || row.requesterDid;
  return (
    <ActorChip
      did={row.requesterDid}
      displayName={row.requesterDisplayName}
      handle={row.requesterHandle}
      avatarUrl={row.requesterAvatarUrl}
      href={`/u/${identifier}`}
      title={row.requesterDid}
    />
  );
}

function IndexedTable({
  rows,
  empty,
  variant,
}: {
  rows: AppviewIndexedRecordEnriched[];
  empty: string;
  variant: "provider" | "receipt" | "settlement";
}) {
  if (rows.length === 0) {
    return <div {...stylex.props(styles.sectionDescription)}>{empty}</div>;
  }

  if (variant === "provider") {
    return (
      <div {...stylex.props(styles.tableWrap)}>
        <table {...stylex.props(styles.table)}>
          <thead>
            <tr>
              <th {...stylex.props(styles.th)}>provider</th>
              <th {...stylex.props(styles.th)}>hardware</th>
              <th {...stylex.props(styles.th)}>status</th>
              <th {...stylex.props(styles.th)}>trust</th>
              <th {...stylex.props(styles.th)}>models</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <ProviderTableRow key={r.uri} row={r} />
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (variant === "receipt") {
    return (
      <div {...stylex.props(styles.tableWrap)}>
        <table {...stylex.props(styles.table)}>
          <thead>
            <tr>
              <th {...stylex.props(styles.th)}>provider</th>
              <th {...stylex.props(styles.th)}>requester</th>
              <th {...stylex.props(styles.th)}>model</th>
              <th {...stylex.props(styles.th)}>tokens</th>
              <th {...stylex.props(styles.th)}>price</th>
              <th {...stylex.props(styles.th)}>completed</th>
              <th {...stylex.props(styles.th)}>job</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <ReceiptTableRow key={r.uri} row={r} />
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div {...stylex.props(styles.tableWrap)}>
      <table {...stylex.props(styles.table)}>
        <thead>
          <tr>
            <th {...stylex.props(styles.th)}>account</th>
            <th {...stylex.props(styles.th)}>status</th>
            <th {...stylex.props(styles.th)}>charged</th>
            <th {...stylex.props(styles.th)}>payout</th>
            <th {...stylex.props(styles.th)}>fee</th>
            <th {...stylex.props(styles.th)}>settled</th>
            <th {...stylex.props(styles.th)}>receipt</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <SettlementTableRow key={r.uri} row={r} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function shortAtRkey(uri: string): string {
  const path = uri.startsWith("at://") ? uri.slice("at://".length) : uri;
  const slash = path.lastIndexOf("/");
  return slash >= 0 ? path.slice(slash + 1) : path;
}

function jsonStrongRefUri(v: JsonValue | undefined): string | null {
  return jsonString(asRecord(v)?.uri);
}

function SettlementTableRow({ row }: { row: AppviewIndexedRecordEnriched }) {
  const o = asRecord(row.body);
  const status = o ? jsonString(o.status) : null;
  const charged = o ? jsonMoney(o.amountCharged) : null;
  const payout = o ? jsonMoney(o.providerPayout) : null;
  const fee = o ? jsonMoney(o.exchangeFee) : null;
  const settledAt = o ? jsonString(o.settledAt) : null;
  const receiptUri = o ? jsonStrongRefUri(o.receipt) : null;

  return (
    <tr>
      <td {...stylex.props(styles.td)}>
        <RepoAccountCell row={row} />
      </td>
      <td {...stylex.props(styles.td)}>
        {status ? (
          <Badge variant={settlementStatusVariant(status)} size="sm">
            {status}
          </Badge>
        ) : (
          "—"
        )}
      </td>
      <td {...stylex.props(styles.td, styles.mono)}>{charged ? formatMoney(charged) : "—"}</td>
      <td {...stylex.props(styles.td, styles.mono)}>{payout ? formatMoney(payout) : "—"}</td>
      <td {...stylex.props(styles.td, styles.mono)}>{fee ? formatMoney(fee) : "—"}</td>
      <td {...stylex.props(styles.td, styles.bodyMeta)}>
        {settledAt ? formatShortTime(settledAt) : "—"}
      </td>
      <td {...stylex.props(styles.td)}>
        {receiptUri ? (
          <a
            href={pdslsRecordUrl(receiptUri)}
            target="_blank"
            rel="noopener noreferrer"
            title={receiptUri}
            {...stylex.props(styles.recordLink)}
          >
            {shortAtRkey(receiptUri)}
          </a>
        ) : (
          "—"
        )}
      </td>
    </tr>
  );
}

function settlementStatusVariant(status: string | null): "success" | "warning" | "default" {
  if (status === "settled") return "success";
  if (status === "refunded") return "warning";
  return "default";
}

function ProviderStatusBadges({ body }: { body: JsonValue }) {
  const o = asRecord(body);
  if (!o) return <>—</>;

  const active = jsonBoolean(o.active);
  const provisioning = jsonBoolean(o.provisioning);
  const serving = jsonBoolean(o.serving);
  const payoutsEnabled = jsonBoolean(o.payoutsEnabled);
  const engineFault = asRecord(o.engineFault);

  const badges: ReactNode[] = [];
  if (provisioning === true) {
    badges.push(
      <Badge key="provisioning" variant="warning" size="sm">
        provisioning
      </Badge>,
    );
  } else if (serving === true) {
    badges.push(
      <Badge key="serving" variant="success" size="sm">
        serving
      </Badge>,
    );
  } else if (serving === false) {
    badges.push(
      <Badge key="offline" variant="default" size="sm">
        offline
      </Badge>,
    );
  }
  if (active === false) {
    badges.push(
      <Badge key="retired" variant="critical" size="sm">
        retired
      </Badge>,
    );
  }
  if (payoutsEnabled === true) {
    badges.push(
      <Badge key="payouts" variant="primary" size="sm">
        payouts
      </Badge>,
    );
  }
  if (engineFault) {
    badges.push(
      <Badge key="fault" variant="critical" size="sm">
        {jsonString(engineFault.code) ?? "engine fault"}
      </Badge>,
    );
  }

  if (badges.length === 0) return <>—</>;

  return <div {...stylex.props(styles.badgeRow)}>{badges}</div>;
}

function ProviderTableRow({ row }: { row: AppviewIndexedRecordEnriched }) {
  const o = asRecord(row.body);
  const chip = o ? jsonString(o.chip) : null;
  const ramGB = o ? jsonNumber(o.ramGB) : null;
  const models = o ? jsonStringArray(o.supportedModels) : [];
  const trustLevel = o ? jsonString(o.trustLevel) : null;

  const hardwareParts: string[] = [];
  if (chip) hardwareParts.push(chip);
  if (ramGB != null) hardwareParts.push(`${ramGB}GB`);

  return (
    <tr>
      <td {...stylex.props(styles.td)}>
        <RepoAccountCell row={row} />
      </td>
      <td {...stylex.props(styles.td, styles.bodyMeta)}>
        {hardwareParts.length > 0 ? hardwareParts.join(" · ") : "—"}
      </td>
      <td {...stylex.props(styles.td)}>
        <ProviderStatusBadges body={row.body} />
      </td>
      <td {...stylex.props(styles.td)}>
        {trustLevel ? (
          <Badge variant="default" size="sm">
            {trustLevel}
          </Badge>
        ) : (
          "—"
        )}
      </td>
      <td
        {...stylex.props(styles.td, styles.mono)}
        title={models.length > 0 ? models.join(", ") : undefined}
      >
        {models.length > 0 ? formatModelList(models) : "—"}
      </td>
    </tr>
  );
}

function ReceiptTableRow({ row }: { row: AppviewIndexedRecordEnriched }) {
  const o = asRecord(row.body);
  const model = o ? jsonString(o.model) : null;
  const tokens = o ? asRecord(o.tokens) : null;
  const tokensIn = tokens ? jsonNumber(tokens.in) : null;
  const tokensOut = tokens ? jsonNumber(tokens.out) : null;
  const price = o ? jsonMoney(o.price) : null;
  const completedAt = o ? jsonString(o.completedAt) : null;
  const jobUri = o ? jsonStrongRefUri(o.job) : null;

  const tokenLabel =
    tokensIn != null || tokensOut != null ? `${tokensIn ?? 0} in · ${tokensOut ?? 0} out` : "—";

  return (
    <tr>
      <td {...stylex.props(styles.td)}>
        <RepoAccountCell row={row} />
      </td>
      <td {...stylex.props(styles.td)}>
        <RequesterCell row={row} />
      </td>
      <td {...stylex.props(styles.td, styles.mono)}>{model ?? "—"}</td>
      <td {...stylex.props(styles.td, styles.mono)}>{tokenLabel}</td>
      <td {...stylex.props(styles.td, styles.mono)}>{price ? formatMoney(price) : "—"}</td>
      <td {...stylex.props(styles.td, styles.bodyMeta)}>
        {completedAt ? formatShortTime(completedAt) : "—"}
      </td>
      <td {...stylex.props(styles.td)}>
        {jobUri ? (
          <a
            href={pdslsRecordUrl(jobUri)}
            target="_blank"
            rel="noopener noreferrer"
            title={jobUri}
            {...stylex.props(styles.recordLink)}
          >
            {shortAtRkey(jobUri)}
          </a>
        ) : (
          "—"
        )}
      </td>
    </tr>
  );
}

function asRecord(body: JsonValue | undefined): Record<string, JsonValue> | null {
  if (body === null || body === undefined || typeof body !== "object" || Array.isArray(body)) {
    return null;
  }
  return body as Record<string, JsonValue>;
}

function jsonString(v: JsonValue | undefined): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function jsonNumber(v: JsonValue | undefined): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function jsonBoolean(v: JsonValue | undefined): boolean | null {
  return typeof v === "boolean" ? v : null;
}

function jsonStringArray(v: JsonValue | undefined): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((item): item is string => typeof item === "string");
}

function jsonMoney(v: JsonValue | undefined): { amount: number; currency: string } | null {
  const o = v ? asRecord(v) : null;
  if (!o) return null;
  const amount = jsonNumber(o.amount);
  const currency = jsonString(o.currency);
  if (amount == null || !currency) return null;
  return { amount, currency };
}

function formatMoney(m: { amount: number; currency: string }): string {
  const currency = m.currency.toUpperCase();
  if (currency === "CC") return `${m.amount.toLocaleString()} CC`;
  if (currency === "USD" || currency === "EUR" || currency === "GBP") {
    const major = m.amount / 100;
    return `${major.toLocaleString(undefined, {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })} ${currency}`;
  }
  return `${m.amount.toLocaleString()} ${currency}`;
}

function formatShortTime(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  return new Date(t).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatModelList(models: string[], maxChars = 28): string {
  if (models.length === 0) return "—";

  const visible: string[] = [];
  let used = 0;

  for (const model of models) {
    const sep = visible.length > 0 ? 2 : 0;
    if (visible.length > 0 && used + sep + model.length > maxChars) break;
    visible.push(model);
    used += sep + model.length;
  }

  const rest = models.length - visible.length;
  const base = visible.join(", ");
  return rest > 0 ? `${base} +${rest} more` : base;
}
