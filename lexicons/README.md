# cocore lexicons

The normative spec for cocore. If code disagrees with anything in this
directory, the code is wrong.

All NSIDs live under `dev.cocore.*`. The current allocation is the
`compute` namespace, which defines the records exchanged between a
requester, a provider, and an exchange around a single unit of compute
work.

## Namespace: `dev.cocore.compute`

| NSID                                            | Owner repo  | Purpose                                                   |
| ----------------------------------------------- | ----------- | --------------------------------------------------------- |
| `dev.cocore.compute.defs`                       | (none)      | Shared object definitions: `money`, `tokenCounts`, etc.   |
| `dev.cocore.compute.provider`                   | provider    | Public profile for one provider machine.                  |
| `dev.cocore.compute.attestation`                | provider    | Hardware/software attestation snapshot, Secure-Enclave-signed. |
| `dev.cocore.compute.paymentAuthorization`       | requester   | Pre-signed authorization for an exchange to charge up to a ceiling. |
| `dev.cocore.compute.job`                        | requester   | Request for work; commits to the encrypted prompt.        |
| `dev.cocore.compute.receipt`                    | provider    | Signed proof a job was completed; strong-refs job + attestation. |
| `dev.cocore.compute.settlement`                 | exchange    | Signed proof of payment; strong-refs receipt + authorization. |

## Namespace: `dev.cocore.account`

Records and methods scoped to a cocore account rather than a unit of work.

| NSID                                | Type      | Purpose                                                              |
| ----------------------------------- | --------- | -------------------------------------------------------------------- |
| `dev.cocore.account.defs`           | defs      | Shared object definitions for account methods (e.g. `apiKeyView`).   |
| `dev.cocore.account.profile`        | record    | A user's cocore-side profile.                                        |
| `dev.cocore.account.friend`         | record    | A directed trust edge between two accounts.                          |
| `dev.cocore.account.tokenGrant`     | record    | An auditable co-op token grant.                                      |
| `dev.cocore.account.tokenPatronage` | record    | An auditable co-op patronage record.                                 |
| `dev.cocore.account.createApiKey`   | procedure | Mint a new API key; returns the secret exactly once.                 |
| `dev.cocore.account.listApiKeys`    | query     | List the authenticated account's API keys (no secrets).             |
| `dev.cocore.account.revokeApiKey`   | procedure | Revoke a key (soft; keeps the row for audit).                        |
| `dev.cocore.account.deleteApiKey`   | procedure | Hard-delete a key row.                                               |

The API-key methods are served by the console at
`/api/xrpc/<nsid>` and authenticate with either a console session or an
existing `Authorization: Bearer cocore-...` key. See
[`docs/api-keys.md`](../docs/api-keys.md) for the full guide and curl
examples.

## Verification chain

A complete unit of work, fully verified by an outside party with no API
calls beyond the federated AT Protocol layer:

1. Fetch the **settlement** record from the exchange's repo.
2. Resolve the strong-refs to the **receipt** and the
   **paymentAuthorization**.
3. Fetch the receipt's strong-refs to the **job** and the
   **attestation**.
4. Verify:
   - the attestation's `selfSignature` against its `publicKey`
     (and, when present, walk `mdaCertChain` to Apple's root)
   - the receipt's `enclaveSignature` against the attestation's
     `publicKey`
   - the receipt's `inputCommitment` equals the job's `inputCommitment`
   - the receipt's `price` ≤ the job's `priceCeiling`
   - the settlement's `amountCharged` ≤ the authorization's `ceiling`
   - the authorization's `exchange` equals the settlement-publishing DID

Any failure in this chain invalidates the unit of work without requiring
agreement from any other party.

## Pro bono receipts

A provider can elect to serve work **pro bono** — free, unmetered, and with
no exchange cut — via the `proBono` policy on its
`dev.cocore.compute.provider` record:

- `proBono.mode: "any"` serves every requester pro bono.
- `proBono.mode: "direct"` serves only the requester DIDs in `proBono.dids`
  (the owner's direct pro bono relationships) and bills everyone else
  normally. An absent policy, or an unknown `mode`, means pro bono is off —
  readers fail closed to paid.

Pro bono is purely **additive**: a requester the policy doesn't cover is
still served as a normal paid job, so opting in never costs the machine paid
work. The election is the provider's alone — there is no central pro bono
registry, consistent with the no-coordinator invariant.

When a provider serves a job pro bono it still publishes a signed receipt
(the provider's PDS stays the source of truth for work done), but the receipt
carries `proBono: true` and, by invariant, `price.amount: 0` and
`tokens: { in: 0, out: 0 }` — the work is explicitly not counted, so neither
figure is a billing claim. The flag is covered by `enclaveSignature`, so the
carve-out is part of the signed, self-verifying record rather than an
off-record side channel. A verifier MUST reject a `proBono: true` receipt
whose price or token counts are non-zero. An exchange settling such a receipt
takes no fee and moves no balance: `amountCharged`, `providerPayout`, and
`exchangeFee` are all `0`.

The `proBono` policy is **owner-written intent** (set from the console / a
management UI), preserved by the agent across re-publishes like
`desiredModels` / `desiredTier`. A requester can deliberately seek out a free
machine via the **pro-bono completion path** (`/v1/probono/chat/completions`),
which routes only to providers whose policy serves that requester; because a
pro-bono receipt moves no balance, a requester with no token balance can still
be served there.

## Coarse location (region)

A machine can **opt in** to publishing its coarse country, an ISO 3166-1
alpha-2 code, so requesters can route to nearby compute:

- `shareLocation` (boolean) on the `dev.cocore.compute.provider` record is the
  owner's opt-in, set from the console. Owner-written intent, preserved by the
  agent across re-publishes (like `proBono` / `desiredTier`).
- When `shareLocation` is on, the agent resolves the machine's country from a
  best-effort public-IP geolocation at serve start and stamps `region`
  (plus `regionSource` and `regionObservedAt`), refreshed on every serve. When
  it is off, those fields are omitted, so opting out drops the value on the
  next re-publish.

`region` is **advisory and self-asserted** (same trust posture as `tier`): a
VPN or proxy moves it, and there is no signed-location primitive, so a verifier
MUST NOT gate anything security-relevant on it. It exists purely as a routing
hint. Requesters narrow by it with the `country` parameter on the completions
endpoints; a provider that isn't sharing a region is never matched by a country
filter, and the request fails closed (`no_providers_for_country`) rather than
silently routing elsewhere. The advisor echoes `region` from the record so
country routing needs no PDS read.

## Federation invariants

These two properties together are what "no privileged operator" means in
this codebase. Both are tested directly:

1. **Write-side (exchange federation).** Two exchanges subscribed to the
   same firehose see the same receipt stream and settle only the
   receipts whose `paymentAuthorization` names them. They cannot
   double-charge each other, and a receipt with no matching exchange is
   simply ignored by all of them. Proof:
   `packages/exchange/src/firehose.test.ts`.

2. **Read-side (AppView federation).** Two AppViews subscribed to the
   same firehose end up with byte-identical indexed state for every
   cocore record they observe. Late operators replaying a recorded
   firehose backfill arrive at the same `verifyReceipt` verdict as
   operators who indexed live; permutation of arrival order doesn't
   change the final state. Proof:
   `packages/appview/src/indexer/federation.test.ts` and
   `packages/appview/src/indexer/replay.test.ts`.

Operators may differ on retention, latency, indexing cursors, and the
convenience APIs they layer on top — but never on what's true about a
canonical record. If a future change to this lexicon would let two
correctly-implemented AppViews disagree on a receipt, that's a design
error and the change should be rejected.

## Evolution policy

- Lexicons evolve **additively**. Existing fields never change meaning.
- New behavior is a new optional field or a new NSID.
- Repurposing a field is a design error; mint a new NSID instead.
- The current frozen tag is `lexicon-v1` (set after this directory's
  first PR lands).

## Codegen

These JSON files are consumed at build time by:

- Rust: `atrium-codegen` → `provider/src/lex/`, gitignored.
- TypeScript: `@atproto/lex-cli` → `packages/appview/schemas/`, gitignored.
- Python: `atproto-lexicon-py` → `sdk/py/src/cocore/lex/`, gitignored.

Never hand-edit generated types.

## Lexicon resolution (making `dev.cocore.*` resolvable)

These schemas are published as `com.atproto.lexicon.schema` records under
the **cocore.dev** identity (`did:plc:5quuhkmwe2q4k3azfsgg7kdz` — confirmed
via `_atproto.cocore.dev`), so any AT Protocol tool (e.g. lexicon.garden's
`com.atproto.lexicon.resolveLexicon`) can resolve and validate them.

Resolution per NSID authority domain (all segments but the name, reversed):

| NSID tree              | authority domain      | DNS record                                      |
| ---------------------- | --------------------- | ----------------------------------------------- |
| `dev.cocore.compute.*` | `compute.cocore.dev`  | `_lexicon.compute.cocore.dev TXT did=did:plc:5quuhkmwe2q4k3azfsgg7kdz` |
| `dev.cocore.account.*` | `account.cocore.dev`  | `_lexicon.account.cocore.dev TXT did=did:plc:5quuhkmwe2q4k3azfsgg7kdz` |

To (re)publish after editing a schema:

```bash
# dry-run validates every schema against lexicon.garden, publishes nothing
COCORE_LEXICON_DRY_RUN=1 scripts/publish-lexicons.sh
# real publish (idempotent putRecord at rkey = NSID)
COCORE_LEXICON_APP_PASSWORD='xxxx-xxxx-xxxx-xxxx' scripts/publish-lexicons.sh
```

Verify resolution:

```bash
curl "https://lexicon.garden/xrpc/com.atproto.lexicon.resolveLexicon?nsid=dev.cocore.compute.receipt"
```
