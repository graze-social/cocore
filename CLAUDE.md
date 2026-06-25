# CLAUDE.md

Guidance for Claude (and other agents) working in this repository.

## What this project is

cocore defines an AT Protocol lexicon for **receipts of computational work**
and ships the minimum surrounding code (provider agent, AppView indexer, SDK)
to make the lexicon useful. The motivating use case is decentralized AI
inference, but the lexicon is intentionally generic enough to cover any job
that has a requester, a provider, a verifiable input/output commitment, and
an attestation about the environment the work ran in.

The reference point for what we are _not_ building is
[Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference). That
project routes inference through a centralized coordinator that owns
attestation verification, billing, and the canonical record of completed
work. We replace the canonical-record role with provider-signed records
under `dev.cocore.compute.*` written to each provider's PDS.

## Core invariants

These are non-negotiable. Treat changes that violate them as design errors,
not implementation details.

1. **The provider's PDS is the source of truth for receipts.** No service in
   this repo may hold authoritative state that contradicts a signed record.
   AppViews are caches and indexes, never ledgers.
2. **Receipts are self-verifying.** A receipt plus the lexicon plus the
   provider's DID document must be sufficient to validate the receipt
   offline. Do not introduce fields whose meaning depends on a live API.
3. **Lexicons evolve additively.** Existing field semantics never change.
   New behavior is a new optional field or a new NSID. If you find yourself
   wanting to repurpose a field, mint a new one.
4. **Attestations are content-addressed and referenced, not inlined.** A
   receipt strong-refs an attestation record; many receipts share one
   attestation. This keeps receipts small and makes attestation rotation
   observable.
5. **No coordinator-shaped components.** If a design needs a privileged
   service that all providers must talk to in order for receipts to be
   valid, the design is wrong. Routing, discovery, and settlement are all
   federable.

## Repo layout

```
lexicons/dev/cocore/        Lexicon JSON. Treat as the spec.
  compute/
    provider.json
    job.json
    attestation.json
    receipt.json
    settlement.json
provider/                   Rust agent that runs inference + signs receipts.
packages/
  sdk/                      TypeScript client (publish + verify).
  appview/                  Indexer + read-only HTTP API over the lexicon.
  console/                  TanStack Start requester UI + device pairing.
  exchange/                 Settlement / payment orchestration.
infra/
  advisor/                  WebSocket matchmaker the provider's `serve`
                            connects to (Register + Heartbeat + attestation).
  services/                 Bridge HTTP + AppView API + Exchange (one
                            process for local dev / single-host deploy).
sdk/
  py/                       Python client (publish + verify).
examples/                   End-to-end walkthroughs.
```

When in doubt, the lexicon wins. If code disagrees with a lexicon, fix the
code; if the lexicon is wrong, change the lexicon and bump its version.

## Lexicon NSIDs

We own `dev.cocore.*`. Current allocation:

- `dev.cocore.compute.provider`
- `dev.cocore.compute.job`
- `dev.cocore.compute.attestation`
- `dev.cocore.compute.receipt`
- `dev.cocore.compute.settlement`

Do not introduce NSIDs outside `dev.cocore.*` without an ADR.

## Receipt shape (informative; lexicon is normative)

A `dev.cocore.compute.receipt` record commits to, at minimum:

- `job` — strong-ref to the requester's job record
- `provider` — DID of the signing provider
- `requester` — DID of the requester (denormalized for indexer convenience)
- `model` — opaque model identifier honored by the provider
- `inputCommitment` — hash over the (typically encrypted) input bytes
- `outputCommitment` — hash over the output bytes returned to the requester
- `tokens` — `{ in: int, out: int }` where applicable
- `startedAt`, `completedAt` — RFC3339
- `price` — `{ amount, currency }` consistent with the job's ceiling
- `attestation` — strong-ref to a `dev.cocore.compute.attestation` record
- `sig` — provider signature (already implicit at the repo layer; this field
  is for any _additional_ enclave-bound signature the provider wants to
  publish alongside the repo signature)
- `proBono` — optional bool, present (`true`) only when the provider served
  the job pro bono under its `provider.proBono` election: free, unmetered, no
  exchange cut. A pro bono receipt MUST carry `price.amount: 0` and
  `tokens: { in: 0, out: 0 }`, and the exchange settles it with all-zero
  amounts. Absent/false is a normal metered, billable receipt.

## Conventions

- **Languages:** Rust for the provider agent (matches d-inference's choice
  and the security posture it implies). TypeScript for the AppView and the
  primary SDK. Python SDK is a thin wrapper for ML practitioners.
- **Schema-first:** generate types from lexicons; never hand-edit generated
  types.
- **Time:** RFC3339 with explicit timezone, always UTC on the wire.
- **Hashes:** SHA-256, lowercase hex, no prefix. If we ever need a second
  hash function, add a tagged field; do not overload the existing one.
- **DIDs:** accept `did:plc` and `did:web`. Reject everything else at the
  edge with a clear error.
- **Money:** integer minor units plus an ISO 4217 (or `XBT`/`XSAT`-style)
  currency code. No floats anywhere near prices.

## Things to avoid

- Adding a database that becomes the de facto source of truth.
- "Just for now" endpoints that require an API key issued by us.
- Optional fields that silently change behavior when present — make
  behavior changes explicit via a new NSID.
- Inlining attestation blobs into receipts.
- Coupling the provider agent to a specific AppView's URL.

## Running things

Run the Rust provider from `provider/`. Run TypeScript packages from the repo
root (`aube`, `make`) or by `cd` into a workspace under `packages/*`. The
lexicon directory is consumed by codegen during builds; do not commit
generated code.

## Claude Code MCP

This repo includes a **project-scoped** MCP server in `.mcp.json` at the
repository root so Claude Code can use **hip-ui** (`hip-ui` design-system
tools) without per-machine duplication.

Equivalent one-shot setup (stdio / project scope), if you prefer the CLI:

```bash
claude mcp add --transport stdio --scope project hip-ui -- npx -y hip-ui mcp
```

On first use, Claude Code may prompt to approve project-scoped servers; see
`claude mcp reset-project-choices` if you need to reset approvals.

## When extending the system

1. Sketch the change against the invariants above. If it violates one,
   stop and write an ADR explaining why the invariant should change.
2. Update the lexicon first. Open a PR with _only_ the lexicon change and
   a short rationale.
3. Once the lexicon lands, update generated types, then provider, then the
   AppView workspace (`packages/appview`), then SDKs, in that order. The provider must be able to write
   valid records before any consumer assumes they exist.
