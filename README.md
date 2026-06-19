<p align="center">
  <img src="docs/goober.png" alt="cocore" width="300">
</p>

# cocore

**Compute, but shared.** A small, federated compute co-op built on the
AT Protocol — where the spare cycles under your desk can answer someone
else's inference job, every bit of work leaves a signed receipt you own,
and the books are open to anyone who wants to check them.

This is an experiment, run in the open. The network is small enough today
that the founders know most of the people on it. If that sounds like the
kind of thing you'd want to poke at, you're exactly who this is for.

> New here? Start with the two posts that explain the why:
> [**Hello, world**](https://console.cocore.dev/blog/hello-world) (what we're
> building) and [**How the cocore economy is shaped**](https://console.cocore.dev/blog/token-market-design)
> (how the co-op settles up). Then come back.

## The shape of it

cocore has three kinds of participants, and only the third one is "ours":

- **Requesters** want compute done — an LLM completion today, other kinds
  of work later. They sign in with their AT Protocol identity (a Bluesky
  handle works), and their jobs are published as records on *their own* PDS.
- **Providers** have hardware with spare cycles — a Mac mini under a desk,
  a homelab box, an idle machine in a closet. They run the cocore agent,
  attest their environment, and publish a signed **receipt** to *their own*
  PDS for every job they complete. (Today the agent runs on Apple Silicon
  Macs; the protocol doesn't care what's on the other end.)
- **The exchange** is the clearinghouse in the middle. It keeps a token
  balance so requesters can pay and providers can earn, takes a small fee
  for the shared treasury, and publishes its rules openly so you never have
  to take its word for anything.

The first two are owned entirely by the people who run them. Job records
live on requester PDSes; receipts live on provider PDSes; your identity is
a DID you can carry anywhere AT Protocol is spoken. **Nothing in this repo
holds authoritative state about who did what work for whom.**

## What makes it different

Most "decentralized compute" networks distribute the *machines* but keep
the *ledger* in one company's database. Ask that one service who did what,
for whom, at what price — and you trust its uptime, its operator, and its
willingness to keep talking to you. The compute is spread out; the record
is not.

cocore moves the record onto the protocol. Every completed job emits a
**signed receipt** — an AT Protocol record under a public lexicon
(`dev.cocore.compute.*`) written to the provider's own repo. A receipt
commits to:

- the job it answered (a strong-ref to the requester's record)
- the model and the parameters honored
- content hashes of the (encrypted) input and the output
- token counts, wall-clock timing, and price
- the hardware attestation that was live when the work ran
- a signature from the provider's DID-bound key

Hand someone a receipt, the lexicon, and the provider's DID document and
they can verify it **offline** — no API call, no permission, no privileged
operator in the loop. Because the lexicon is public, anyone can run an
AppView that indexes receipts across providers for discovery, billing, or
auditing. None of those AppViews is canonical. The canonical record is the
signed entry sitting in the provider's PDS.

```
   Requester (DID)                    Provider (DID)
        │   1. publish a job              │
        │   (dev.cocore.compute.job)      │
        │ ───────────────────────────────▶│
        │                          2. run the work
        │                             on attested hardware
        │   3. signed receipt             │
        │   (dev.cocore.compute.receipt)  │
        │ ◀───────────────────────────────│
        │                                 │
        └──────────────┬──────────────────┘
                       │
            anyone can index the firehose
            and run an AppView — or a whole
            other exchange — off these receipts
```

## The economy, briefly

Settlement runs on **tokens**: one model token in or out costs one token
from your balance, full stop. There's no exchange rate to anything outside
the system and no secondary market — the token buys compute, and that's the
only value we try to assert. It's a *mutual-credit* unit in the tradition of
[Sardex](https://www.sardex.net/) and the 1934 WIR cooperative bank.

The mechanics are deliberately few:

- **A welcome grant** — every new DID gets 1,000,000 tokens on the house,
  so you can try the network before contributing anything back.
- **An admission floor** — jobs need a minimum balance to run, so you never
  settle into the red mid-job.
- **A 95 / 5 split** — a receipt credits the provider 95% and the shared
  treasury 5%; nothing is minted or burned, so the books always sum to zero.
- **A weekly refresh** — a small use-it-to-keep-it drip so an occasional
  member never gets locked out.
- **A monthly patronage rebate** — most of the treasury flows back to active
  members in proportion to how much they participated. This is the old
  Rochdale co-op dividend (think REI's annual rebate), translated to compute.

Every parameter lives on a public `dev.cocore.compute.exchangePolicy`
record, so you — or a competing exchange — can replicate the math without
asking us. The full rationale, and what we deliberately left out, is in
[the economy post](https://console.cocore.dev/blog/token-market-design).

## Try it

**As a requester:** sign in at [console.cocore.dev](https://console.cocore.dev)
with your Bluesky handle. You'll land with a million tokens and can run a
job right away.

**As a provider:** turn an Apple Silicon Mac into a node. The friendly path
is the menu-bar app (it pairs, downloads a model, and starts serving);
the headless path is one line:

```sh
curl -fsSL https://console.cocore.dev/agent | sh
```

Either way the agent pairs to your identity, attests the machine, loads a
local model, and starts publishing receipts as it earns. See
[`docs/install-mac.md`](docs/install-mac.md) for the details.

## What's in here

The lexicon is the source of truth. Everything else exists to make it
useful — and if code ever disagrees with a lexicon, the lexicon wins.

```
lexicons/dev/cocore/   the schemas — the spec for receipts, jobs, attestations,
                       settlements, and the exchange policy
provider/              the Rust agent: runs inference, attests, signs receipts
provider-shell/        the macOS menu-bar app that pairs + supervises the agent
packages/
  sdk/                 TypeScript SDK: lexicon types, canonical JSON, and the
                       verification helpers shared across appview/exchange/console
  appview/             indexer + read-only API over the lexicon
  console/             the requester web app + device pairing (console.cocore.dev)
  exchange/            settlement / token-ledger orchestration
infra/
  advisor/             the WebSocket matchmaker the agent's `serve` connects to
  services/            bridge + AppView API + exchange for local/single-host dev
docs/                  install, deploy, and the ADRs behind the big decisions
```

Lexicon NSIDs live under `dev.cocore.*`: `compute.{provider,job,attestation,
receipt,settlement}` for the work itself, `compute.exchangePolicy` for the
published rules, and `account.{tokenGrant,tokenPatronage}` for the auditable
co-op trail. The `account.{create,list,revoke,delete}ApiKey` methods expose
API-key lifecycle over XRPC so you can automate access ([`docs/api-keys.md`](docs/api-keys.md)).
Lexicons only ever change **additively** — existing fields never change
meaning; new behavior is a new optional field or a new NSID.

## Hack on it

You'll want Rust (provider), Node + pnpm (the TypeScript workspaces), and —
if you're touching the Mac app — Swift. The repo uses `mise` to pin tool
versions and a `Makefile` that wraps the common loops:

```sh
pnpm install            # TypeScript workspaces (packages/* and infra/*)
make build              # build provider, appview, console, exchange, shell
make test               # lexicon validation + all suites
make stack-up           # bring up the local dev stack
cargo test --manifest-path provider/Cargo.toml   # just the agent
```

The order of operations when you extend the system is always the same:
**lexicon first.** Sketch the change against the invariants below; if it
violates one, write an ADR (`docs/adr/`) explaining why the invariant
should change. Then land the lexicon, regenerate types, and update the
provider, the AppView, and the SDKs — in that order, so the thing that
*writes* records can do so before anything assumes they exist. (More in
[`CLAUDE.md`](CLAUDE.md), which doubles as a guide for human and AI
contributors alike.)

## The promises we keep

The "no central exchange" claim is enforced in code, not just asserted:

- **The provider's PDS is the source of truth.** No service here holds
  authoritative state that can contradict a signed receipt. AppViews and
  the exchange are caches and clearinghouses — never the ledger of record.
- **Receipts are self-verifying.** A receipt + the lexicon + the provider's
  DID document is enough to validate it offline.
- **AppViews are interchangeable.** Two AppViews on the same firehose
  converge to byte-identical state and identical verdicts, in any replay
  order. (`packages/appview/src/indexer/federation.test.ts`,
  `…/replay.test.ts`, `…/integration/firehose.test.ts`.)
- **Exchanges are interchangeable.** Because receipts live on provider
  PDSes and not in any exchange's database, a second exchange can index the
  same firehose, settle the receipts that name it, and never interfere with
  the first. The cocore.dev exchange is a participant, not a chokepoint.

If a change would let two correctly-implemented operators disagree about a
canonical record, that change is a bug — the design kind, not the typo kind.

## Where this is

Early, live, and a little held together with tape in places — on purpose.
There's one exchange running today at cocore.dev, under one DID, with a
policy anyone can read. The agent runs on Apple Silicon. The identity layer
is founder-vouched: a verified Bluesky handle gets you in, which is plenty
for a network this size. Expect rough edges and the occasional breaking
change while the lexicon settles.

## Standing on shoulders

Almost nothing here is novel; it's mostly solved problems borrowed from
adjacent ones and kept honest in translation. The mutual-credit unit comes
from Sardex and WIR. The patronage rebate comes from the Rochdale tradition
by way of REI and rural electric co-ops. The "signed, portable artifact of
work" pattern was sharpened by the open-source work at
[darkbloom.dev](https://www.darkbloom.dev/). The federate-don't-coordinate
posture is just the AT Protocol's own lesson about what happens when one
service ends up owning everyone's canonical state. And the original framing —
*Airbnb for compute*, a cloud co-op — came from a
[Silicon Florist post](https://siliconflorist.com/2024/09/11/cocore-airbnb-for-compute/)
that named cocore in the first place.

## Come say hi

This is a cooperative, so the most useful thing you can do is participate —
run a node, dispatch a job, read the receipts, and tell us where it breaks.
And there's one kind of bug we especially want to hear about: a place where
the design isn't *honest* — where the numbers don't add up, the published
policy doesn't match what the code does, or some piece of state is hiding on
our side that shouldn't be. That's the only kind we don't think we can
engineer our way out of alone.

Open an issue, or find us on Bluesky at [@cocore.dev](https://bsky.app/profile/cocore.dev).
