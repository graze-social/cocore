# Confidential compute: a proposal for privacy *from* the provider

Status: proposal / discussion
Tracking issue: [#27](https://github.com/graze-social/cocore/issues/27)
Audience: anyone working on the provider agent, the attestation path, or the
requester-side SDKs.

This document is a response to issue #27. It does three things:

1. summarizes how [darkbloom.dev](https://www.darkbloom.dev) handles the same
   problem (privacy of a prompt *from the machine that runs the inference*);
2. maps darkbloom's approach onto the posture ladder in #27 and onto the code
   we actually have today; and
3. makes a concrete counter-proposal that differs from #27 in a few places
   that matter for *our* invariants — chiefly the no-coordinator rule.

It is deliberately opinionated. Where it disagrees with #27 it says so.

---

## 1. The problem, restated

`crypto_box` sealing protects a prompt **in transit to the provider you
chose**. It does **not** protect it **from** that provider. In our code the
plaintext first exists at `advisor.rs::handle_inference_request`, right after
`ctx.encryption.open_from(...)`:

```rust
// provider/src/advisor.rs
let plaintext: Zeroizing<Vec<u8>> = match ctx
    .encryption
    .open_from(&req.requester_pub_key, &req.ciphertext) { ... };
```

That buffer is then stringified and handed to an `Engine`. Today the only real
engine is `SubprocessEngine`, which proxies an OpenAI-shaped request over a
Unix socket to a **Python + vllm-mlx child the machine owner provisioned**
(`provider/src/engines/subprocess.rs`, `provider/python/...`). Everything from
`open_from` onward runs on hardware and inside an interpreter the provider owns
and fully controls. That is the architectural root cause, exactly as #27 says.

Two facts have to become true for this to be "solved," and neither is today:

- **F1 — Plaintext must live somewhere the machine owner can't read.** Right
  now it lives in an interpreted Python process the owner controls.
- **F2 — The requester's encryption must be bound to an *attestation of that
  environment*,** not to the provider's long-lived X25519 key (which the
  provider holds in the clear; see `encryptionPubKey` in
  `attestation.json` / `attestation.rs`).

---

## 2. What darkbloom does

Darkbloom (Eigen Labs, public alpha April 2026) is the closest existing system
to ours: decentralized inference on idle Apple-silicon Macs, OpenAI-compatible,
and explicitly chasing "verifiable privacy, not promised privacy." Their
published architecture has four layers, and it is worth being precise about
each because the deltas to us are instructive.

| Layer | What darkbloom ships | Our equivalent today |
|---|---|---|
| **End-to-end encryption** | Coordinator routes ciphertext; only the matched provider's hardware-bound X25519 key can decrypt. | We have this (`crypto_box` sealing). |
| **In-process inference** | "The inference engine runs **in-process — no subprocess, no local server, no IPC**." Prompt never crosses a process boundary the owner can sit on. | **We do not have this.** We do the opposite: plaintext is streamed over a UDS to an owner-provisioned Python child. |
| **Hardened runtime** | `PT_DENY_ATTACH`; memory-read APIs blocked by Hardened Runtime; SIP can't be disabled without a reboot that kills the process — so the protections are "provably immutable for the process lifetime." | Partial. We have `PT_DENY_ATTACH` + `RLIMIT_CORE=0` + SIP-required in `security.rs`, and a hardened-runtime entitlements file (`cocore.entitlements`) — **but it's the entitlements file for the *shell*, and the protections wrap the Python child only loosely because the prompt lives outside the agent.** |
| **Attestation** | Four-layer: Secure Enclave (P-256) signature, MDM cross-check, Apple Managed Device Attestation (MDA) cert chain to Apple's root, and a **challenge-response re-verified every ~5 minutes**. Two trust levels: *self-attested* (SEP sig + challenge-response) vs *hardware-attested* (full MDA chain). | We have ~60% of the *data model*: `attestation.rs` signs `binaryHash` + posture flags + an MDA chain verified to Apple's Enterprise Attestation Root (`mda.rs`) + a SEP-backed `selfSignature` + `encryptionPubKey`. We do **not** have the interactive challenge-response, and our binary measurement is a file digest, not the OS-enforced cdhash (see §4). |

### The one thing about darkbloom that should shape our design the most

Darkbloom is candid that **the coordinator is in their trusted computing base**:

> "the coordinator remains part of the trusted routing layer. That boundary is
> explicit."

The coordinator matches supply/demand *and* is the thing that encrypts each
request to the provider's key. That is a perfectly reasonable engineering
choice — and it is **exactly the choice our invariant #5 forbids**
("No coordinator-shaped components… Routing, discovery, and settlement are all
federable"). Darkbloom can lean on a coordinator to hold the canonical view of
"which providers are attested-good and what key to seal to." We cannot. So:

> **Darkbloom's hardest 20% (interactive attestation + sealing to an attested,
> fresh key) is centralized in their coordinator. For us that same 20% has to
> be done client-side, by the requester, against the provider's PDS as the only
> source of truth.** That is the real work, and it's the part #27's ladder
> under-specifies.

Everything else darkbloom does — in-process engine, hardened runtime, MDA, SEP
signatures — we can copy almost directly, and #27's Rung 3 already names most of
it. The federation constraint is what makes our version genuinely different.

---

## 3. Mapping darkbloom → the #27 ladder

- **Rung 0 (cost-raising hardening):** matches darkbloom's hardened-runtime
  layer. Note: the `python -S -E -B` / site-module hardening #27 lists as
  shipped is **not yet present in `subprocess.rs` on this branch** — the
  launcher still spawns the venv python with no isolation flags
  (`provider/src/engines/subprocess.rs:404`). Worth landing for real before we
  claim it; but it is band-aid on a path we intend to delete (see §5, WS1).
- **Rung 1 (trust-by-selection, accountable):** darkbloom's *self-attested*
  tier is essentially this. Cheap, honest, ship now. No disagreement.
- **Rung 2 (attestation-bound ephemeral keys):** darkbloom's challenge-response
  + hardware-bound key is the production version of this. This is where our
  no-coordinator constraint bites and where I propose a concrete shape (§5).
- **Rung 3 (macOS-native sealed inference):** this is darkbloom's whole
  product. They have shipped (alpha) what #27 describes as our ceiling. The
  gap between us and them on Rung 3 is **WS1 (native in-process engine)** plus
  **WS3 (requester-side fail-closed verification)** — and we removed the
  in-process engine we used to have (see §4).
- **Rung 4 (real TEE):** darkbloom is Apple-silicon-confidential, same hardware
  bet we are. Neither of us has a TDX/SEV-SNP-class quote on a Mac. #27 is
  right that this is a hardware pivot, not a near-term rung.

---

## 4. Gap analysis against our actual code

Five concrete gaps, in rough order of leverage.

**G1 — The prompt lives outside the measured binary.** `binaryHash` in the
attestation covers the *agent*, but the agent hands plaintext to a Python child
that is **not** covered by any measurement. So even a perfect attestation today
attests the wrong thing: it vouches for the process that *doesn't* see the
prompt and says nothing about the one that does. This is F1, unsolved.

**G2 — We deleted in-process inference, and for a real reason.** Per the long
comment in `engines/mod.rs`, the old PyO3/`inference`-feature design was removed
because `PyO3 + auto-initialize` baked the build machine's libpython path into
the Mach-O load commands and crashed dyld on any Mac without Homebrew Python at
exactly the expected path. **This is the single most important practical
constraint on WS1** and #27 mentions it only in passing. Any "go in-process"
plan that reintroduces a dynamic libpython dependency will reproduce that
outage. darkbloom's "no subprocess, no IPC" claim implies they run a
**statically linked native** inference path — which is the lesson.

**G3 — `binaryHash` is a file digest, not the OS-enforced identity.**
`attestation.rs::hash_file` SHA-256's the binary file. But what the kernel
*enforces* (and what `get-task-allow=false` + library-validation actually
protect) is the code-signing **cdhash**, not a whole-file digest. A requester
checking `binaryHash` cannot map it to "the OS will refuse to run anything but
this code." We need cdhash (`csops(CS_OPS_CDHASH)` / `SecCodeCopySelf`) as the
measured identity, with `binaryHash` kept only as an informational field.

**G4 — There is no requester-side verifier, and no interactive freshness.**
Our attestation is a *published record* with a 24h `expiresAt`. That is the
right primitive for **verifying a receipt after the fact**. It is the *wrong*
primitive for **deciding whether to hand over a plaintext right now**: a 24h
window is an eternity for a key the provider holds in the clear, and a published
record proves nothing about *liveness* at sealing time. darkbloom's 5-minute
challenge-response exists precisely for this. We have neither the handshake nor
any SDK code that fails closed before sealing.

**G5 — "cdhash ∈ known-good" is coordinator-shaped unless we are careful.**
If the known-good set is a list the cocore org publishes and requesters trust,
then *we* have quietly become the coordinator that decides what counts as
confidential — a soft violation of invariant #5 and exactly the
"API key issued by us" smell from CLAUDE.md's "things to avoid." This is the
subtle trap in WS3/WS4 and it deserves a first-class answer (§5, R4).

---

## 5. Proposal

Six recommendations. R1–R3 are the substrate; R4 is the one most likely to be
overlooked; R5–R6 are about honesty and shipping order.

### R1 — Native, statically linked engine for WS1. Do **not** resurrect PyO3.

Add a third `Engine` implementation that does inference **in-process with no
dynamic libpython linkage**, so the attested cdhash actually covers the code
that touches the prompt (closes G1). Concretely:

- **Prefer llama.cpp + Metal**, statically linked into the agent, GGUF weights.
  It is mature, embeddable, and has no interpreter to bake a path into. This
  directly avoids the dyld breakage that killed the old in-process design (G2).
  Cost: we lose process-level crash isolation (a native segfault aborts the
  agent) and we move off MLX/vllm weight formats. Both are acceptable for an
  explicit *confidential tier*.
- `mlx-c` FFI is the alternative if we must keep MLX weights; treat it as a
  fast-follow, not the first cut.
- Keep `SubprocessEngine` as the **explicitly untrusted, non-confidential
  tier** (R5). We are not deleting it; we are demoting it.

The `Engine` trait already isolates this cleanly — `generate_stream` is the only
surface a native engine has to implement.

### R2 — Split attestation into two flows; bind sealing to a *fresh ephemeral* key.

This is the core of Rung 2, done in a way that respects "no coordinator" and the
evolve-additively invariant.

- **Flow A — published attestation (unchanged):** what we have. Receipts
  strong-ref it; verifiers use it to validate a receipt offline. 24h window is
  fine here.
- **Flow B — interactive session handshake (new), for sealing-time
  confidentiality:**
  1. Requester sends a random `nonce`.
  2. Provider, **inside the measured native engine**, generates an ephemeral
     X25519 keypair and returns `ephemeralPubKey` plus a SEP P-256 signature
     over `canonical(ephemeralPubKey ‖ nonce ‖ attestationCid)`.
  3. Requester verifies that SEP signature chains to the `publicKey` of a
     *fresh, verified* attestation (MDA → Apple root, posture flags, cdhash ∈
     known-good, `osVersion ≥ floor`), and that the nonce matches. **Only then**
     does it `seal_to(ephemeralPubKey, …)`.
  4. The provider discards the ephemeral private key when the session ends.

The receipt commits to what was live via **new optional lexicon fields**
(additive, no semantic change to anything existing): e.g.
`attestation.json` gains an optional `cdHash`, `teamId`,
`hardenedRuntime`/`libraryValidation`/`getTaskAllow` booleans; `receipt.json`
gains an optional `sessionKeyCommitment` (SHA-256 of the ephemeral pubkey) and
`attestationLiveness` (the nonce/freshness proof reference). Because they're
optional, nothing about today's records changes — invariant #3 holds.

This closes F2 and G4: the requester seals to a key that exists only inside an
attested process, and only after an interactive liveness check — not to a
long-lived key sitting in the clear.

### R3 — Measure cdhash, not the file; verify it requester-side, fail-closed.

- Repoint the measured identity at the **cdhash** of the native engine code
  path (G3). Add `cdHash`, Developer-ID `teamId`, and the
  hardened-runtime/library-validation/`get-task-allow` status as additive
  attestation fields.
- Build the **verifier-side equivalent of `mda.rs`** in `packages/sdk`,
  `sdk/py`, and the console: verify MDA chain → Apple root (we already have the
  producer side), require `sipEnabled && getTaskAllow == false &&
  libraryValidation == true`, `osVersion ≥ floor`, `cdHash ∈ known-good`, and a
  fresh liveness nonce — **then** seal. **Default-on, fail-closed.** Skipping
  this is what #27 correctly calls "theater": without it, all the producer-side
  attestation in the world buys nothing because no one checks it before handing
  over a secret.
- **The advisor never participates in this.** It matches supply and demand and
  nothing else. The requester verifies against the provider's PDS record
  directly. This is what keeps us on the right side of invariant #5 while
  darkbloom puts the same logic in their coordinator.

### R4 — Make "known-good" a federable transparency log, or we become the coordinator.

This is the recommendation I'd most want eyes on, because it's the one #27's WS4
treats as a build-engineering footnote and I think it's load-bearing for the
invariants.

`cdHash ∈ known-good` only means "this is confidential" if a requester can map a
cdhash to **reviewable source** *without trusting us to curate the list*. If the
set is "whatever cocore.dev publishes," then we are the privileged service every
requester must consult to know what's safe — coordinator-shaped (G5).

The fix is Apple PCC's "code transparency" property, federated:

- **Reproducible builds** of the confidential engine, so cdhash → exact source
  is checkable by anyone.
- An **append-only, mirrorable transparency log** of `(cdHash, sourceCommit,
  buildProvenance)` entries. Anyone can run a mirror; the cocore org runs *a*
  log, not *the* log. Requesters can pin whichever logs/keys they trust, exactly
  like a "friend network" (Rung 1) but for code identity.
- Requesters MAY ship a default log set the way browsers ship a default CA set —
  convenient default, not a mandatory chokepoint.

Without this, R3's `cdHash ∈ known-good` is just "trust cocore," and we've
rebuilt the thing the project exists to avoid.

### R5 — Two explicit receipt/attestation tiers, surfaced everywhere.

Add a tier marker (`attested-confidential` vs `best-effort`) to the
attestation/receipt and surface it in the console and SDK verify output. The
subprocess/Python path is permanently `best-effort`; the native+verified path is
`attested-confidential`. No optional field silently changes behavior — the tier
is explicit, per invariant #3 and CLAUDE.md. A requester should never be unsure
which guarantee they got.

### R6 — Keep the honest contract until a rung lands.

Until R1–R3 ship, the README/SECURITY language must keep saying plainly: *the
network gives you verifiable receipts and transport privacy, not privacy from
the provider; don't send secrets to a provider you don't operate or trust.*
Receipt integrity (signed, content-addressed, non-forgeable) is unaffected by
any of this and should be described as the separate, already-delivered guarantee
it is.

---

## 6. Recommended sequencing (mine)

This differs from #27's ordering in one way: I front-load the **WS2 JIT spike**
and the **requester-side verifier skeleton** because both are cheap and both can
*invalidate* the rest of the plan, and I tie WS1 to the native-static decision
from R1 rather than leaving the engine choice open.

1. **Rung 1 now.** DIDs, on-record ToS/confidentiality attestations, reputation,
   requester allowlists, optional stake-and-slash. Honest, immediately valuable.
2. **Land Rung 0 for real.** Add the `python -S -E -B` + site-module hardening
   to `subprocess.rs` (it's described as done but isn't on this branch). It's a
   band-aid on a path we'll demote, but the band-aid should at least exist.
3. **WS2 JIT spike (cheap, de-risks everything).** Can a hardened-runtime,
   library-validation-on agent run Metal without `allow-jit`? Precompile a
   signed `.metallib`. If this is infeasible, Rung 3 on Mac is in question and we
   should know now.
4. **Requester-side verifier skeleton + interactive handshake (R2/R3), against
   today's attestation fields.** Fail-closed, default-on, but initially gating
   on the fields we already publish. This makes the *check* real before the
   *thing being checked* is strong — the opposite of theater.
5. **WS1 native static engine (R1), llama.cpp+Metal first.** The long pole.
   Once it lands, repoint the measured identity at its cdhash (R3) and bind the
   ephemeral key into it (R2).
6. **WS4 transparency log + reproducible builds (R4), in parallel with 5.**
   Without it, step 5's cdhash check is "trust cocore."
7. **Tier markers + OS-version floor + MDA revocation revisit (R5 / WS5).**

---

## 7. Residual holes (so we don't over-claim)

Even with all of the above shipped, we are at "mostly solved on Apple silicon,"
not "solved":

- Self-attestation of software on macOS is not first-class — there is no
  TDX/SEV-SNP/TPM-style measured-launch quote. cdhash + MDA + SEP lean on
  library-validation / no-debugger-entitlement / SIP, all of which a **kernel
  compromise** could defeat. We mitigate by attesting `osVersion` and gating on
  a floor, but a vulnerable-but-unpatched kernel beats kernel-enforced task-port
  protection.
- Metal JIT vs hardened runtime is an unresolved tension (the WS2 spike).
- Physical attacks — DMA, cold-boot — are out of scope without a real TEE.
- A real TEE (Rung 4: NVIDIA CC GPUs + SEV-SNP/TDX) is the only *trustless*
  answer, and it's a Linux + hardware pivot away from Macs/MLX. Apple Private
  Cloud Compute is the existence proof of the design but relies on custom
  silicon a federated network can't replicate. FHE / MPC remain orders of
  magnitude too slow for useful LLMs — watch-the-research, not buildable.

The honest one-liner: **darkbloom shows the Apple-silicon confidential path is
buildable; our job is to build it without their coordinator, which moves the
hardest part (interactive, fail-closed attestation) onto the requester and the
PDS where our invariants require it to live.**

---

## Sources

- cocore issue [#27](https://github.com/graze-social/cocore/issues/27)
- Code: `provider/src/advisor.rs`, `provider/src/attestation.rs`,
  `provider/src/mda.rs`, `provider/src/security.rs`,
  `provider/src/engines/{mod,subprocess}.rs`,
  `provider-shell/Sources/CoCoreShell/Resources/cocore.entitlements`,
  `lexicons/dev/cocore/compute/{attestation,receipt}.json`
- darkbloom.dev (homepage + provider setup docs); Eigen Labs "Project Darkbloom"
  blog (blog.eigencloud.xyz); darkbloom GitHub (github.com/darkbloomdev/darkbloom)
</content>
</invoke>
