# ADR-0006: Tier lifecycle robustness + a single tray↔console capability handshake

Status: proposed (Devin, 2026-07-05)
Date: 2026-07-05

## Context

After the ADR-0005 native+SE confidential build shipped (0.9.43/0.9.44), the
`attested-confidential` and Secure Mode tiers were observed **flapping** on a
physical Mac: green, then not, then green again, with the agent restarting
~20×/day. No single component was wrong — the flap was **emergent**, produced by
several independently-reasonable behaviors composing badly:

1. **The tier read was keyed on the signing pubkey.** ADR-0005 gave the agent a
   graceful SE→software fallback: `load_or_create_identity()` returns the SE key
   when the enclave is reachable and a software `~/.cocore/identity.pem` key
   otherwise. That makes the *identity non-deterministic by process context* —
   the long-lived `serve` loop holds the SE key (`SdZz…`) while a short-lived
   CLI (`agent tier`) that couldn't reach the enclave loads the software key
   (`1feH…`). Record-matching keyed on `attestationPubKey` then failed to find
   the machine's own record from the CLI, read "no record" → **best-effort**,
   and the tray spawned the best-effort worker even though the owner wanted
   confidential. (Fixed this PR: `record_is_mine` matches on a **stable
   identity** — cached rkey, then `machineFingerprint`, then legacy pubkey — so
   the read no longer depends on which key the current process happens to hold.)

2. **`codeAttested` is per-connection and resets on every reconnect.** A single
   WS churn event (Railway edge idle cutoff, sleep/wake, network blip) drops the
   advisor entry's `codeAttested` to false, which empties the machine from the
   confidential feed until the next full APNs code-challenge completes — a
   multi-second-to-minute gap that reads as "confidential turned off." (Fixed
   this PR: `codeAttested` **survives a brief reconnect** — same signing key +
   same cdHash, within a 5-minute grace — so WS churn no longer resets a
   just-proven attestation. Security-gated: a key change or cdHash change never
   carries the flag.)

3. **The tray re-probes the tier on every respawn.** `spawnChild` shells out to
   `cocore agent tier` once per spawn to pick the worker binary. A transient
   failure of that shell-out (the CLI couldn't launch, or returned nothing)
   returned `"best-effort"`, flipping the worker and tripping
   `reconcileConfidential`'s auto-bounce → another restart. (Fixed this PR:
   `probeTierResilient()` distinguishes a *clean* best-effort answer from a
   *failed* probe and holds the last definite tier on failure. Worker selection
   only — never a security grant, since the advisor still gates confidential on
   cdHash + code-attestation.)

4. **The MDA (Secure Mode) attestation could bind a stale key.** Fixed in #178
   (shipped 0.9.44): the coordinator discards a DeviceInformation attestation
   whose freshness/chain binds a key other than the one currently expected, so a
   queued stale-key capture no longer clobbers a fresh current-key one.

The through-line: **each tier's standing was rebuilt from scratch, on every
restart, against asynchronous external state (a live PDS read, a fresh APNs
round-trip, an MDM command queue).** Any transient gap in any input flipped the
surfaced state. The fixes above make each input *durable across a transient
gap* rather than fail-open-to-off.

## Decision

### Part A — durability fixes (shipped this PR, 0.9.45)

Adopt the four continuity fixes above as the standing posture: **tier and
attestation standing must degrade only on durable evidence of change, never on a
transient read/connection gap.** Concretely:

- Machine-record identity resolves by stable id (fingerprint/cached-rkey),
  independent of which signing key a given process loaded.
- `codeAttested` carries across a brief reconnect under an
  identity-and-measurement equality gate.
- The tray holds the last definite tier when the probe fails to execute.
- MDA captures that bind a non-current key are discarded, not applied.

None of these widen the trust boundary: every carry-forward is gated on the
same identity + measurement that the original grant required, so a machine that
has *genuinely* changed key, cdHash, or owner intent still loses standing.

### Part B — a single capability/liveness handshake (spec only; not built here)

The deeper structural issue is that "is this machine confidential-capable?" and
"is this machine reachable right now?" are **conflated** and recomputed from a
half-dozen legs on every connection. The target design separates them:

- **Capability** (slow-changing, machine-scoped): the tuple
  `{ cdHashKnownGood, secureEnclaveAvailable, encScheme, selfTier,
  challengeVerifiedSip, machineFingerprint }`. Established once per
  build/enrollment and re-proven only when an input actually changes. A
  successful APNs code-challenge stamps a **capability lease** (signed by the
  advisor, bound to signing key + cdHash + machineFingerprint, with an
  expiry) rather than a per-connection boolean.

- **Liveness** (fast-changing, connection-scoped): the WS heartbeat / register
  freshness. Reconnects toggle liveness only; they consult the still-valid
  capability lease instead of tearing attestation down and rebuilding it.

- **One tray↔console handshake:** the tray presents its capability lease + a
  fresh liveness proof; the console renders tier standing directly from those
  two, with a single calm state machine (Off / Applying…(reason) / Active) and
  no per-leg flapping. The lease's expiry — not a connection drop — is what
  forces re-attestation.

This collapses the current multi-leg recompute into "valid lease + live
connection = Active," which is what a user intuitively expects and what stops
the flap at its root.

**Why spec-only now:** minting an advisor-signed capability lease changes the
confidential *enable* path — the exact surface an adversary attacks (astra).
Getting the lease's binding (key + cdHash + fingerprint + expiry + replay
resistance) wrong would open a real loophole, so it must land as its own PR with
its own adversarial review, not bundled into a robustness fix. The Part A
durability fixes remove the observed flapping without touching the trust
boundary; Part B is the clean-slate follow-up.

## Accepted residual

- Part A makes standing *sticky across transient gaps*, which by construction
  widens the window in which a machine that changed state is still shown at its
  prior tier — bounded by the grace window (5 min for `codeAttested`) and always
  re-gated on identity + measurement equality, so it cannot show a *different*
  machine or a *changed* build at the old tier.
- Part B's capability lease is deferred; until it lands, standing is still
  recomputed per connection, so a churny network still causes brief Applying…
  transitions (no longer full off-flaps, but not yet a single steady state).

## Consequences

- The flapping observed on 0.9.44 is resolved by Part A without a protocol
  change or a new trust root.
- Part B is captured as the intended end-state so the next person doesn't
  re-derive it, and so the enable-path change gets the isolated, adversarially
  reviewed PR it needs.
- No new coordinator and no change to the offline-verifiable receipt: the
  capability lease, if built, is an *accelerator* for the live tier UI (like the
  advisor's code-attestation leg today), never authority over a sealed receipt.
