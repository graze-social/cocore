# Track B: hardware-attested tier via Apple MDA (mirroring darkbloom)

Status: decided, not yet built. Owner action in progress (ABM + Apple Developer
Program already in hand). This doc is the single source of truth for standing up
the `hardware-attested` confidential tier.

## Why we believe this is the right target

darkbloom.dev runs this in production *today* — verified, not inferred. Their
provider attestation data is public and the chains check out against Apple's CA.
Reproduce the proof:

```sh
# 246 live providers; 217 trust_level=hardware, 193 with real Apple MDA chains.
curl -fsS https://api.darkbloom.dev/v1/providers/attestation -o db.json
python3 - <<'PY'
import json,collections
d=json.load(open('db.json')); p=d['providers']
print('total',len(p))
print('trust_level',dict(collections.Counter(x['trust_level'] for x in p)))
print('mdm_verified', sum(x.get('mdm_verified') for x in p))
print('acme_verified', sum(x.get('acme_verified') for x in p))
print('mda_verified', sum(x.get('mda_verified') for x in p))
print('chains populated', sum(1 for x in p if x.get('mda_cert_chain_b64')))
PY
# -> total 246; trust_level {'hardware':217,'self_signed':29};
#    mdm_verified 217; acme_verified 0; mda_verified 193; chains populated 193
```

Decode one provider's chain and verify it cryptographically roots to Apple's
Enterprise Attestation Root CA (the same PEM embedded in `provider/src/mda.rs`):

```sh
python3 - <<'PY'
import json,base64
d=json.load(open('db.json'))
p=next(x for x in d['providers'] if x.get('mda_cert_chain_b64'))
for i,b in enumerate(p['mda_cert_chain_b64']):
    open(f'c{i}.der','wb').write(base64.b64decode(b))
PY
openssl x509 -inform DER -in c0.der -noout -subject -issuer -dates
#  subject=CN=<hash>, OU=AAA Certification, O=Apple Inc.
#  issuer =CN=Apple Enterprise Attestation Sub CA 1, O=Apple Inc., C=US
#  notBefore/After ~ 90-day Apple MDA lifetime, freshly issued
openssl x509 -inform DER -in c0.der -out c0.pem; openssl x509 -inform DER -in c1.der -out c1.pem
openssl verify -CAfile <apple_root.pem> -untrusted c1.pem c0.pem   # -> c0.pem: OK
```

The leaf carries the Apple MDA OIDs `1.2.840.113635.100.8.13.{1,2,3}`
(SIP / SecureBoot / kext) and `.8.10.{1,2,3}` (OS / SEP / LLB versions) — exactly
the OIDs `mda.rs` extracts. Only Apple can issue under that Sub CA. This is real
Apple Managed Device Attestation at fleet scale.

**Key fact for our design:** `acme_verified` is `false` and `mdm_verified` is
`true` across their entire fleet → darkbloom uses the **MDM DeviceInformation /
DevicePropertiesAttestation** route, not ACME `device-attest-01`. We mirror that.

## How darkbloom enrolls providers (from their `install.sh`)

`curl -fsSL https://api.darkbloom.dev/install.sh | bash` (Swift CLI v0.5.0+):

- Step 4 "Enrollment + device attestation": checks `profiles status -type
  enrollment`; if not enrolled, POSTs to their coordinator `/v1/enroll`, downloads
  `Darkbloom-Enroll-<serial>.mobileconfig`, and prompts the user to install the
  profile (opens System Settings → Profiles). One click; user-enrolled MDM.
- The bundle is `Darkbloom.app/Contents/MacOS/{darkbloom, darkbloom-enclave,
  mlx.metallib}` — native **mlx-swift** linked directly, plus a **precompiled,
  signed `mlx.metallib`** (this is how they run Metal under a hardened runtime
  without `allow-jit` — it validates the WS-AGENT-SIGNING / S1 plan), and a
  separate `darkbloom-enclave` companion (SEP + attestation).

## Decisions (locked: "do what darkbloom does")

- **MDM: self-hosted.** Our coordinator serves the enrollment profile and obtains
  + holds the chains (darkbloom's model). Self-host guarantees access to the raw
  x5c chain bytes, which cocore must embed in the provider's PDS attestation
  record. NanoMDM is the reference open-source server.
- **Attestation flow: MDM DeviceInformation / DevicePropertiesAttestation** (not
  ACME), matching `mdm_verified` / `acme_verified=false`.

## Pipeline to a working chain

```
Apple Business Manager (have it)  +  Apple Developer Program (have it — for Developer ID signing/notarization)
        │  link MDM server (server token / public key in ABM)
        ▼
self-hosted MDM (NanoMDM)  ──APNs push cert──►  can command devices
        │  serve enrollment .mobileconfig  (our coordinator's /enroll)
        ▼
provider Mac installs profile  →  MDM-managed
        │  MDM requests DevicePropertiesAttestation,
        │  attesting the agent's SEP P-256 SIGNING key
        │  (nonce binds sha256(SE_signing_pubkey))
        ▼
Apple returns x5c DER chain  →  leaf certifies that key → Sub CA → Apple Root
        │  coordinator stores it, keyed by device/serial
        ▼
provider agent fetches it (mda_loader::try_load) and embeds it in the
dev.cocore.compute.attestation record it publishes to its own PDS
        │
        ▼
verifier (provider/src/mda.rs, packages/sdk/src/mda.ts) already enforces:
   chain → Apple Enterprise Attestation Root CA, CA constraints,
   AND leaf.publicKey == attestation.publicKey (the signing key)  →  hardware-attested
```

## Critical wiring requirement (don't miss this)

`mda.rs` / `mda.ts` drop any chain whose **leaf public key != the agent's signing
identity key** (`secure_enclave.rs SigningIdentity::public_key_bytes`). So the key
that MDA attests **must be cocore's SEP signing-identity key**, not a throwaway.
`docs/mda-companion-binary.md` already specs this ("leaf MUST certify the agent's
P-256 signing key"). Concretely: the `cocore-mda-attest` companion must drive
attestation of the *existing* enclave signing identity (or the enclave identity
must be created through the attestation flow). Verify this binding end-to-end on
the first test Mac before scaling — a mismatch silently caps the tier at
`best-effort` with no error.

**Open question to resolve on the first Mac:** in the MDM DeviceInformation route,
the *MDM server* (coordinator) receives the chain, not the device. Decide how it
gets back to the provider agent for embedding (coordinator stores by serial →
agent pulls via `mda_loader`). darkbloom's coordinator clearly holds + serves the
chains (that's what `/v1/providers/attestation` returns), so mirror that: the
coordinator hands the chain to the agent, the agent embeds it, the PDS record
stays the source of truth (invariant #1).

## Concrete next actions (in order)

1. **Stand up NanoMDM + obtain the APNs push certificate.** The APNs cert for a
   self-hosted MDM is the known friction point — budget for it. (Good task for the
   Mac Claude instance with live access to the current NanoMDM setup docs +
   Apple Push Certificates Portal; don't work from memory here.)
2. **ABM → Settings → MDM Servers → add your NanoMDM** (upload its public key,
   download the server token) to link ABM ↔ MDM.
3. **Confirm the Developer Program membership is the GRAZE SOCIAL PBC org** (you're
   already the Account Holder — the "can't enroll" screen just means already
   enrolled; convert individual→org via Apple Developer Support if needed). Use the
   org Developer ID cert for WS-AGENT-SIGNING (sign + notarize `cocore-provider`).
4. **Enroll one test Mac** via the `.mobileconfig` profile.
5. **Drive DevicePropertiesAttestation** on the agent's SEP signing key; capture
   the x5c chain; run it through `mda::verify_chain` — expect verify-to-Apple-root
   + the leaf==signing-key binding to pass.
6. **Build `cocore-mda-attest`** (`docs/mda-companion-binary.md`) to automate
   acquiring the chain and writing it where `mda_loader::try_load()` reads it; wire
   the coordinator to serve the chain back to the agent; flip the provider to
   `hardware-attested`.

## Relationship to the rest of the plan

- This is **Track B**. Track A (software-attested confidential: native engine +
  cdHash + posture + ephemeral-key binding + fail-closed verify) is pure code, no
  Apple infra, and ships first — see `~/.claude/plans/` parity plan / the
  workstreams in the confidential-compute plan.
- The verifier, the embedded Apple root, the binding check, and the lexicon slot
  (`mdaCertChain`) are **already built**. Track B only adds the chain *producer*
  (this MDM pipeline) — when a real chain shows up, the same code flips the tier
  with no rework.
</content>
