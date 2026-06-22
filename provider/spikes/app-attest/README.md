# App Attest companion (`cocore-appattest`)

The MDM-free path to **`trustLevel: hardware-attested`**. This helper drives
Apple's App Attest API to produce an attestation object that is *bound to the
agent's receipt-signing key*, which the provider embeds in its
`dev.cocore.compute.attestation` record (the `appAttest` field). The verifier
(`appattest.rs` / `appattest.ts` / `appattest.py`) confirms it offline.

## Why App Attest (not MDM/step-ca/SCEP)

The hardware-attested flip is gated by **binding**: the Apple attestation must
commit to *our* P-256 signing key, or a genuine Apple chain for an unrelated
device could be stapled on. The MDM `device-attest-01` flow attests a *fresh
ACME key* with an Apple-chosen nonce — neither binds to our signing key, so its
chain verifies but is rejected by the binding gate.

App Attest lets the app choose the attested data. We set

```
clientDataHash = SHA256(signingPubKeyBytes)   # the 64-byte raw P-256 X‖Y point
```

Apple commits that hash into the attestation's credential-certificate nonce
extension (OID `1.2.840.113635.100.8.2`). The verifier recomputes
`nonce = SHA256(authData ‖ SHA256(publicKey))` and requires it to equal that
extension. That equality **is** the binding — by construction, no CA changes.

### What it proves (and the ceiling)

Proves: genuine, un-tampered Apple hardware holds a Secure-Enclave key, and our
signing key is what was attested (via `clientDataHash`). Also binds the App ID /
team. It does **not** by itself prove the signing key is SE-resident, nor that
the running binary is honest — those remain carried by the SE-backed signing
identity + hardened runtime + the cdHash known-good gate (the same
self-measurement ceiling the MDA path has). `hardware-attested` means *genuine
Apple hardware*, not *honest binary*.

## One-time Apple Developer portal setup (ops)

App Attest requires the entitlement
`com.apple.developer.devicecheck.appattest-environment`, which must be
**authorized by the embedded provisioning profile**. Same Team `4L45P7CP9M`,
same App ID `dev.cocore.provider` already used for APNs.

1. Apple Developer portal → Identifiers → `dev.cocore.provider` → enable the
   **App Attest** capability (under DeviceCheck on some portal versions). Save.
2. Profiles → regenerate the `dev.cocore.provider` provisioning profile so it
   carries the new capability. Download it.
3. Use that profile path with `build.sh` / `run.sh`.

Until the profile authorizes it, `codesign` still succeeds but
`DCAppAttestService.attestKey` returns an error at runtime.

## Run

```bash
# Needs a real Apple-silicon Mac (App Attest is unsupported in VMs / on Intel).
./run.sh ~/Downloads/cocore_provisioning_profile.provisionprofile
```

`run.sh` builds + signs the helper, reads the live signing pubkey via
`cocore agent pubkey`, runs the helper, and writes a self-contained fixture to
`target/appattest-device-fixture.json`:

```json
{
  "object": "<base64 CBOR attestation object>",
  "keyId": "<base64 App Attest key id>",
  "publicKey": "<base64 64-byte signing pubkey it bound to>",
  "clientDataHashHex": "...",
  "appId": "4L45P7CP9M.dev.cocore.provider",
  "environment": "production"
}
```

That fixture is the real device vector the cross-language verifier tests run
against (they otherwise use synthetic, self-rooted vectors). Point the Rust
test at it with `COCORE_APPATTEST_FIXTURE=target/appattest-device-fixture.json`.

## Production wiring

The same binary ships inside the app bundle and is invoked by the agent via the
`COCORE_APPATTEST_BINARY` env var (see `provider/src/mda_loader.rs`):
`cocore-appattest <signing-pubkey-b64>` → JSON `{object, keyId}` on stdout. The
agent verifies the object locally (same discipline as the MDA path — only embeds
evidence it has itself confirmed binds) before publishing it.
