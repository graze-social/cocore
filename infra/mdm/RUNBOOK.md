# Secure Mode production cutover — runbook (2026-06-21)

Goal: make the guided **Secure Mode** wizard work end-to-end through the
console coordinator against the live `cocore-step-ca` + `cocore-nanomdm`
services, so an enrolling Mac earns `trustLevel: hardware-attested`.

The **code half is done** (this branch): the coordinator now mints a real
per-device SCEP+MDM+ACME enrollment profile, the wizard's HTTP-400 bug is
fixed (enrollmentId is returned in the JSON body), and there's a durable
chain store + an authenticated ingest endpoint for step-ca to post the
captured Apple x5c chain. What remains is **infra** — and the Railway API
token in `~/.zshenv` is **read-only**, so these steps are done by hand in
the Railway dashboard / with the `step` CLI. Nothing here transits a tool
call (secrets stay on your machine + the dashboard).

## Current live state (verified 2026-06-21)

- `cocore-step-ca` (`4de1dff8-…`) — UP, ACME `cocore-attest` serving via
  TCP proxy `reseau.proxy.rlwy.net:43462`. Root `6d7bcfec…` (still the
  2026-06-20 root). **EPHEMERAL** — volume `cocore-step-ca-volume`
  (`4ccbbb4b-…`) is detached (`serviceId: null`).
- `cocore-nanomdm` (`277e36ce-…`) — UP at
  `cocore-nanomdm-production.up.railway.app`, auth working. **EPHEMERAL** —
  no volume; push cert lives in file storage and dies on redeploy.
- `Client` (console, `e8f485a3-…`) — has the `/data` volume, so the new
  chain store persists for free.

> ⚠️ Re-initialising step-ca changes its **root fingerprint**, which
> breaks NanoMDM's baked `-ca` _and_ any Mac already trusting the old
> root. Do steps 1→2→3 as one sequence, then enroll. Don't redeploy
> step-ca after step 1.

---

## Step 1 — Persist step-ca (with SCEP + the attest webhook at boot)

1. **Attach the volume.** Railway → `cocore-step-ca` → Settings → Volumes →
   attach `cocore-step-ca-volume` at `/home/step`.
2. **Init-once env** (Variables): keep `RAILWAY_RUN_UID=0`,
   `DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT=true`, and
   `DOCKER_STEPCA_INIT_DNS_NAMES=reseau.proxy.rlwy.net`. Redeploy → step-ca
   inits **into the volume** (now durable). This mints a **new root** —
   that's expected; capture it next.
3. **Capture the new root + intermediate:**
   ```sh
   curl -sk https://reseau.proxy.rlwy.net:43462/roots.pem  > ~/cocore-mdm/stepca-root.pem
   # intermediate is in ~/cocore-mdm/stepca-client after bootstrap, or:
   STEPPATH=~/cocore-mdm/stepca-client step ca bootstrap \
     --ca-url https://reseau.proxy.rlwy.net:43462 \
     --fingerprint <new-fingerprint-from-roots.pem> --force
   ```
4. **Re-add the provisioners so they exist AT BOOT** (the `/scep` route
   only mounts for provisioners present at boot — that was the blocker):
   ```sh
   STEPPATH=~/cocore-mdm/stepca-client step ca provisioner add cocore-attest \
     --type ACME --challenge device-attest-01 --attestation-format apple \
     --admin-provisioner admin --admin-subject step \
     --password-file ~/cocore-mdm/stepca-password.txt
   STEPPATH=~/cocore-mdm/stepca-client step ca provisioner add cocore-scep \
     --type SCEP --challenge "$(cat ~/cocore-mdm/scep-challenge.txt)" \
     --encryption-algorithm-identifier 2 \
     --admin-provisioner admin --admin-subject step \
     --password-file ~/cocore-mdm/stepca-password.txt
   ```
   Because the CA is now persistent, these survive restarts and `/scep`
   mounts at boot. Verify:
   ```sh
   curl -sk https://reseau.proxy.rlwy.net:43462/acme/cocore-attest/directory   # 200 JSON
   curl -sk https://reseau.proxy.rlwy.net:43462/scep/cocore-scep?operation=GetCACaps  # 200
   ```
5. **Wire the attestation webhook** on the `cocore-attest` provisioner so a
   successful `device-attest-01` posts the captured Apple x5c chain to the
   console ingest endpoint:

   ```sh
   STEPPATH=~/cocore-mdm/stepca-client step ca provisioner webhook add cocore-attest \
     cocore-chain --url https://cocore.dev/api/agent/mdm/attestation-chain \
     --kind ENRICHING \
     --bearer-token "$COCORE_MDM_CHAIN_INGEST_KEY"
   ```

   The webhook body must be `{ "serial": "<permanent-identifier>", "chain":
["<b64-DER-leaf>", …] }` (leaf-first Apple x5c). **Validate the payload
   shape** against your step-ca version — if it doesn't surface the Apple
   x5c directly, use the fallback shim below.

   _Fallback if the webhook can't carry the x5c:_ a 20-line poller that
   reads the issued order's attestation off step-ca's admin API by
   permanent-identifier (= serial) and `POST`s it to the same ingest URL.
   The console side is already done; only the source differs.

---

## Step 2 — Persist NanoMDM

1. **Add a Postgres** plugin to the project; attach to `cocore-nanomdm`.
2. **Storage DSN** (Variables): switch the container args to
   `-storage pgsql -dsn "$DATABASE_URL"` (keep `RAILWAY_RUN_UID=0`,
   `[::]:9000` bind, target port 9000).
3. **Re-bake `-ca`** = the **new** step-ca root+intermediate bundle from
   step 1.3 (the `~/cocore-mdm/nanomdm-deploy/` image bakes `ca.pem`).
   `railway up` the updated image.
4. **Re-upload the push cert once** (now durable on Postgres):
   ```sh
   cat ~/cocore-mdm/apns_push.pem ~/cocore-mdm/push.key | \
     curl -T - -u "nanomdm:$(cat ~/cocore-mdm/nanomdm-api-key.txt)" \
     https://cocore-nanomdm-production.up.railway.app/v1/pushcert      # 200 + topic
   ```

---

## Step 3 — Set the console (Client) env

Railway → `Client` → Variables. Paste the secrets yourself (they never
touch a tool call). Values come from `~/cocore-mdm/`:

```
COCORE_MDM_SCEP_URL=https://reseau.proxy.rlwy.net:43462/scep/cocore-scep
COCORE_MDM_SCEP_NAME=cocore-scep
COCORE_MDM_SCEP_CHALLENGE=<~/cocore-mdm/scep-challenge.txt>
COCORE_MDM_SERVER_URL=https://cocore-nanomdm-production.up.railway.app/mdm
COCORE_MDM_CHECKIN_URL=https://cocore-nanomdm-production.up.railway.app/mdm
COCORE_MDM_TOPIC=com.apple.mgmt.External.7e4125e2-8e2b-4a0d-a148-23c33073bc61
COCORE_MDM_ROOT_CA_PEM=<full PEM of ~/cocore-mdm/stepca-root.pem (step 1.3)>
COCORE_MDM_INTERMEDIATE_CA_PEM=<step-ca intermediate PEM, optional>
COCORE_MDM_ACME_URL=https://reseau.proxy.rlwy.net:43462/acme/cocore-attest/directory
COCORE_NANOMDM_URL=https://cocore-nanomdm-production.up.railway.app
COCORE_NANOMDM_API_KEY=<~/cocore-mdm/nanomdm-api-key.txt>
COCORE_MDM_CHAIN_INGEST_KEY=<generate a fresh 32+ char secret; same value used in step 1.5>
```

Redeploy the console. (The `/data` volume already backs the new
`mdm_attestation_chains` table — no extra volume needed.)

---

## Step 4 — Smoke test (no Mac required for 4a–4b)

**4a. Coordinator is live (not 503).** With any valid agent API key:

```sh
curl -s -X POST https://cocore.dev/api/agent/mdm/enroll-profile \
  -H "Authorization: Bearer $COCORE_API_KEY" -H 'content-type: application/json' \
  -d '{"serial":"H2WHW38LQ6NV","udid":"00008103-001869192E20801E"}' | jq '{enrollmentId, signed, len: (.profile|length)}'
```

Expect a JSON envelope with `enrollmentId` + a base64 `profile`. Decode it
and confirm it carries `com.apple.security.scep`, `com.apple.mdm`
(AccessRights 3, SignMessage), and `com.apple.security.acme` (Attest) — and
**no** `com.apple.security.pkcs12`. A `503 {missing:[…]}` means an env key
from step 3 is unset.

**4b. push-attestation no longer 400s:**

```sh
curl -s -X POST https://cocore.dev/api/agent/mdm/push-attestation \
  -H "Authorization: Bearer $COCORE_API_KEY" -H 'content-type: application/json' \
  -d '{"serial":"H2WHW38LQ6NV"}' | jq .   # → {queued:true, status:"bundled"}
```

**4c. Full run on the M1 (`H2WHW38LQ6NV`).** Open co/core → Status →
Security → **Enable Secure Mode**. Install the profile (Touch ID). The Mac
SCEP-enrolls, checks into NanoMDM, and runs `device-attest-01` against
step-ca on install. step-ca's webhook posts the x5c → the wizard's
chain poll (`GET …/attestation-chain?serial=H2WHW38LQ6NV`) returns
`status:"captured"` → provider flips to **hardware-attested**.

Watch:

- NanoMDM logs: `Authenticate serial_number=H2WHW38LQ6NV` + `TokenUpdate`.
- step-ca logs: `challenge device-attest-01 status=valid`.
- `curl …/attestation-chain?serial=H2WHW38LQ6NV` (with the agent key) →
  `{status:"captured", chain:[…]}`.

---

## Division of labour

- ✅ **Code (this branch):** SCEP/MDM/ACME enrollment profile, fail-closed
  503, wizard-400 fix (JSON envelope), push tolerance, durable chain store
  - authenticated ingest endpoint, unit tests.
- ⏳ **Infra (you, dashboard / `step` CLI):** steps 1–3 above, plus the one
  judgment call in 1.5 (does your step-ca's webhook surface the Apple x5c,
  or do you need the poller shim?).
- 🔁 **No app release needed** for initial enrollment — the shipped 0.9.23
  wizard drives this once the server + infra are in place.

---

## Option-B: key-bound hardware-attested (DeviceInformation + DeviceAttestationNonce)

The ACME flow above proves _genuine Apple hardware_ but its attestation can't
**bind to the receipt-signing key**: the ACME path attests an OS-managed P-384
key (not our P-256 signer), and its freshness = `sha256(challenge token)` (step-ca
chosen). App Attest — which lets an app bind an arbitrary key via clientDataHash —
is **iOS-only** (`DCAppAttestService.isSupported` is false on macOS, confirmed on
M1/macOS 26.4.1). So neither earns `hardware-attested` for the P-256 receipt key
on a Mac.

**The fix (no App Attest, no forked step-ca): MDM `DeviceInformation`
attestation with a key-bound nonce.** Apple's security guide: for
DeviceInformation attestation, _the leaf's freshness code = the
`DeviceAttestationNonce` the MDM sends_. Set

```
DeviceAttestationNonce = sha256(agent P-256 publicKey)
```

→ the leaf's freshness OID (1.2.840.113635.100.8.11.1) commits to the signing
key → the shipped verifiers' option-B check (`freshness == sha256(publicKey)`,
in mda.rs / verify-provider.ts / verify.py, and AppView verifyReceipt) bind it →
`hardware-attested`. Apple rate-limits this to **~1 attestation/device/7 days**,
so it's a weekly re-bind; the captured chain is reused across the 24h attestation
publishes while the signing key is stable.

### Wire-up (code is done; these are the config/ops steps)

1. **NanoMDM → console webhook.** Run NanoMDM with
   `-webhook-url 'https://cocore.dev/api/agent/mdm/nanomdm-webhook?key=<SECRET>'`
   and set the console env `COCORE_NANOMDM_WEBHOOK_KEY=<SECRET>` to the same
   value (NanoMDM doesn't send an Authorization header, so the secret rides in
   the URL `?key=`; a Bearer header is also accepted). The webhook captures the
   device's
   `DevicePropertiesAttestation` result and stores the chain keyed by serial —
   the same store the agent polls.
2. **Agent env** (set by the Secure Mode wizard / installer next to the existing
   chain-URL wiring):
   ```
   COCORE_MDA_REQUEST_URL=https://cocore.dev/api/agent/mdm/request-attestation
   COCORE_MDA_DEVICE_SERIAL=<device serial>
   COCORE_MDA_DEVICE_UDID=<NanoMDM enrollment UDID>
   COCORE_MDA_CHAIN_URL=https://cocore.dev/api/agent/mdm/attestation-chain?serial=<serial>
   COCORE_API_KEY=<agent bearer>            # already set
   ```
   On serve the agent POSTs its pubkey to `request-attestation` (best-effort,
   weekly), then polls `attestation-chain` as today.
3. **Flow:** agent → `request-attestation {serial, udid, publicKey}` → coordinator
   enqueues a `DeviceInformation` command (Queries: `DevicePropertiesAttestation`,
   `DeviceAttestationNonce = sha256(pubkey)`) via NanoMDM → device returns the
   Apple x5c → NanoMDM webhook → stored by serial → agent reads it →
   `attestation::build` binds via freshness (option B) → `hardware-attested`.

### ⚠️ Confirm the freshness bytes on the FIRST live capture

We carry the nonce as a base64 `<string>` and the verifiers expect the freshness
OID to contain the raw 32 bytes of `sha256(pubkey)`. Apple's exact storage of the
nonce→freshness bytes is the one unconfirmed detail. On the first captured leaf:

```sh
# leaf.pem = the captured Apple attestation leaf; pubkey = `cocore agent pubkey`
scripts/inspect-mda-freshness.sh leaf.pem "$(cocore agent pubkey)"
```

- **MATCH** → done, the shipped verifiers accept it as-is.
- **NO MATCH** → the script prints the actual freshness bytes vs `sha256(pubkey)`;
  adjust the single freshness normalizer (`provider/src/mda.rs::freshness_binds`,
  mirrored in `packages/sdk/src/verify-provider.ts::freshnessBindsKey` and
  `sdk/py/cocore/verify.py::_freshness_binds_key`) to fit, and re-run the
  cross-language fixtures.

### Division of labour (option-B)

- ✅ **Code (this branch):** `request-attestation` + `nanomdm-webhook` endpoints,
  the DeviceInformation command builder + nonce + webhook result parser
  (unit-tested), the agent's `request_attestation` trigger, the freshness-binding
  verifiers (all 4), and `inspect-mda-freshness.sh`.
- ⏳ **Infra/ops (you):** NanoMDM `-webhook-url` + `COCORE_NANOMDM_WEBHOOK_KEY`,
  the agent env wiring, and the one-capture freshness-bytes confirmation above.

---

## Option-B bring-up — corrected procedure (live-validated 2026-06-22)

Standing up the MDM backend durably surfaced several gotchas. This is the
working sequence; it supersedes the optimistic notes above.

**A. step-ca must be DURABLE + REMOTE-MANAGED.** The throwaway ephemeral
instance re-inits a new root + admin password on every redeploy and has no
admin API (`/admin/*` → 404), so provisioners can't be managed. On
`cocore-step-ca`: attach the volume at `/home/step` and set
`DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT=true`, `RAILWAY_RUN_UID=0`,
`DOCKER_STEPCA_INIT_DNS_NAMES=reseau.proxy.rlwy.net,cocore-step-ca-production.up.railway.app,localhost`.
First boot prints the **root fingerprint** + **admin password** (capture both,
once). Bootstrap a context: `step ca bootstrap --ca-url <CA> --fingerprint <fp>`.

**B. SCEP needs an RSA decrypter (EC CA can't do SCEP key transport).** Symptom:
macOS profile install fails _"Unable to generate certificate signing request for
SCEP server"_; `GetCACert` returns the bare EC intermediate. Fix: an RSA
recipient cert the device encrypts the pkcsPKIEnvelope to.

```sh
openssl req -x509 -newkey rsa:2048 -keyout decrypter.key -out decrypter.crt -days 3650 -nodes \
  -subj "/CN=cocore-scep-decrypter" -addext "keyUsage=critical,keyEncipherment,digitalSignature"
ADMIN=(--admin-provisioner admin --admin-subject step --admin-password-file admin-pw.txt --ca-url <CA> --root root.pem)
step ca provisioner add cocore-attest --type ACME --challenge device-attest-01 --attestation-format apple "${ADMIN[@]}"
step ca provisioner add cocore-scep --type SCEP --challenge "$(cat scep-challenge.txt)" \
  --encryption-algorithm-identifier 2 --include-root \
  --scep-decrypter-certificate-file decrypter.crt --scep-decrypter-key-file decrypter.key "${ADMIN[@]}"
```

Verify: `GetCACert` now returns a 3-cert bundle led by `CN=cocore-scep-decrypter`
(key=RSA). ACME routes mount at runtime, but the **SCEP route only mounts at
boot — RESTART step-ca** after adding `cocore-scep` (a plain restart; the volume
means no re-init, root preserved).

**C. Re-sync the (new) root everywhere.** A fresh init mints a new root, so:
Client env `COCORE_MDM_ROOT_CA_PEM` + `COCORE_MDM_INTERMEDIATE_CA_PEM` = new
PEMs (redeploy Client); and re-bake NanoMDM `-ca` = intermediate+root
(`nanomdm-deploy/ca.pem`, then `railway up`). NanoMDM uses **file storage**
(ephemeral) — every redeploy wipes the push cert + enrollments, so **re-upload
the push cert after any NanoMDM deploy** (`…/v1/pushcert`) and enroll only after.
(Persist NanoMDM on Postgres — Step 2 — to stop this churn.)

**D. NanoMDM webhook.** `-webhook-url 'https://cocore.dev/api/agent/mdm/nanomdm-webhook?key=<SECRET>'`

- Client env `COCORE_NANOMDM_WEBHOOK_KEY=<SECRET>`. NanoMDM POSTs the URL
  verbatim (no query mangling), so the `?key=` secret survives; the event shape is
  `{topic, acknowledge_event:{udid, raw_payload:<base64 plist>}}`.

**E. The DeviceInformation command (the binding).** `DeviceAttestationNonce` is
`<data>` (raw 32 bytes = sha256(pubkey)); `Queries` must include BOTH
`DevicePropertiesAttestation` (the leaf chain) AND `SerialNumber` (the event only
carries the UDID, but the chain store is keyed by serial). Apple rate-limits this
to ~1/device/7 days.

**F. End-to-end (proven up to enrollment 2026-06-22).** `enroll-profile`
(use the Hardware UUID as the udid) → install the profile (Touch ID; SCEP now
succeeds) → `request-attestation {serial, udid, publicKey}` → NanoMDM pushes →
device returns the attestation → webhook stores by serial → agent polls
`attestation-chain?serial=…` → `scripts/inspect-mda-freshness.sh` confirms
`freshness == sha256(pubkey)`. Debug seam: set `COCORE_MDM_WEBHOOK_DEBUG=1` on
the Client and read the raw webhook payload via
`GET attestation-chain?serial=zzwebhookdebuglast`.

---

## Option-B productionization (agent auto-wiring) — 2026-06-22

The agent now **auto-derives** the option-B inputs on `serve`; no hand-set env
vars and no tray release are needed for the attestation loop:

- `mda_loader::acquire_auto` runs when no explicit `COCORE_MDA_*` env is set.
  It only proceeds if the Mac is **MDM-enrolled** (`profiles status -type
enrollment`), reads its own **serial** + **Hardware UUID** via `ioreg`
  (`IOPlatformSerialNumber` / `IOPlatformUUID`), and derives the coordinator
  URLs from the session console base (`session.api_base`) + session API key.
- It loads the captured chain from
  `…/api/agent/mdm/attestation-chain?serial=<serial>` and embeds it (binds via
  freshness in `attestation::build`). Only if **no** bound chain exists yet does
  it POST `…/api/agent/mdm/request-attestation` — throttled by a 6h local
  cooldown (`~/.cocore/.mda-last-request`) so we never burn Apple's ~1/device/7-day
  attestation quota once we hold a chain.
- Operator overrides still win: `COCORE_MDA_CERT_CHAIN_PATH` / `_CHAIN_URL` /
  `_ATTEST_BINARY` / `_REQUEST_URL` (+`_DEVICE_SERIAL`/`_DEVICE_UDID`) short-circuit
  the auto path.

So the **Secure Mode wizard's only required job is to enroll the device**
(install the profile); the serving agent picks up / requests the attestation
itself on its normal 23h refresh.

### Remaining ops to finish productionization

1. **Persist NanoMDM on Postgres (stop the ephemeral churn).** Add a Railway
   Postgres to the project, apply NanoMDM's pgsql schema, and switch the
   `cocore-nanomdm` Custom Start Command storage flags to
   `-storage pgsql -dsn "$DATABASE_URL"` (keep `-ca /app/ca.pem -api … -listen
[::]:9000 -webhook-url '…?key=…'`). Re-upload the push cert once (durable
   thereafter). Until this lands, every NanoMDM redeploy wipes enrollments +
   the push cert.
2. **Turn OFF the debug seam.** Remove `COCORE_MDM_WEBHOOK_DEBUG` from the
   `Client` service env (it stashes raw webhook bodies; debug-only).

## Secure Mode wizard failure codes (triage)

When the Secure Mode wizard's attesting step stalls it no longer shows a bare
"attestation chain isn't ready" — it classifies what it observed into a stable
code and `NSLog`s a full `co/core Secure Mode attestation failed [...]` report
(serial, enrolled, elapsed/polls, the `push-attestation` response, the last
`attestation-chain` poll). That report is in the user's log file and in the
dialog, so it's copy-pasteable straight into an issue / a model. Codes:

| Code                             | What it means                                                                                                                                                                                                                                                                         | Where to look                                                                                                                                                                     |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `secure-mode/not-enrolled`       | The Mac doesn't report MDM enrollment, so nothing can request an attestation.                                                                                                                                                                                                         | Re-run enroll (Allow + Touch ID the profile); `profiles status -type enrollment`.                                                                                                 |
| `secure-mode/push-failed`        | `push-attestation` returned `status=error` — NanoMDM enqueue/push failed.                                                                                                                                                                                                             | NanoMDM `/v1/enqueue` + `/v1/push`; that the device's UDID is a valid NanoMDM target.                                                                                             |
| `secure-mode/chain-store-error`  | The `attestation-chain` GET returned non-200 / `status=error`.                                                                                                                                                                                                                        | Console chain store + the step-ca / NanoMDM attestation webhook ingest.                                                                                                           |
| `secure-mode/chain-not-captured` | Most common. Every poll was a clean 200 `pending`; no chain landed in the window. The Attest button does **not** itself drive a hardware attestation — capture is the agent's background option-B flow (MDM-enrolled, Apple-rate-limited ~1/device/7d, agent re-requests ≤ every 6h). | Agent log for `MDA auto:` lines (request/bind); with `COCORE_MDM_WEBHOOK_DEBUG` set, `GET attestation-chain?serial=zzwebhookdebuglast` to see whether NanoMDM is posting results. |

The classifier is `AttestationDiagnostic` in
`provider-shell/Sources/CoCoreShell/SecureModeWizard.swift` (pure value type —
the code/summary mapping lives there).
