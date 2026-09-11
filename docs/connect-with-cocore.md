# Connect with co/core (for applications)

Let your users connect their co/core account to your app in one click, so your
app can run inference billed to their credits — no key copying, no OAuth client
registration with us, no scopes to negotiate. This is the same device-pairing
flow `cocore agent pair` uses, with your app's identity attached. Graze's
"Connect co/core" is the reference implementation.

## What the user sees

1. They press **Connect co/core** in your app.
2. Their browser lands on `https://cocore.dev/devices/new?code=…`. If they are
   not signed in at co/core they sign in first (a Bluesky handle works).
3. The approve screen reads *"Connect **Your App** to co/core — Verified
   application: @yourapp.example · yourapp.example"*, explains that the key can
   run inference on their credits and nothing else, and offers **Allow Your App**.
4. Approval sends them straight back to your app. Your server already has the
   key.

## What you do — once

### 1. Publish a registration record on your app's account

Your app is identified by a DID with a repo: usually the Bluesky account you
run your app from. Publish one `dev.cocore.app.registration` record at rkey
`self`:

```json
{
  "$type": "dev.cocore.app.registration",
  "name": "Your App",
  "description": "What the connection is used for, in one sentence.",
  "website": "https://yourapp.example",
  "iconUrl": "https://yourapp.example/icon.png",
  "returnUrls": ["https://yourapp.example/settings/connections"],
  "createdAt": "2026-09-11T00:00:00Z"
}
```

```sh
# with the atproto CLI of your choice; e.g. via com.atproto.repo.putRecord on your PDS
curl -sS -X POST "$PDS/xrpc/com.atproto.repo.putRecord" -H "authorization: Bearer $ACCESS_JWT" \
  -H 'content-type: application/json' \
  -d '{"repo":"did:plc:yourapp","collection":"dev.cocore.app.registration","rkey":"self","record":{…}}'
```

`name` is what users see; `returnUrls` are the only places the approve screen
will ever send a browser. There is no central registry: the record on your
account *is* the registration, and you can change or delete it any time.

### 2. Prove you control the return host

Serve `https://<return host>/.well-known/cocore-app.json`:

```json
{ "did": "did:plc:yourapp" }
```

(`{"dids": [...]}` is accepted when one host fronts several apps.) Without
this, users can still connect — the approve screen just labels your app
**unverified** and does not redirect them back to you.

## What you do — per user

### 3. Start a pairing, server-side

```sh
curl -sS -X POST https://cocore.dev/api/xrpc/dev.cocore.devicePair.start \
  -H 'content-type: application/json' \
  -d '{"appDid":"did:plc:yourapp","keyName":"Your App","returnUrl":"https://yourapp.example/settings/connections?cocore=connected"}'
```

```json
{ "deviceId": "…32 hex…", "userCode": "K7PX2M4Q",
  "verificationUri": "https://cocore.dev/devices/new?code=K7PX2M4Q",
  "pollIntervalSecs": 3, "expiresInSecs": 600 }
```

Keep `deviceId` on your server: it is the credential that collects the key.
`returnUrl` must match one of your registered `returnUrls` on origin and path;
its query string is yours to use.

### 4. Send the user to `verificationUri`

A plain top-level navigation. Same-tab works best: co/core returns them to your
`returnUrl` afterwards.

### 5. Poll for the key

```sh
curl -sS "https://cocore.dev/api/xrpc/dev.cocore.devicePair.poll?deviceId=…"
```

`{"status":"pending"}` until they act; then, exactly once,

```json
{ "status": "session", "session": { "did": "did:plc:…", "handle": "alice.bsky.social",
  "apiKey": "cocore-…", "apiBase": "https://cocore.dev" } }
```

Terminal states: `denied` (403), `expired` / `consumed` (410), `unknown` (404;
the attempt is gone — start again). **Check `session.did` is the user you
expected** before storing `apiKey`; the key belongs to whoever was signed in at
co/core. Store it encrypted; it is shown once.

### 6. Use the key

Point any OpenAI-compatible client at `https://cocore.dev/v1` with the key as
the bearer token. Jobs are billed to the user's credits; every response's
`x_cocore` block names the provider and the signed receipt.

## SDK helpers

```ts
import { startAppPairing, waitForAppPairing } from "@cocore/sdk";
const pairing = await startAppPairing({ appDid, keyName: "Your App", returnUrl });
// redirect the user to pairing.verificationUri, then:
const session = await waitForAppPairing(pairing);
```

```python
from cocore import start_app_pairing, wait_for_app_pairing
pairing = start_app_pairing("did:plc:yourapp", key_name="Your App", return_url=return_url)
# redirect the user to pairing.verification_uri, then:
session = wait_for_app_pairing(pairing)
```

## Limits and behaviour

- `start`, `describe` and `confirm` are rate-limited per client IP (30 / 120 /
  30 per ten minutes). Start pairings from your server, not the browser.
- Pairings expire after ten minutes and are held in memory; a co/core deploy
  drops them (`unknown`). Handle that by starting again.
- `dev.cocore.devicePair.describe?userCode=` is the public read the approve
  screen uses; it echoes your registration and never the `deviceId`.
- The approve screen shows **Unregistered request** for a `start` with an
  `appName` but no `appDid`. That path still works for CLIs and prototypes, but
  users are told the name was self-declared.
