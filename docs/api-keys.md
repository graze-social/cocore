# API keys

cocore API keys are bearer tokens that let scripts, agents, and other
automation act for your account without driving a browser session. The same
key authenticates inference (`dev.cocore.inference.*`), the record proxy
(`dev.cocore.proxy.*`), and the key-management endpoints documented here.

A key looks like `cocore-<43 url-safe base64 chars>` — 256 bits of entropy.
The server stores only a SHA-256 hash plus a short displayable `prefix`
(e.g. `cocore-AbCd1234`); the full secret is shown **exactly once**, at
creation, and is unrecoverable afterward.

The key-management methods are defined by lexicons under `dev.cocore.account.*`
(published as resolvable `com.atproto.lexicon.schema` records, see
[`lexicons/README.md`](../lexicons/README.md)) and are reachable two ways:

- **`/xrpc/<nsid>`** — the proper AT Protocol surface, authenticated by
  **service auth** (recommended; no bootstrapping problem). See below.
- **`/api/xrpc/<nsid>`** — the legacy alias, authenticated by an existing
  bearer key or the console session cookie.

## Authentication

### Service auth (the `/xrpc/*` surface)

The `/xrpc/dev.cocore.account.*` endpoints authenticate **only** with an AT
Protocol service-auth token — a short-lived JWT signed by the signing key in
*your* DID document. You don't craft it by hand: your client asks its own PDS
to proxy the call, and the PDS mints and attaches the JWT. With an `atproto`
agent that's just the `atproto-proxy` header:

```ts
// agent already authenticated to the requester's PDS
await agent.call(
  "dev.cocore.account.listApiKeys",
  {},
  { headers: { "atproto-proxy": "did:web:console.cocore.dev#cocore_account" } },
);
```

The PDS resolves the console's DID document (served at
`https://console.cocore.dev/.well-known/did.json`), forwards the request to
`https://console.cocore.dev/xrpc/<nsid>`, and signs a JWT whose `iss` is your
DID, `aud` is `did:web:console.cocore.dev`, and `lxm` is the method NSID. The
console verifies that signature against your DID document — so a valid token is
proof you control the DID, with no shared secret. This is the recommended path:
because you authenticate with your own identity, there's nothing to bootstrap.

A missing, malformed, expired, wrong-audience, or wrong-`lxm` token returns
`401` (`AuthRequired`, `BadJwt`, `JwtExpired`, `BadJwtAudience`,
`BadJwtLexicon`, `BadJwtIssuer`, or `BadJwtSignature`).

### Bearer key / session (the legacy `/api/xrpc/*` surface)

The `/api/xrpc/dev.cocore.account.*` aliases accept either credential:

- **`Authorization: Bearer cocore-...`** — an existing API key. Mint one key
  from the console UI, then create, list, revoke, and delete the rest headlessly.
- **Console session cookie** — what the signed-in web UI sends.

The owning DID is derived from whichever credential you present, and every
operation is scoped to that DID — you can only ever touch your own keys. A
missing or invalid credential returns `401` with `{ "error": "AuthRequired" }`.

> **Bootstrapping.** Creating your *first* key over the bearer-key path needs a
> credential you didn't mint via the API: sign in to the console and create one
> key under **Account → API keys**, or let `cocore agent pair` mint one for a
> machine. The service-auth `/xrpc/*` path above avoids this entirely.

## Endpoints

The examples below use the legacy bearer-key base URL
`https://console.cocore.dev/api/xrpc`. The same NSIDs, bodies, and responses
are served at `https://console.cocore.dev/xrpc/<nsid>` under service auth —
swap the base URL and the `Authorization` header accordingly.

### `dev.cocore.account.createApiKey` — mint a key

`POST`. Body `{ name: string, expiresAt?: string | null }`. Returns the new
key's metadata plus the one-time `secret`.

```sh
curl -sS -X POST \
  'https://console.cocore.dev/api/xrpc/dev.cocore.account.createApiKey' \
  -H 'Authorization: Bearer cocore-YOUR-EXISTING-KEY' \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci-runner","expiresAt":"2027-01-01T00:00:00Z"}'
```

```json
{
  "key": {
    "id": "9b1c…",
    "did": "did:plc:…",
    "name": "ci-runner",
    "prefix": "cocore-AbCd1234",
    "createdAt": "2026-06-19T12:00:00.000Z",
    "expiresAt": "2027-01-01T00:00:00.000Z"
  },
  "secret": "cocore-AbCd1234…the-full-43-char-secret"
}
```

Store `secret` now; it is never returned again. Omit `expiresAt` (or send
`null`) for a key that never expires on its own.

### `dev.cocore.account.listApiKeys` — list your keys

`GET`. No parameters — the account is taken from your credential. Returns
every key, newest first. Secrets are never included.

```sh
curl -sS \
  'https://console.cocore.dev/api/xrpc/dev.cocore.account.listApiKeys' \
  -H 'Authorization: Bearer cocore-YOUR-KEY'
```

```json
{
  "keys": [
    {
      "id": "9b1c…",
      "did": "did:plc:…",
      "name": "ci-runner",
      "prefix": "cocore-AbCd1234",
      "createdAt": "2026-06-19T12:00:00.000Z",
      "lastUsedAt": "2026-06-19T12:05:00.000Z"
    }
  ]
}
```

A revoked key stays in the list with `revokedAt` set, until it's deleted.

### `dev.cocore.account.revokeApiKey` — revoke a key

`POST`. Body `{ id: string }` (the `id` from create/list). The key stops
authenticating immediately; the row is retained with `revokedAt` set so it
remains visible for audit. Idempotent — revoking an unknown or
already-revoked key returns `{ "revoked": false }`.

```sh
curl -sS -X POST \
  'https://console.cocore.dev/api/xrpc/dev.cocore.account.revokeApiKey' \
  -H 'Authorization: Bearer cocore-YOUR-KEY' \
  -H 'Content-Type: application/json' \
  -d '{"id":"9b1c…"}'
```

```json
{ "revoked": true }
```

### `dev.cocore.account.deleteApiKey` — delete a key

`POST`. Body `{ id: string }`. Hard-deletes the row (no audit-trail recovery).
Prefer `revokeApiKey` for most flows; use this to clean up revoked or expired
keys you no longer want listed. Idempotent — deleting an unknown key returns
`{ "deleted": false }`.

```sh
curl -sS -X POST \
  'https://console.cocore.dev/api/xrpc/dev.cocore.account.deleteApiKey' \
  -H 'Authorization: Bearer cocore-YOUR-KEY' \
  -H 'Content-Type: application/json' \
  -d '{"id":"9b1c…"}'
```

```json
{ "deleted": true }
```

## Errors

| Status | Body                              | Meaning                                            |
| ------ | --------------------------------- | -------------------------------------------------- |
| `401`  | `{ "error": "AuthRequired" }`     | No valid session cookie or bearer key presented.   |
| `400`  | `{ "error": "InvalidRequest" }`   | Malformed JSON, or a field failed validation.      |

## A note on scope

A bearer key can mint and delete other keys for the same account, so treat
it like a password. Revoke any key you suspect is leaked — that severs every
capability it carried (inference, the proxy, and key management alike) in one
step, while leaving a `revokedAt` audit marker behind.
