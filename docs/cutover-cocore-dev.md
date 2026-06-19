# Cutover runbook: `console.cocore.dev` → `cocore.dev`

Goal: make **`cocore.dev`** the canonical console host, served on Railway, with
`console.cocore.dev` kept alive as a permanent alias (installed agents + the
tray app + `curl … | sh` all bake it in, so it can never 301 away on the
`/agent`, `/api`, `/v1`, `/xrpc`, `/.well-known` paths).

Decisions locked in:
- **Flip canonical to `cocore.dev`** (accept a one-time re-login for all users —
  the ATProto OAuth `client_id` is `https://<canonical>/api/auth/atproto/metadata.json`,
  so changing the host is a new OAuth client).
- **Move DNS to Cloudflare** for apex CNAME-flattening (DigitalOcean cannot put
  a CNAME/ALIAS at the zone apex; Railway serves custom domains by CNAME and
  gives no static apex IP).

## The blocker, in one line

`cocore.dev` (apex) must CNAME to `5srj47wl.up.railway.app`, and only a
flattening DNS provider (Cloudflare) can do that at the root.

## Current Railway state (already done — no action)

The console service already has all three custom domains attached:

| Domain | Railway-required record | Status |
|---|---|---|
| `console.cocore.dev` | CNAME → `lmy3bsgv.up.railway.app` | PROPAGATED (live) |
| `cocore.dev` | CNAME → `5srj47wl.up.railway.app` | REQUIRES_UPDATE (no DNS yet) |
| `www.cocore.dev` | CNAME → `ofg1g7be.up.railway.app` | drifted (currently `5srj47wl`) |

Railway IDs (project **co/core**):
- project `a46692ef-f462-4801-9a64-0af69ea7143d`, env `production` `9584945f-7b2f-4369-87a9-4eea8ffd7eae`
- console service `e8f485a3-fb10-4d89-8d29-d56a71673bc7`

## Step 0 — Pre-flight (do this first, no user impact)

1. **Export the DigitalOcean zone** for `cocore.dev` (DO panel → Networking →
   Domains → cocore.dev, or the API). `dig` cannot enumerate the whole zone —
   the export is the source of truth. Reconcile it against the checklist below.
2. Known records that MUST exist in Cloudflare (DNS-only / gray cloud — Railway
   terminates TLS, do **not** proxy):

   | Type | Name | Value | Proxy |
   |---|---|---|---|
   | CNAME | `@` (apex `cocore.dev`) | `5srj47wl.up.railway.app` | DNS only |
   | CNAME | `www` | `ofg1g7be.up.railway.app` | DNS only |
   | CNAME | `console` | `lmy3bsgv.up.railway.app` | DNS only |
   | CNAME | `advisor` | `h0aevzi4.up.railway.app` | DNS only |
   | CNAME | `appview` | `avjh8yxu.up.railway.app` | DNS only |
   | TXT | `_atproto` | `did=did:plc:5quuhkmwe2q4k3azfsgg7kdz` | n/a |
   | … | (anything else in the DO export — `_lexicon`, etc.) | (copy verbatim) | |

   ⚠ `_atproto.cocore.dev` is the **@cocore.dev handle verification** (DNS
   method — the HTTP `/.well-known/atproto-did` returns Not Found). If it's
   missing after the NS flip, the @cocore.dev account's handle breaks.

3. **Build the full Cloudflare zone now, but do NOT change nameservers yet.**
   Verify parity by querying Cloudflare's assigned nameservers directly before
   delegating:
   ```sh
   CFNS=<your-cloudflare-ns>   # e.g. xxx.ns.cloudflare.com
   for n in cocore.dev www.cocore.dev console.cocore.dev advisor.cocore.dev appview.cocore.dev; do
     echo "$n -> $(dig @$CFNS +short $n)"
   done
   dig @$CFNS +short _atproto.cocore.dev TXT   # must be did:plc:5quuhk…
   ```
   The apex should return Railway's flattened A records; the subdomains their
   CNAME targets; `_atproto` the DID. Only proceed once this matches.

## Step 1 — Merge the cookie-domain PR (safe, forward-compatible)

Branch: `console/cookie-domain-cocore-dev` (this PR). It scopes the auth session
cookie to `cocore.dev` so a login on the apex is also valid on
`console.cocore.dev`. It's a no-op until `cocore.dev` serves, and harmless on
`console.cocore.dev` today (a subdomain of `cocore.dev`). Merge → console
redeploys.

## Step 2 — Flip nameservers (registrar)

Switch the `cocore.dev` NS from DigitalOcean (`ns1/2/3.digitalocean.com`) to the
two Cloudflare nameservers. `console`/`advisor`/`appview` keep working
throughout because their records are identical in both zones; `cocore.dev`
(apex) starts resolving once delegation lands.

## Step 3 — Let Railway issue the apex cert

Poll until `cocore.dev` flips to PROPAGATED and the cert is issued:
```sh
cat > /tmp/dq.json <<'JSON'
{"query":"{ domains(projectId: \"a46692ef-f462-4801-9a64-0af69ea7143d\", environmentId: \"9584945f-7b2f-4369-87a9-4eea8ffd7eae\", serviceId: \"e8f485a3-fb10-4d89-8d29-d56a71673bc7\") { customDomains { domain status { dnsRecords { recordType requiredValue currentValue status } } } } }"}
JSON
curl -s -H "Authorization: Bearer $RAILWAY_API_TOKEN" -H "Content-Type: application/json" \
  --data @/tmp/dq.json https://backboard.railway.app/graphql/v2 | python3 -m json.tool
```
Then confirm TLS: `curl -sI https://cocore.dev | head -1` (expect 200/3xx, valid cert).

## Step 4 — Flip the canonical env on Railway (the user-visible moment)

This is what re-points OAuth at `cocore.dev` and logs everyone out once. Do it
deliberately, after Step 3 succeeds. Set on the **console** service:

| Var | Value | Why |
|---|---|---|
| `CONSOLE_PUBLIC_URL` | `https://cocore.dev` | OG/share + OAuth fallback |
| `PUBLIC_URL` | `https://cocore.dev` | OG/share primary (`getPublicUrl`) |
| `BETTER_AUTH_URL` | `https://cocore.dev` | OAuth primary (`getBaseUrl`) |

Also check the Railway dashboard for `ATPROTO_BASE_URL` / `VITE_PUBLIC_URL` — if
either is currently pinned to `console.cocore.dev`, override to `https://cocore.dev`
(both take precedence over the fallbacks).

Ready-to-run (per var; repeat name/value):
```sh
cat > /tmp/vq.json <<'JSON'
{"query":"mutation { variableUpsert(input: { projectId: \"a46692ef-f462-4801-9a64-0af69ea7143d\", environmentId: \"9584945f-7b2f-4369-87a9-4eea8ffd7eae\", serviceId: \"e8f485a3-fb10-4d89-8d29-d56a71673bc7\", name: \"CONSOLE_PUBLIC_URL\", value: \"https://cocore.dev\" }) }"}
JSON
curl -s -H "Authorization: Bearer $RAILWAY_API_TOKEN" -H "Content-Type: application/json" \
  --data @/tmp/vq.json https://backboard.railway.app/graphql/v2
```
The upsert triggers a redeploy.

## Step 5 — Verify

```sh
# canonical OG/OAuth now cocore.dev
curl -s https://cocore.dev/api/auth/atproto/metadata.json | python3 -m json.tool | grep client_id
# expect: "client_id": "https://cocore.dev/api/auth/atproto/metadata.json"

# agents still work on the alias (must NOT have moved)
curl -s https://console.cocore.dev/agent/version    # v0.9.17
curl -s https://appview.cocore.dev/xrpc/dev.cocore.appview.getReceipts?limit=1 -o /dev/null -w '%{http_code}\n'

# handle still verifies
dig +short _atproto.cocore.dev TXT                  # did:plc:5quuhk…
```
Then: log in on `https://cocore.dev` end-to-end; confirm the session cookie is
`Domain=cocore.dev`; load `https://console.cocore.dev` and confirm you're still
signed in (shared cookie).

## Rollback

- **App canonical bad (cert/OAuth):** revert the three env vars to
  `https://console.cocore.dev` and redeploy — instant; restores the old OAuth
  client. (The DNS can stay on Cloudflare.)
- **Cloudflare misbehaving:** flip NS back to DigitalOcean (slower; propagation
  lag). The DO zone still exists, unchanged.
- **Cookie PR bad:** revert the PR.

## Optional follow-ups (not required for the cutover)

- 301 `www.cocore.dev` → `https://cocore.dev`.
- 301 `console.cocore.dev` **page** routes → `cocore.dev`, **excluding**
  `/agent*`, `/api/*`, `/v1/*`, `/xrpc/*`, `/.well-known/*`, `/oauth*`.
- Flip the ~40 hardcoded `console.cocore.dev` defaults in console routes + docs
  to `cocore.dev`. The tray/provider defaults move on their next release; agents
  keep working via the `console.cocore.dev` alias meanwhile.
