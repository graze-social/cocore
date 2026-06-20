#!/usr/bin/env bash
# Configure a Railway per-PR preview environment so it self-references.
#
# Railway clones each PR environment (`cocore-pr-<N>`) from `production`, which
# uses custom domains (console.cocore.dev / cocore.dev). So a fresh clone points
# its public URLs + service DID at PROD and is missing the new-code gating vars
# (COCORE_APPVIEW_DID, COCORE_ADVISOR_URL, the internal secret, the AppView's
# OAuth key). We can't fix this by converting production to ${{ RAILWAY_* }}
# reference variables — that would break prod's custom domains. Instead this
# script rewrites the PR env's vars to its OWN deterministic Railway domains
# (`<service>-cocore-pr-<N>.up.railway.app`) and copies/fills the shared
# secrets, then redeploys. Idempotent — safe to re-run on every push.
#
# Usage:
#   ./scripts/configure-pr-env.sh <pr-number>
#   PR_NUMBER=26 ./scripts/configure-pr-env.sh
#
# Auth: uses the ambient Railway login (your CLI session locally, or
# RAILWAY_TOKEN in CI). Needs access to the project's PR environments.

set -euo pipefail

PR="${1:-${PR_NUMBER:-}}"
[[ -n "$PR" ]] || { echo "usage: $0 <pr-number>" >&2; exit 2; }

ENV="cocore-pr-$PR"
CONSOLE_URL="https://console-$ENV.up.railway.app"
ADVISOR_URL="https://advisor-$ENV.up.railway.app" # HTTP base (server-side /providers, /jobs)
SERVICES_DID="did:web:services-$ENV.up.railway.app"

note() { printf '  %s\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }

get() {
  railway variables --service "$1" --environment "$ENV" --json 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('$2') or '')"
}

bold "==> configuring $ENV"

# Idempotency guard: if services already targets its own DID, this env is
# configured — skip (no var writes, no redeploy). Lets the CI workflow run on
# every push harmlessly; it only acts on a freshly cloned env. Override with
# FORCE=1 to reconfigure regardless.
if [[ "${FORCE:-0}" != "1" && "$(get services COCORE_APPVIEW_DID)" == "$SERVICES_DID" ]]; then
  bold "==> $ENV already configured (services COCORE_APPVIEW_DID == $SERVICES_DID) — nothing to do"
  exit 0
fi

# Shared secrets that must be IDENTICAL across console + services in this env.
# The AppView OAuth key is cloned from prod (present on console); copy it to
# services. The internal secret isn't cloned — reuse the console's if it has
# one, else mint a fresh one for this env.
KEY="$(get console ATPROTO_PRIVATE_KEY_JWK)"
[[ -n "$KEY" ]] || { echo "ERROR: $ENV console has no ATPROTO_PRIVATE_KEY_JWK (clone incomplete)" >&2; exit 1; }
SECRET="$(get console COCORE_INTERNAL_SECRET)"
[[ -n "$SECRET" ]] || SECRET="$(get services COCORE_INTERNAL_SECRET)"
[[ -n "$SECRET" ]] || SECRET="$(openssl rand -hex 32)"
note "secrets resolved (OAuth key + internal secret)"

# Console: own public URLs + the services DID it service-auths against.
railway variables --service console --environment "$ENV" --skip-deploys \
  --set "COCORE_ADVISOR_URL=$ADVISOR_URL" \
  --set "COCORE_APPVIEW_DID=$SERVICES_DID" \
  --set "COCORE_APPVIEW_INTERNAL_URL=http://services.railway.internal:8081" \
  --set "COCORE_INTERNAL_SECRET=$SECRET" \
  --set "CONSOLE_PUBLIC_URL=$CONSOLE_URL" \
  --set "PUBLIC_URL=$CONSOLE_URL" \
  --set "BETTER_AUTH_URL=$CONSOLE_URL" >/dev/null
note "console vars set"

# Services (AppView): own DID, the console it points back at, OAuth key, advisor.
railway variables --service services --environment "$ENV" --skip-deploys \
  --set "ATPROTO_BASE_URL=$CONSOLE_URL" \
  --set "ATPROTO_PRIVATE_KEY_JWK=$KEY" \
  --set "COCORE_ACCOUNT_DB=/data/account.db" \
  --set "COCORE_ADVISOR_URL=$ADVISOR_URL" \
  --set "COCORE_APPVIEW_DID=$SERVICES_DID" \
  --set "COCORE_INTERNAL_SECRET=$SECRET" \
  --set "CONSOLE_PUBLIC_URL=$CONSOLE_URL" >/dev/null
note "services vars set"

# Redeploy both from the PR branch source so the new vars take effect.
railway redeploy --service services --environment "$ENV" --yes >/dev/null 2>&1 || true
railway redeploy --service console --environment "$ENV" --yes >/dev/null 2>&1 || true
bold "==> $ENV configured + redeploying"
note "console:  $CONSOLE_URL"
note "advisor:  $ADVISOR_URL"
note "appview:  $SERVICES_DID"
