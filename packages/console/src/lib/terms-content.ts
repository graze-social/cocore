// Terms of Service + Privacy Policy text for the cocore.dev exchange.
//
// Bumping the version string forces every signed-in user to re-accept
// before they can use the console — the active dev.cocore.compute.exchangePolicy
// carries this version, and the modal compares it against the user's
// most recent dev.cocore.compute.termsAcceptance.
//
// Process when changing terms:
//   1. Edit `tos` / `privacy` below.
//   2. Bump `version`.
//   3. Set COCORE_TERMS_VERSION to match on the services container.
//   4. Deploy. Next bootstrap publishes a fresh exchangePolicy; the
//      modal lights up for everyone.

export const termsContent = {
  version: "v3-2026-07-01",
  effectiveDate: "2026-07-01",
  tos: `# Terms of Service

**Effective:** 2026-07-01 · **Version:** v3

co/core is **alpha software**. Read the entire document before using
it.

## What co/core is

co/core is an experimental ATProto-native protocol for decentralized
compute. Anyone can run the **provider agent** (a Rust binary you
install on your own Mac) to serve work, or use the **console / API**
to dispatch jobs to other people's machines.

## What you accept by installing the provider agent

By installing or running the co/core provider agent on any machine
you control, you affirmatively accept that:

1. **The software has not been independently security-audited.** It
   was built rapidly with significant assistance from generative AI
   tooling. The co/core maintainers have not subjected it to
   third-party review, fuzzing, or formal verification. There may
   be vulnerabilities — known or unknown — that allow attackers to
   exfiltrate prompts, modify replies, escape the hardened-runtime
   sandbox, or otherwise compromise the integrity of work served on
   your machine.

2. **You assume the risk.** You alone are responsible for any
   damage, data loss, financial loss, downtime, or other harm that
   results from running the agent. The co/core maintainers,
   contributors, and operators of the cocore.dev exchange disclaim
   responsibility for any such harm to the maximum extent permitted
   by applicable law.

3. **Hardened-runtime is best-effort.** The agent applies
   PT_DENY_ATTACH, blocks debugger attachment, and runs in a
   process configured to deny memory reads. These mitigations
   raise the bar against casual snooping by the machine operator —
   they do **not** guarantee that the operator cannot read prompts
   they choose to serve. If you're a requester sending sensitive
   prompts, treat every provider as semi-trusted.

## What you accept by sending work

By submitting a job to any provider through co/core (whether through
the in-app console, the OpenAI-compatible API, or any other
client), you affirmatively agree that:

1. **You will not attempt to harm other machines.** Prompts that
   instruct the model to write malware, scan networks, exploit
   the provider's host, exfiltrate data, or attempt privilege
   escalation are prohibited. Prompts that try to manipulate the
   provider agent's signed receipts, attestation chain, or
   cryptographic identity are prohibited.

2. **You take responsibility for the prompts you send.** Some
   providers may log inputs. The co/core-provided console encrypts
   prompts to the provider's published key before transit, but
   the provider itself decrypts and processes the plaintext —
   anything you send is potentially observable to the provider.

3. **Compute is priced in tokens, not dollars.** co/core runs a
   **closed-loop token economy**. There is no card on file, no
   fiat settlement, no Stripe in the middle, and no exchange rate
   between co/core tokens and any outside currency. The active
   exchange (operated by whoever publishes the
   \`dev.cocore.compute.exchangePolicy\` you accepted) denominates
   everything in **tokens** (currency code \`CC\`) and publishes
   every parameter that moves your balance:

   - **Onboarding grant.** Your DID receives a one-time grant the
     first time it touches the exchange — the policy's
     \`tokenGrant\`, currently **1,000,000 tokens** on cocore.dev.
     Issued exactly once per DID and recorded as a
     \`dev.cocore.account.tokenGrant\` record on your PDS.
   - **Uniform rate.** The exchange pins a single \`tokenRate\`
     that applies to every provider and model; cocore.dev settles
     at **one balance token per model token** (1:1), so a
     million-token completion costs a million tokens. Providers
     settling through the exchange MUST price receipts at this
     rate — their own \`dev.cocore.compute.provider.priceList\` is
     informational for client display today, not authoritative.
   - **The 95/5 split.** When a provider publishes a receipt, the
     exchange debits the receipt's token price from your balance,
     credits **95%** to the provider, and routes the remaining
     **5%** (\`fee.bps = 500\`) to the treasury. No tokens are
     minted or burned — the balance changes sum to zero. The fee
     sits on the provider's side of the ledger, so you see a single
     debit equal to the receipt price, never a separate surcharge
     "on top." Jobs you run on your own machine through the
     exchange (requester DID == provider DID) have the fee waived.
   - **Admission floor.** The exchange refuses a new job if it
     would leave your balance below \`tokenFloor\` — currently
     **100,000 tokens** — so an unlucky completion can't push you
     negative at settlement time. If you're under the floor the
     job doesn't run; you wait for the next refresh.
   - **Refresh + rebate.** Active members accrue a small weekly
     refresh (\`weeklyRefresh\`, currently **70,000 tokens**,
     issued lazily on your next balance touch), and once a month
     the treasury redistributes the bulk of its accumulated fees
     back to active members as a patronage rebate
     (\`patronageDistribution\`), in proportion to how much they
     used and supplied the network.
   - **Balances are experimental and are not money.** Token
     metering, settlement, credits, grants, and rebates are
     experimental and may be incorrect, delayed, reversed, or lost
     — including through bugs in the agent or exchange, or a
     provider's self-reported usage. Tokens (\`CC\`) have no cash
     value, are not redeemable, and confer no entitlement. Do not
     rely on a balance.

   Every one of these numbers is a field on the active policy
   record, signed under the exchange's DID, so you can verify the
   rules offline rather than taking our word for them. You can
   switch exchanges at any time by editing your job's
   \`acceptedExchanges\` field; a different exchange may publish a
   different rate, fee, grant, or cadence.

## Attestation and the confidential tier are experimental

Some providers advertise a **hardware-attested** trust level or an
**attested-confidential** tier. These are experimental, best-effort
signals — **not** independently audited or proven guarantees:

1. **Attestation** is our best-effort check that a machine is
   genuine Apple hardware running a known build. We do not treat it
   as independently verified, and it may be wrong, stale, or worked
   around in ways we have not ruled out. Do not rely on a
   trust-level badge as proof of anything.

2. **The confidential tier** aims to keep your prompt unreadable to
   the machine's operator by running inference inside a measured,
   signed build under a hardened runtime, with the agent's signing
   and prompt-decryption keys held in the Secure Enclave so the
   operator can't copy them to another machine. It is a raised bar,
   **not** a hardware enclave for compute, and it is not audited: a
   compromised OS, an agent bug, a mis-routed request, or a
   maliciously substituted build could still expose your prompt.
   Treat every provider as semi-trusted, and **do not send anything
   through a confidential provider that you could not tolerate the
   operator reading.**

These features may change, regress, or be withdrawn at any time
without notice.

## Generative-AI disclosure

A meaningful fraction of co/core's source code, documentation,
deployment scripts, and these terms themselves were drafted with
the help of large language models, including pair-programming
sessions with Anthropic's Claude. Human maintainers reviewed each
PR before merge, but the volume of AI-generated content is high
relative to typical software at this stage. **Treat the
implementation accordingly.**

## No warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Acceptance

Your acceptance of these terms is recorded as a
\`dev.cocore.compute.termsAcceptance\` record on your ATProto PDS.
That record is portable: any future co/core-aware client can verify
that you accepted version \`v2\` on a specific date, against a
specific exchange's policy.

If you don't agree with any of the above, **do not click "I agree"**
and do not run the provider agent.
`,
  privacy: `# Privacy Policy

**Effective:** 2026-07-01 · **Version:** v3

co/core stores as little personal data as it can while still
functioning as an open, ATProto-native protocol.

## What we collect

The **cocore.dev exchange** (which you may or may not be using —
exchanges are federable and anyone can run their own) collects:

- **Your DID** — the ATProto identity you signed in with. This is
  public information by design. If you signed up via Bluesky,
  it's the same DID that backs your Bluesky handle.
- **API keys you mint** — stored hashed (SHA-256, no salt because
  the input is already 256 bits of entropy). The plaintext key is
  shown to you exactly once at creation; we cannot recover it.
- **OAuth session tokens** — the access + refresh tokens issued
  by your PDS, plus the DPoP private JWK. Stored encrypted at
  rest in our SQLite session store; used only to publish records
  to your repo on your behalf.
- **Records you publish** — every \`dev.cocore.compute.*\` record
  you create lives on your own PDS (e.g. bsky.network for a
  Bluesky DID). cocore.dev caches a copy in our AppView's local
  index so dashboards load fast; deleting the record from your
  PDS removes it from the index.

## What we don't collect

- We do **not** store inference prompts in plaintext. The console
  encrypts each prompt to the chosen provider's published X25519
  key before it leaves your browser. The exchange never sees
  decrypted prompts.
- We do **not** retain provider-side replies. The console
  decrypts them in-process to stream back to your client and
  drops them; the AppView only indexes the metadata receipt
  (token counts, price, attestation strong-ref).
- We do **not** sell, license, or share your data with third
  parties. There is no advertising network. There is no analytics
  pixel.
- We do **not** track non-signed-in visitors beyond the access
  logs on Railway, Cloudflare, and the GitHub release-asset CDN —
  same logs that any other operator's HTTP service collects.
- Confidentiality from the **provider** is a separate, experimental
  feature (see the Terms). The exchange not seeing your prompt does
  not mean the provider machine's operator cannot — treat the
  confidential tier as unproven and don't send a provider anything
  you'd need kept private.

## Where data lives

- **Your records** (\`dev.cocore.compute.*\`) — your PDS
  (Bluesky's host, or whatever PDS your DID resolves to).
- **AppView index** — SQLite on a Railway volume mounted into the
  cocore.dev services container. Records keyed by ATProto URI;
  re-buildable from the source PDS firehose.
- **API keys + OAuth sessions** — SQLite on a Railway volume
  mounted into the cocore.dev console container.
- **Static page logs** — Railway / Cloudflare access logs;
  retention is whatever the underlying providers default to.

## Your rights

- **Delete everything**: the \`/account\` page has a "Wipe all my
  data" button that deletes every record you own across all
  co/core collections from your PDS, removes the corresponding
  rows from cocore.dev's AppView, and hard-deletes every API key.
- **Take your data with you**: every record is on your own PDS in
  open ATProto format. You can export your repo with
  \`com.atproto.sync.getRepo\` at any time without going through
  cocore.dev.
- **Sign out**: clears the cookie locally. The OAuth session in
  our SQLite store stays alive (so any API keys you've minted keep
  working) — to fully revoke server-side credentials, revoke each
  key individually on \`/account\` first.

## Generative-AI disclosure

This privacy policy was drafted with the help of generative AI
tooling and reviewed by human maintainers. The codebase that
implements it was built the same way.

## Contact

This is alpha-stage hobby/research software. Bug reports and
privacy questions go to GitHub issues at
https://github.com/graze-social/cocore .
`,
};
