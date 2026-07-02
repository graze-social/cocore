# cocore on Linux (`feature/linux-support`)

This branch turns a Linux box into a cocore compute provider: the agent
receives encrypted prompts, runs them on your GPU(s) via a **managed
`llama-server`** (llama.cpp), and publishes P-256-signed receipts to its
ATProto repo — mirroring the macOS provider's shape, lifecycle, and security
posture as closely as Linux allows, and being explicit where it can't.

Everything below is implemented and tested on this branch unless marked with
an annotation:

> **DECISION** — needs a maintainer call before/at merge.
> **FOLLOW-UP** — scoped work deliberately left out of this branch.
> **NOTE** — context a reviewer should have.

---

## What works today

| Area | Status |
|---|---|
| Build + full test suite on Linux | ✅ 269 tests, clippy clean, rustfmt clean (default features; rebased on v0.9.39 main) |
| **Validated live against the production network** | ✅ see [Live validation](#live-validation-against-production) |
| Real machine telemetry (`/proc`, `/sys`, `/etc/os-release`, DMI, NVIDIA GPU count) | ✅ |
| Managed inference: agent spawns/supervises/restarts `llama-server` per model, GGUF auto-download from HF | ✅ |
| Unmanaged escape hatch: proxy to any OpenAI-compatible endpoint | ✅ |
| systemd user-unit service management (`models` / `doctor --fix` / `update` / post-`pair` restart) | ✅ |
| Billing for GGUF models (uniform off-catalog rate, exact llama-server token counts) | ✅ |
| Honest Linux attestation: Secure Boot (efivars), kernel lockdown, Yama anti-debug, binary self-measurement, hypervisor detect | ✅ |
| TPM 2.0 quote **verifier** (structure + ECDSA + key binding), validated against real swtpm **and** real AMD fTPM output | ✅ |
| Confidential tier | ❌ by design — Linux is `best-effort` (see [Trust model](#trust-model-on-linux)) |
| `trustLevel: hardware-attested` via TPM | ⏳ wired but **fail-closed** (see [TPM](#tpm-hardware-attestation-status)) |

## Quick start (from a checkout)

Prereqs: Rust toolchain, `cmake` + a C compiler (for `aws-lc-rs`),
`ca-certificates` (the advisor WSS anchors in the OS trust store), and a
`llama-server` binary built with your GPU backend (CUDA / ROCm / Vulkan) —
this branch deliberately does **not** build llama.cpp for you.

```bash
cd provider && cargo build --release
COCORE_LLAMA_SERVER_BIN=/usr/local/bin/llama-server \
  ../scripts/install-linux-provider.sh
```

The installer places the binary at `~/.local/bin/cocore`, writes the static
config to `~/.cocore/provider.env`, pairs (`cocore agent pair`), installs +
enables the **systemd user unit** `cocore-provider.service`, and enables
linger so the service survives logout. Then:

```bash
cocore agent models add bartowski/Qwen2.5-7B-Instruct-GGUF
journalctl --user -u cocore-provider -f     # watch the engine-load + register sequence
cocore agent doctor                         # session / service / version / auth / health
```

> **FOLLOW-UP** — there is no `curl | sh` path for Linux yet: the console's
> `/agent` route is Darwin-gated and release CI builds only the macOS
> tarball. `update.rs` already sends `linux-x86_64` / `linux-arm64` arch
> labels, so the client side is ready; the console `/agent/dl` proxy and a
> Linux release job (with `ldd`/`readelf` replacing the `otool` no-libpython
> check) are the missing halves. Until then: checkout install, above.

## Architecture: how it mirrors the Mac

The macOS provider's engine is a **managed subprocess** (`SubprocessEngine`
spawning vllm-mlx). The Linux mirror is `engines/llama_server.rs`:

| Property | macOS `SubprocessEngine` | Linux `LlamaCppEngine` |
|---|---|---|
| Backend | vllm-mlx (Python child, MLX weights) | `llama-server` (llama.cpp, GGUF) |
| Weight download | automatic (HF, inside the child) | automatic (`-hf <repo>`; `COCORE_HF_TOKEN` honored via the same `apply_hf_download_env`) |
| Transport | Unix socket (uid-gated) | TCP loopback + per-instance random `--api-key` |
| Readiness | stall-based (300 s no-progress, 6 h hard cap) | same constants; progress = child output activity |
| Health / restart | `ready()` = child alive; watchdog `restart()` | same (fresh port per respawn) |
| Teardown | SIGTERM → 5 s → SIGKILL, poison-tolerant locks | same, plus `PR_SET_PDEATHSIG` so the kernel reaps the child if the agent dies |
| Parent-death failsafe | Python `getppid()` poll thread | kernel `PR_SET_PDEATHSIG` (strictly stronger) |
| Tool calls | startup canary before advertising | same canary (`--jinja` + forced function call) |
| Inference wire code | hand-rolled UDS HTTP + SSE | delegates to `OpenAiEngine` (same OpenAI SSE shape — body building, `<think>` splitting, ToolCall channel are shared, not duplicated) |
| Child output | 64-line ring buffer, **never** tracing (prompt-leak safety) | same |
| `in_process()` | `false` (subprocess) | `false` — Linux stays best-effort |

**Engine selection in `build_engines`** (first match wins, after the
empty-model-set early return):

1. `COCORE_NATIVE_MLX_MODEL` — macOS confidential in-process engine (feature-gated, never on Linux)
2. **`COCORE_LLAMA_SERVER_BIN` — the managed Linux path (primary)**
3. `COCORE_OPENAI_BASE_URL` — unmanaged proxy to an endpoint you run yourself (no restart/terminate lifecycle; escape hatch, not a mirror)
4. venv subprocess (vllm-mlx) — the macOS default

Per-model recovery matches the Mac: 3 attempts, 8 s·attempt backoff. New
`EngineFault` codes: `llama-server-missing` (binary not found — actionable),
and the llama variant of `model-load-failed` (GGUF-format hint instead of the
MLX one).

**The model set is NOT a local file on Linux.** The PDS `desiredModels`
record is the source of truth (invariant #1): `cocore agent models add`
writes it and restarts the unit; the serve loop reconciles it into
`COCORE_INFERENCE_MODELS` at startup (`inference_models_action`), exactly as
the website's model picker drives a Mac. This is why the Linux `models_cli`
arm is a fraction of the macOS PlistBuddy machinery — parity without a
duplicate local store.

### Service management parity

| macOS | Linux |
|---|---|
| LaunchAgent `dev.cocore.provider.plist` | systemd user unit `cocore-provider.service` (template in `scripts/`) |
| `KeepAlive{SuccessfulExit:false}` / `ThrottleInterval 10` | `Restart=on-failure` / `RestartSec=10` |
| serve-loop exit 3 (config reload) / 7 (engine death) → launchd respawn | same exit codes → systemd respawn |
| plist `EnvironmentVariables` | `EnvironmentFile=~/.cocore/provider.env` (static config only) |
| `launchctl print` / `kickstart -k` (doctor, models, update, pair) | `systemctl --user is-active` / `restart` via `provider/src/service.rs` |
| `~/.cocore/logs/{stdout,stderr}.log` | journald (`journalctl --user -u cocore-provider`) + the agent's own `~/.cocore/logs/agent.log` |

`~/.cocore/` layout (identity.pem, session.json, logs/) is unchanged from
macOS. All cross-cutting subsystems (protocol, advisor, pds, oauth,
diagnostics, geoip, schedule) were audited and run unchanged on Linux; the
only `#[cfg]`-gated wire field is `apns_device_token`, which correctly
compiles to `None`.

## Configuration reference (Linux-relevant)

| Var | Meaning | Default |
|---|---|---|
| `COCORE_LLAMA_SERVER_BIN` | path to `llama-server`; **selects the managed Linux engine** | unset |
| `COCORE_LLAMA_NGL` | `-ngl` GPU layers | `999` (offload everything; llama.cpp clamps) |
| `COCORE_LLAMA_EXTRA_ARGS` | raw passthrough (whitespace-split, no shell) — multi-GPU knobs live here: `--tensor-split`, `--split-mode`, `--ctx-size`; or pin per-instance GPUs with `CUDA_VISIBLE_DEVICES` | unset |
| `COCORE_ENABLE_TOOL_CALLS` | adds `--jinja`; advertised only after the canary passes | off |
| `COCORE_INFERENCE_MODELS` | bootstrap model set; superseded by PDS `desiredModels` after first serve | unset → stub only |
| `COCORE_OPENAI_BASE_URL` / `COCORE_OPENAI_API_KEY` | unmanaged OpenAI-compatible proxy path | unset |
| `COCORE_HF_TOKEN` (or `HF_TOKEN`…) | authenticated GGUF downloads | anonymous |
| `COCORE_CONSOLE` / `COCORE_ADVISOR` / `COCORE_LOG` / `COCORE_MACHINE_LABEL` / `COCORE_SERVE_START/END` / `COCORE_MODEL_SCHEDULES` | unchanged from macOS; persisted in `provider.env` instead of the plist | — |

Model ids: a HuggingFace repo (`org/name`) is fetched as GGUF via
`llama-server -hf`; an absolute path is served locally via `-m`.

**Billing**: off-catalog ids (all GGUF ids) are priced at the uniform
exchange rate on **both** the advertised `priceList` and the signed receipt —
this branch fixed `rate_for()` to fall back to a named `UNIFORM_RATE` instead
of coincidentally-matching `RATES[0]`, so the two agree by construction.
Token counts come from llama-server's real `usage`, not the estimator.

> **DECISION** — confirm the uniform 1:1 CC rate is the *intended* policy for
> GGUF/off-catalog models, or whether GGUF entries should be added to the
> catalog with their own rates.

> **FOLLOW-UP** — GGUF models get **no RAM-floor / overprovision guard** (the
> catalog floors are MLX-4-bit-specific, so they're inert for GGUF and
> intentionally skipped). An oversized model fails at `start()` with an
> honest `EngineFault` instead of being pre-filtered. A GGUF-aware estimator
> (params × bytes-per-quant + KV headroom) is the right fix; a static catalog
> doesn't scale to open-ended GGUF ids.

> **FOLLOW-UP** — the interactive model picker (`models add` with no arg)
> still lists the MLX catalog and uses MLX wording; it *accepts* any typed
> `org/name`, so GGUF works, but the copy should say so on Linux.

## Trust model on Linux

Two orthogonal axes, both reported **honestly** — the producer can never
over-claim (missing evidence always degrades, never elevates):

**Confidentiality tier → always `best-effort`.** `llama-server` is a
subprocess, so `inProcessBackend=false` — the load-bearing bit — and
`hardenedRuntime`/`libraryValidation` have no Linux kernel equivalent. The
formula blocks confidential automatically; no policy code needed.

What Linux *does* report (all new/extended on this branch):

| Attestation field | Linux source |
|---|---|
| `secureBootEnabled` | EFI var `SecureBoot-8be4df61…` (last byte == 1) |
| **`kernelLockdown`** *(new lexicon field)* | `/sys/kernel/security/lockdown` bracketed mode. The **SIP analogue**: the confidential OS-integrity gate is now `sipEnabled OR kernelLockdown == "confidentiality"` in the producer formula (tested: `confidentiality` satisfies it, `integrity` does not) |
| `cdHash` | SHA-256 of `/proc/self/exe` (self-measurement — weaker than csops and documented as such) |
| `getTaskAllow` | `false` only under lockdown `confidentiality` |
| `antiDebug` | `true` only when Yama `ptrace_scope >= 2` (+ `PR_SET_DUMPABLE(0)`) |
| `sipEnabled` | always `false` on Linux (no SIP; `kernelLockdown` carries the gate) |

> **NOTE** — verifiers (AppView / SDK) must mirror the `kernelLockdown`
> substitution when recomputing tier for a Linux record; the lexicon text
> spells out the exact rule. See DECISION on verifier ownership below.

### TPM hardware attestation (status)

The Linux path to `trustLevel: hardware-attested`, mirroring how a bound
Apple MDA chain / App Attest object earns it on macOS:

**Done on this branch**
- **Lexicon** (additive): `tpmQuote { quoted, signature, akCertChain }` with
  the full verifier contract — AK chain to an embedded TPM-manufacturer root,
  signature over `quoted`, and the key binding
  `extraData (qualifyingData) == sha256(publicKey)` (the same staple-attack
  defense as the MDA/App-Attest bindings).
- **Verifier core** (`provider/src/tpm.rs`, pure Rust, zero new deps, always
  compiled): `TPMS_ATTEST` parse (bounds-checked, never panics) + ECDSA-P256
  signature + key binding. Validated against **two real vectors** frozen in
  `provider/src/testdata/`:
  - `swtpm_quote.txt` — genuine software-TPM output (swtpm 0.7.3 via
    tss-esapi), and
  - `amd_ftpm_quote.txt` — a quote from a **real AMD firmware TPM**
    (Ryzen 7 3700X / ASRock X570 Taichi, manufacturer `"AMD"`, TPM 2.0
    rev 1.38), produced with tpm2-tools and independently confirmed by
    `tpm2_checkquote`.
- **Wiring**: `AttestationInputs.tpm_quote` seam, record field, and the
  `trustLevel` decision now includes `|| rec.tpmQuote.is_some()`.

**Fail-closed by design**: `attestation::build` **drops** any quote today,
because `tpm::vendor_roots()` is empty and the AK-chain walk doesn't exist
yet — so a TPM quote cannot earn `hardware-attested` until both land. An
unverified measurement never elevates trust (tested).

> **DECISION (the big one)** — the **TPM-manufacturer root set**. Which
> vendor CAs does cocore trust to anchor AK chains (Infineon, STMicro,
> Nuvoton, Intel PTT, AMD fTPM, …), and does a *firmware* TPM count the same
> as a discrete chip? Empirical data point from this branch: the AMD fTPM
> tested here has a working EK but **no EK certificate** (empty NV) — common
> for consumer fTPMs — so it can produce hardware-rooted quotes but cannot
> complete a vendor chain. If cocore requires the chain (recommended — it is
> the exact analogue of requiring Apple's root), certless fTPMs stay
> self-attested and a ~$20 discrete module (which ships a real Infineon/
> Nuvoton EK cert) is the operator's upgrade path. This mirrors "trust the
> Apple root" and cuts against the no-central-authority ethos in the same
> way — it is a maintainer policy call, not an implementation detail.

> **FOLLOW-UP** — once roots are curated: `tpm::verify_ak_chain` (x509 walk
> mirroring `mda::verify_chain`; testable with rcgen synthetic chains exactly
> like the MDA tests) + flip `attestation::build` to embed verified+bound
> quotes.

> **FOLLOW-UP** — acquisition: producing the quote on the provider via
> `tss-esapi`, behind a Linux-only `tpm` feature (heavy C dep — default
> builds/CI stay green, like `secure_enclave`/`native_mlx`). The recipe is
> proven end-to-end on this box (swtpm + real fTPM); needs `libtss2-dev` at
> build time and, for the live integration test, `swtpm` in the CI job. A
> `TpmIdentity` (hardware-bound *signing*, distinct from attestation) slots
> into `load_or_create_identity()` behind the same feature.

> **NOTE** — CLAUDE.md's extension workflow says lexicon changes land first
> in a lexicon-only PR. Commit `3a68216` (adds `kernelLockdown` + `tpmQuote`
> to `attestation.json`) is cleanly separable if maintainers want that split.

> **DECISION** — who updates the AppView + SDK verifiers (TypeScript) for
> `kernelLockdown` and, later, `tpmQuote` recompute logic — this branch's
> author or the core team? Provider-side is done; the lexicon documents the
> exact rules a verifier must apply.

## Live validation against production

The full chain was exercised against the real network from an Ubuntu
24.04 box (Ryzen 7 3700X, RTX 2060 + RTX 3060, prebuilt Vulkan
llama.cpp b9860), 2026-07-02. Every artifact below is public and
independently verifiable on the provider's PDS
(`did:plc:rfrx5n26phualqc6x54n6myq`):

- **Pair → serve → register**: device-pair, provisioning + real provider
  records published, attestation published, registered with
  `wss://advisor.cocore.dev/v1/agent`, heartbeats; `doctor` cross-system
  health reported `diagnosis=healthy`.
- **The published attestation is the branch's Linux shape**, live on the
  wire: `kernelLockdown: "none"` (the new additive field, accepted by the
  PDS), `chipName: "AMD Ryzen 7 3700X"`, `osVersion: "Ubuntu 24.04.4
  LTS"`, honest `sipEnabled: false` / `tier: "best-effort"`, and a 64-hex
  `cdHash` (the `/proc/self/exe` self-measurement).
- **Managed engine**: cold spawn → automatic GGUF download
  (`bartowski/Qwen2.5-0.5B-Instruct-GGUF`) → ready + advertised in
  **35 s**; respawn from cache in ~7 s on a fresh port; the model
  layer-split across **both GPUs** (Vulkan0 + Vulkan1); the model
  appeared in the network's public model directory (`/api/v1/models`).
- **Owner controls**: flipping the tier toggle in the console produced
  the designed live behavior — clean llama-server SIGTERM teardown +
  `exit(3)` supervisor reload.
- **A real job end-to-end**: encrypted prompt → advisor → decrypt →
  llama-server on the GPUs → sealed streamed response → **signed receipt**
  `at://…/dev.cocore.compute.receipt/3mpp6cpixda2m` with exact
  llama-server usage counts `tokens {in:42, out:135}` and
  `price {amount:177, currency:CC}` — 42+135 at the uniform 1:1 rate,
  i.e. the off-catalog GGUF billing path priced a live receipt correctly
  by construction.

## Verification

```bash
cd provider
cargo fmt --check          # clean
cargo clippy --all-features --all-targets   # 0 warnings, 0 errors
cargo test -- --test-threads=1   # 269 passed, 0 failed  (1 live-only ignored; rebased on v0.9.39 main)
```

> Run the suite single-threaded. Three pre-existing upstream `advisor::tests`
> share the `ALLOW_INSECURE_ADVISOR` env var and race under default
> parallelism; they are deterministic with `--test-threads=1`. Not introduced
> by this branch.

Test coverage follows the upstream conventions (descriptive-sentence
names, doc comments explaining *why*, hand-rolled fakes, `ENV_LOCK` for
env-mutating tests, extracted pure helpers). Highlights beyond unit
parsing: the **managed llama-server lifecycle** is exercised end-to-end
against a fake `llama-server` (a python3 stand-in honoring the real
contract — parse `--port`, serve `/v1/models` + `/v1/chat/completions`)
with a real process boundary: spawn → readiness → idempotent re-start →
inference → SIGTERM teardown, the OOM-kill/`restart()` respawn contract,
and startup-failure ring-buffer capture. The OpenAI engine's channel
routing (reasoning_content field, inline `<think>`, prefill-think models,
tool_calls/null), body shape (present + omitted-not-null), the tool-call
canary (positive/negative), and prompt-safe error elision are all pinned.

TPM vectors are regenerable: swtpm via the tss-esapi recipe (start
`swtpm socket --tpm2 … --daemon`, TCTI `swtpm:host=127.0.0.1,port=2321`);
the AMD vector via tpm2-tools against `/dev/tpmrm0`
(`tpm2_createek/createak -G ecc`, `tpm2_quote -q $(sha256 of the signing
key) -l sha256:0,1,2,3,7`). Both are committed so tests need no TPM present.

## Branch changelog

Foundation → engine → ops → attestation, in commit order:

| Commits | What |
|---|---|
| `bf7b839` `71b2b95` | rustls TLS backend (no system OpenSSL) + process-default CryptoProvider (prevents the dual aws-lc-rs/ring panic) |
| `fa4e84f` `889e39a` `4b4e1b0` `184d9d4` `82ef8c0` | Linux telemetry + honest attestation inputs: system profile, aarch64 hypervisor detect, binary self-measurement, Yama anti-debug, Secure Boot / sysctl equivalents |
| `8df520a` `a41783f` `e5fe86d` | OpenAI-compatible HTTP engine (the unmanaged escape hatch) + wiring |
| `f9ba947` `163b68d` | **Managed llama-server engine** + `build_engines` wiring (the primary Linux path) |
| `f4468d0` | Off-catalog receipt rate decoupled from the stub entry (GGUF billing correct by construction) |
| `ebe61cc` `adecb0b` | systemd service parity (`service.rs` + Linux arms in models/doctor/update/pair) + unit template + install script |
| `3a68216` | **Lexicon (additive)**: `kernelLockdown` + `tpmQuote` |
| `c168efd` `4386efc` | kernelLockdown populated + wired as the Linux SIP gate; tpmQuote data path + trustLevel wiring (fail-closed) |
| `44fef38` `6290379` | TPM quote verifier + real swtpm and real AMD-fTPM test vectors |
| `f6e4a6c` `f511001` | rustfmt sweep + this document |
| `3a1498c` `d79e745` `757f918` `20de0f9` | test hardening: reasoning_content routing fix + full engine channel/body/canary coverage, managed-lifecycle tests against a fake llama-server, lockdown-parse/wire-shape/AK negatives |
| `b0f44ac` | rebase adaptation to v0.9.39 main (ModelRate.tool_call_parser, new AttestationInputs site) |
