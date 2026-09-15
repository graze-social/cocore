# Attached engines: serve a model through your own OpenAI-compatible server

The agent's default backend is a `vllm-mlx` child it spawns per model. That
is the right default for someone who installs the tray and picks a model. It
is the wrong ceiling for a provider who has measured their hardware: on an M1
Max, [`mei`](https://github.com/tijs/mei) decodes the same 4-bit MoE
checkpoint at roughly four times vllm-mlx's speed, and `llama-server` or
`mlx_lm.server` win on other machines. Issue #204 asked for a way to plug
those in. This is it.

An **attached engine** is a model the agent does not run. You start the
server; the agent proves it is up, proves what it can do, advertises exactly
that, and proxies jobs to it over loopback HTTP.

## Configure

One map from model id to base URL. Two equivalent places:

```bash
# environment (LaunchAgent plist, or the shell you run `cocore agent serve` in)
export COCORE_ENGINE_MAP="mlx-community/Qwen3.6-35B-A3B-4bit=http://127.0.0.1:8024"
```

```text
# ~/.cocore/engine-map — one entry per line, `#` comments; picked up when the
# env var is unset, so tray installs can use it without touching the plist.
mlx-community/Qwen3.6-35B-A3B-4bit = http://127.0.0.1:8024
ornith-ai/Ornith-1.5-35B-A3B-MLX-4bit = http://127.0.0.1:8025
```

Rules:

- The URL is the **server root** (`http://host:port`, optional path prefix).
  The agent appends `/v1/models` and `/v1/chat/completions` itself; a URL
  ending in `/v1` is rejected.
- `http://` only. The client is plain HTTP/1.1 and the server is meant to be
  on this machine. A non-loopback host is accepted with a loud warning:
  decrypted prompts would cross the network in the clear.
- A model in the map is served by the attached engine **and removed from the
  vllm-mlx set**, even if the tray's picker also wrote it to
  `COCORE_INFERENCE_MODELS`. One model, one engine.
- A machine whose every model is attached never needs the Python venv.
  Installing with `COCORE_SKIP_VENV=1` is fine; `cocore agent models add`
  accepts attached models without one.
- A malformed map is a fault (`engine-map-invalid` on the provider record),
  not a silent fall-back to vllm-mlx.
- `stub` cannot be remapped.

## What the agent does with an attached model

1. **Readiness.** `GET /v1/models` must answer 2xx. At startup the agent
   waits up to `COCORE_ATTACHED_READY_TIMEOUT` seconds (default 300 — a
   native server loading a 20 GB checkpoint cold can take a couple of
   minutes) and logs progress every 15 s. Afterwards the serve loop's health
   tick re-probes like any engine; a server that goes away is de-advertised
   within a tick instead of sinking jobs. The agent never starts or restarts
   the server: `restart()` is a re-probe.
2. **Tool-calling canary.** The same forced `report_status` call the
   vllm-mlx engine runs. Pass → the model is listed in `tool_call_models`
   and receives jobs that carry `tools`.
3. **Structured-output canary.** One `response_format: json_schema` request
   whose prompt begs for prose. A server that honours the schema can only
   answer `{"status":"ok"}`; a server that silently drops `response_format`
   (mei ≤ 0.5.0 ignores unknown fields) answers in sentences and fails.
   Pass → the model is listed in `structured_output_models`. Fail → the
   agent **refuses** schema jobs for that model with a typed
   `structured-output-unsupported` error before a byte reaches the server,
   and the advisor routes schema jobs elsewhere (see below).
   `COCORE_ATTACHED_SKIP_CANARIES=1` skips both and advertises neither.
4. **Proxying.** Streaming SSE with `stream_options.include_usage` so token
   counts on receipts are the server's own; chunked transfer framing is
   handled; `reasoning_content` and `tool_calls` deltas are forwarded on
   their channels; the same first-token (300 s) and idle (60 s) budgets as
   the subprocess engine.
5. **Tier.** Attached engines are out-of-process, so the machine is
   best-effort — the same tier the vllm-mlx child has always had. Nothing
   about attestation changes.

## The admission gate

Every real engine — attached **and** vllm-mlx — is now wrapped in a
per-model admission gate: one generation running, one waiting, anything
beyond that refused immediately with a typed `engine-busy` error. Before
this the agent had no concurrency limit at all: a second job routed to a
busy vllm-mlx machine died twenty seconds later with `writing HTTP request
body` and still published a billable receipt (issue #202); a second job on
mei would have queued unbounded until our 300 s budget killed it.

Refused jobs never publish or bill a receipt. The requester gets a sealed
`[cocore provider] engine-busy: …` chunk and a completion with no receipt,
exactly like a model miss.

The ceiling (`model_capacity`, 2) is advertised on the Register frame, and
the advisor skips a machine whose in-flight count for the requested model
has reached it. If every machine serving the model is saturated the job is
refused with HTTP 503 `no-capacity` up front, which a client can retry,
rather than dispatched to a machine that will refuse it after the fact.

## Recipe: mei on an Apple-silicon Mac

```bash
brew install tijs/tap/mei
mei pull qwen3.6-35b-a3b-text        # ~19 GB, pinned revision, verified
mei --model-dir ~/.cache/mei/models/Qwen3.6-35B-A3B-4bit-textonly \
    --model-profile qwen3.6-35b-a3b-text \
    --served-model-id mlx-community/Qwen3.6-35B-A3B-4bit
```

```text
# ~/.cocore/engine-map
mlx-community/Qwen3.6-35B-A3B-4bit = http://127.0.0.1:8024
```

Then start serving (tray, or `cocore agent serve`). Watch for
`attached inference engine ready` and the two canary lines in the agent
log; `cocore.dev/machines/<yours>` lists the model within a heartbeat.

Two honesty notes for that recipe:

- `--served-model-id` decides the id the network sees. The profile above is
  a text-only *repack* of the `mlx-community` checkpoint, so advertising it
  under the catalog id is a convenience, not a provenance claim. Off-catalog
  ids are priced at the uniform rate and route fine — advertise the repack
  under its own name if you would rather be exact.
- Until mei implements `response_format`, the structured-output canary fails
  and the model is (correctly) not advertised for schema jobs. Free-text and
  tool-calling jobs are unaffected.

## Faults you may see on the provider record

| code | meaning |
|---|---|
| `attached-engine-unreachable` | the server never answered `GET /v1/models` within the ready timeout; other models are unaffected |
| `engine-map-invalid` | the map could not be parsed; no attached model is served until fixed |

## Not in scope (yet)

- **Managed mode** — the agent spawning `mei`/`llama-server` itself, with the
  tray's picker offering "engine: mei". The attached engine is the seam
  that makes this a small follow-up (see `engines/attached.rs`).
- **HTTPS / remote servers** — deliberately unsupported; see the loopback
  note above.
- **Per-model capacity other than 2** — every backend we ship is
  single-flight. A truly concurrent server would want a bigger gate; the
  `Gated::new(inner, capacity, queued)` constructor already takes it.
