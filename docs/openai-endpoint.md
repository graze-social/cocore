# Serving via an OpenAI-compatible endpoint (incl. Linux)

cocore's default backend is Apple-MLX (`vllm-mlx`), which only runs on Apple
Silicon. The **OpenAI-compatible HTTP engine** lets a provider — on Linux or
anywhere — serve real inference by proxying to any server that speaks the
OpenAI `/v1/chat/completions` API. cocore is a pure client here: it does **not**
spawn or supervise the endpoint.

Works with anything OpenAI-compatible: llama.cpp's `llama-server`, Ollama,
vLLM, LM Studio, OpenRouter, the OpenAI API itself, etc. HTTP and HTTPS are both
supported (transport is rustls).

## Build (Linux)

The agent builds from source with no system OpenSSL dependency:

```sh
cd provider
cargo build --release --locked
install -m755 target/release/cocore ~/.local/bin/cocore
```

## Configure

| Env var | Meaning | Default |
|---|---|---|
| `COCORE_ENGINE_BACKEND` | set to `openai` to use this engine | (unset → Apple-MLX path) |
| `COCORE_OPENAI_BASE_URL` | endpoint root, e.g. `http://127.0.0.1:8080` or `https://api.example.com` (a trailing `/v1` is fine) | — (required) |
| `COCORE_OPENAI_API_KEY` | sent as `Authorization: Bearer …` if set | — (optional) |
| `COCORE_INFERENCE_MODELS` | comma-separated model ids; each is advertised to cocore **and** sent verbatim as the upstream `model` | — |
| `COCORE_MACHINE_LABEL` | display name on the console | hostname |

The cocore model id you advertise is sent as the request's `model`, so use the
name your endpoint expects.

## Examples

**llama.cpp `llama-server`** (started separately, e.g. `llama-server -m model.gguf --host 127.0.0.1 --port 8080`):

```sh
export COCORE_ENGINE_BACKEND=openai
export COCORE_OPENAI_BASE_URL=http://127.0.0.1:8080
export COCORE_INFERENCE_MODELS="my-local-model"   # llama-server ignores the name; advertise what you like
cocore agent pair      # one-time: bind to your AT Protocol identity
cocore agent serve
```

**Ollama** (`ollama serve`, OpenAI-compatible at `/v1`):

```sh
export COCORE_ENGINE_BACKEND=openai
export COCORE_OPENAI_BASE_URL=http://127.0.0.1:11434
export COCORE_INFERENCE_MODELS="llama3.1:8b"
cocore agent serve
```

**A hosted OpenAI-compatible API:**

```sh
export COCORE_ENGINE_BACKEND=openai
export COCORE_OPENAI_BASE_URL=https://api.example.com
export COCORE_OPENAI_API_KEY=sk-...
export COCORE_INFERENCE_MODELS="gpt-4o-mini"
cocore agent serve
```

## Behaviour notes

- **Readiness / health.** A model is advertised only if `GET {base}/v1/models`
  returns 2xx at startup. A dead or misconfigured endpoint surfaces as a
  content-safe `engineFault` on the provider record (the machine still appears,
  serving only `stub`) rather than silently dropping jobs. If your endpoint
  doesn't implement `/v1/models`, this engine won't advertise it.
- **Timeouts.** The dial is bounded by a connect timeout; a generation by a
  generous total request timeout (10 min). Long generations beyond that are cut.
- **No RAM guard.** The catalog RAM-fit checks are skipped — inference runs on
  the endpoint, not this machine.

## Trust / privacy

The requester's prompt is decrypted by the agent and **forwarded in cleartext
(over TLS) to your configured endpoint** — so you (and implicitly the
requester) trust that endpoint with prompt content. For a local endpoint that's
nothing new; for a third-party one it's a deliberate choice. The model set is
operator-configured and never requester-controlled, so a remote requester can't
redirect the agent to a different endpoint or model. Prompt/response content is
never written to the agent's logs.
