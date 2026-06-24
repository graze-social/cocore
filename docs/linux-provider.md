# Running the cocore provider on Linux

cocore's default inference backend (Apple MLX / vllm-mlx) is macOS-only. On
Linux the provider connects to any **OpenAI-compatible HTTP endpoint** you
supply — llama.cpp's `llama-server`, Ollama, vLLM, etc. The Rust agent itself
has no macOS or OpenSSL system dependency.

## Prerequisites

### Build tools

```sh
# Rust toolchain (via rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Ubuntu / Debian build essentials (C linker + libz for ring/aws-lc-rs)
sudo apt-get update
sudo apt-get install -y build-essential pkg-config cmake libclang-dev
```

> `cmake` and `libclang-dev` are required by `aws-lc-rs` (the rustls crypto
> backend). `pkg-config` is a standard build dep; you do **not** need
> `libssl-dev` because the agent uses rustls exclusively.

### Inference backend

Install whichever server you prefer and have it running **before** `cocore
agent serve`.

**llama.cpp** (recommended for verified/deterministic inference):

```sh
# Pre-built binary from the llama.cpp releases page, or build from source:
# https://github.com/ggml-org/llama.cpp/releases
llama-server -m /path/to/model.gguf --host 127.0.0.1 --port 8080
```

**Ollama**:

```sh
# https://ollama.com/download/linux
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b
ollama serve          # exposes OpenAI-compatible API on port 11434
```

**vLLM** (GPU):

```sh
pip install vllm
vllm serve meta-llama/Llama-3.1-8B-Instruct --port 8080
```

## Build the provider agent

```sh
cd provider
cargo build --release --locked
install -m755 target/release/cocore ~/.local/bin/cocore
```

## Configure and run

```sh
# Point at your inference endpoint
export COCORE_ENGINE_BACKEND=openai
export COCORE_OPENAI_BASE_URL=http://127.0.0.1:8080   # your endpoint

# The model name you advertise must match what the endpoint expects
export COCORE_INFERENCE_MODELS="llama-3.1-8b"

# Optional: API key if your endpoint requires auth
# export COCORE_OPENAI_API_KEY=sk-...

# Optional: human-readable name shown in the console
# export COCORE_MACHINE_LABEL="my-linux-server"

# One-time: bind this machine to your AT Protocol identity
cocore agent pair

# Start serving
cocore agent serve
```

## Verified / deterministic inference

Setting `COCORE_DETERMINISTIC=1` enables greedy decoding (`temperature=0`)
with a fixed seed. This makes the provider's output reproducible: anyone with
the same model weights and input can independently re-run the inference and
confirm the receipt's `outputCommitment` hash.

```sh
export COCORE_DETERMINISTIC=1
export COCORE_DETERMINISTIC_SEED=42   # default; change if you prefer

cocore agent serve
```

The generation parameters (`temperatureMilli=0`, `seed=42`) are committed to
the published receipt's `params` field and covered by the provider's
`enclaveSignature`, so a verifier can prove the provider claimed these settings
and re-run the inference accordingly.

### Verification procedure

Given a receipt with:
- `inputCommitment` = SHA-256 of the plaintext prompt
- `outputCommitment` = SHA-256 of the plaintext response
- `params.temperatureMilli = 0`
- `params.seed = 42`
- `model` = the model id

A verifier can:
1. Obtain the same model weights (same quantization, same format).
2. Run the same endpoint software with the same parameters.
3. Submit the same prompt.
4. SHA-256 the response and compare to `outputCommitment`.

Agreement across independent providers running the same model is the basis
for the web-of-trust model planned for the Linux provider tier.

## Trust posture

Without Secure Enclave hardware, Linux providers:

- Sign receipts with a **software P-256 key** stored at
  `~/.cocore/identity.pem` (same format as the macOS software fallback).
- Publish attestations with `tier: "best-effort"` and
  `secureEnclaveAvailable: false` — honest about the absence of hardware
  binding.
- Do **not** claim `inProcessBackend: true` (inference runs in an external
  endpoint, not the measured binary).

The `enclaveSignature` on receipts and attestations is a real ECDSA-P256
signature that anyone can verify against the published `attestationPubKey`,
confirming "this DID's agent produced this receipt" — they just can't elevate
that claim to hardware-attested without the Apple MDA chain.
