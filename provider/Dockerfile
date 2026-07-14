# Debian-based image for the cocore Rust provider agent, built for running
# under podman on SteamOS (whose read-only root can't host a system
# toolchain — see install.sh's steamos guard). This mirrors install.sh's
# Debian branch (apt build deps + rustup + cargo build + Ollama) but every
# step is forced non-interactively: install.sh's `yn` prompts read from
# /dev/tty, which doesn't exist during `podman build`.
#
# Build (from the provider/ directory):
#   podman build -t cocore-provider -f Dockerfile .
#   # with AMD ROCm GPU support bundled:
#   podman build --build-arg COCORE_ROCM=1 -t cocore-provider -f Dockerfile .
#
# Run (see the accompanying notes for volumes/pairing):
#   podman volume create cocore-state
#   podman volume create cocore-ollama
#   podman run --rm -it \
#     -v cocore-state:/root/.cocore \
#     -v cocore-ollama:/root/.ollama \
#     cocore-provider cocore agent pair
#   podman run -d --name cocore \
#     -v cocore-state:/root/.cocore \
#     -v cocore-ollama:/root/.ollama \
#     cocore-provider

# ── builder ────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

# install.sh: install_build_deps_debian()
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential pkg-config cmake libclang-dev ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# install.sh: install_rust() (Debian branch — rustup, forced non-interactive)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY . .

# install.sh: build_cocore() → cargo build --release
# COCORE_GIT_SHA lets the build embed the real commit sha (build.rs falls
# back to `git rev-parse`, which has nothing to work with once the source
# is copied in without a .git directory).
ARG COCORE_GIT_SHA=""
ENV COCORE_GIT_SHA=${COCORE_GIT_SHA}
RUN cargo build --release --locked

# ── runtime ────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Set to 1 (--build-arg COCORE_ROCM=1) to bundle the ROCm GPU backend for
# AMD graphics passthrough (see the podman --device/HSA_OVERRIDE_GFX_VERSION
# notes for running it). Off by default since the ROCm tarball is large and
# CPU-only inference works fine without it.
ARG COCORE_ROCM=0

RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl zstd lshw \
 && rm -rf /var/lib/apt/lists/* \
 # install.sh: install_ollama() → _ollama_official() (Debian has no ollama
 # apt package, so this is the only branch that applies here). zstd isn't
 # in bookworm-slim by default but the installer requires it to unpack.
 && curl -fsSL https://ollama.com/download/ollama-linux-amd64.tar.zst \
    | tar x --zstd -C /usr \
 && if [ "$COCORE_ROCM" = "1" ]; then \
      curl -fsSL https://ollama.com/download/ollama-linux-amd64-rocm.tar.zst \
        | tar x --zstd -C /usr; \
    fi

COPY --from=builder /build/target/release/cocore /usr/local/bin/cocore

# install.sh: COCORE_MODEL default + the env cocore agent serve needs to
# talk to the Ollama endpoint started in entrypoint.sh
ENV COCORE_MODEL=llama3.1:8b \
    COCORE_ENGINE_BACKEND=openai \
    COCORE_OPENAI_BASE_URL=http://127.0.0.1:11434 \
    COCORE_INFERENCE_MODELS=llama3.1:8b

# Ollama's model store and cocore's pairing keys/state — mount these as
# named volumes so `cocore agent pair` and pulled models survive
# `podman rm` / image rebuilds instead of being baked into (and lost with)
# the image layer.
VOLUME ["/root/.ollama", "/root/.cocore"]

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["cocore", "agent", "serve"]
