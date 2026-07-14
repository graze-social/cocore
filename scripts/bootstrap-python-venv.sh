#!/usr/bin/env bash
# Bootstrap the Python venv that the cocore agent's subprocess
# engine spawns at runtime to host vllm-mlx.
#
# v0.6.0 switched this from "find a system Python + pip install" to
# "use uv + python-build-standalone". uv installs a relocatable
# CPython managed entirely under `$HOME/.local/share/uv/`, so we no
# longer depend on the user having ANY Python on their system —
# Homebrew, python.org installer, conda, Xcode CLT, none of those
# are needed. `python-build-standalone` is the same redistributable
# CPython that uv itself, Pyoxidizer, Sentry, and Replit use.
#
# Why this matters: v0.5.x bound the agent binary to the build
# runner's libpython at LC_LOAD_DYLIB, which caused
# "Library not loaded: /opt/homebrew/opt/python@3.12/..." dyld
# aborts on every user whose Mac didn't have brew Python at the
# build's exact path. v0.6.0 fixes that on the binary side
# (no PyO3 linkage at all) AND on the Python side (uv-managed
# Python instead of "whatever the user happens to have").
#
# Idempotent: re-running upgrades vllm-mlx in place but reuses the
# existing venv and HuggingFace cache.
#
# Usage:
#   ./bootstrap-python-venv.sh
#
# Env knobs:
#   COCORE_PYTHON_VENV       venv path (default: $HOME/.cocore/python)
#   COCORE_PYTHON_VERSION    Python version uv installs (default: 3.12)
#   COCORE_VLLM_MLX_VERSION  optional vllm-mlx pin (default: latest)
#   COCORE_UV                path to a pre-installed uv binary; if
#                            unset, we install it under $HOME/.local/bin
#
# Exit codes:
#   0  success
#   2  uv install failed
#   3  pip install vllm-mlx failed
#   4  venv verification failed (packages installed but don't import)

set -euo pipefail

readonly DEFAULT_VENV="$HOME/.cocore/python"
COCORE_PYTHON_VENV="${COCORE_PYTHON_VENV:-$DEFAULT_VENV}"
COCORE_PYTHON_VERSION="${COCORE_PYTHON_VERSION:-3.12}"
COCORE_VLLM_MLX_VERSION="${COCORE_VLLM_MLX_VERSION:-}"
COCORE_UV="${COCORE_UV:-}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  warn:\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m  error:\033[0m %s\n' "$*" >&2; }
phase() { printf '\n'; bold "==> $*"; }

ensure_uv() {
  phase "ensure uv"
  if [[ -n "$COCORE_UV" && -x "$COCORE_UV" ]]; then
    note "using preset COCORE_UV: $COCORE_UV"
    return
  fi
  # Check if uv is on PATH (e.g. user already has it from a prior
  # install or system-wide). astral's installer drops it at
  # ~/.local/bin/uv, which the cocore installer adds to PATH.
  if command -v uv >/dev/null 2>&1; then
    COCORE_UV="$(command -v uv)"
    note "found uv at $COCORE_UV ($("$COCORE_UV" --version 2>&1))"
    return
  fi
  note "no uv on PATH; downloading from astral.sh"
  # Pinning the version makes the install deterministic across runs.
  # Bump this when we want a newer uv (also bump on the release
  # checklist so 0.6.x users converge on the same uv as 0.7+).
  local uv_version="0.11.14"
  if ! curl -fsSL --max-time 60 \
        "https://astral.sh/uv/${uv_version}/install.sh" \
        | UV_NO_MODIFY_PATH=1 sh >&2; then
    err "uv installer download/run failed."
    err "Manual fallback: install uv from https://github.com/astral-sh/uv/releases"
    exit 2
  fi
  COCORE_UV="$HOME/.local/bin/uv"
  [[ -x "$COCORE_UV" ]] || { err "uv installed but missing at $COCORE_UV"; exit 2; }
  note "installed uv at $COCORE_UV ($("$COCORE_UV" --version 2>&1))"
}

install_python() {
  phase "install python $COCORE_PYTHON_VERSION (uv-managed)"
  # uv idempotently downloads + caches the requested Python at
  # ~/.local/share/uv/python/cpython-<ver>-<platform>/. Subsequent
  # runs are a no-op.
  "$COCORE_UV" python install "$COCORE_PYTHON_VERSION" >&2
  note "$("$COCORE_UV" python find "$COCORE_PYTHON_VERSION" 2>&1)"
}

create_venv() {
  phase "create venv at $COCORE_PYTHON_VENV"
  mkdir -p "$(dirname "$COCORE_PYTHON_VENV")"
  if [[ -d "$COCORE_PYTHON_VENV" && -x "$COCORE_PYTHON_VENV/bin/python" ]]; then
    # uv venv refuses to overwrite an existing venv by default;
    # the --allow-existing flag makes it reuse the dir. Inside,
    # `bin/python` is re-linked to the requested Python version.
    note "existing venv detected; reusing"
    "$COCORE_UV" venv --python "$COCORE_PYTHON_VERSION" --allow-existing \
        "$COCORE_PYTHON_VENV" >&2
  else
    "$COCORE_UV" venv --python "$COCORE_PYTHON_VERSION" "$COCORE_PYTHON_VENV" >&2
  fi
  note "venv python: $("$COCORE_PYTHON_VENV/bin/python" --version 2>&1)"
}

install_packages() {
  phase "install vllm-mlx + uvicorn into the venv"
  local pkg="vllm-mlx"
  if [[ -n "$COCORE_VLLM_MLX_VERSION" ]]; then
    pkg="vllm-mlx==$COCORE_VLLM_MLX_VERSION"
  fi
  # hf_transfer is the accelerated (parallel, byte-range, Rust-based)
  # HuggingFace downloader. Without it, large weight downloads stall and
  # burst on a single connection; the engine enables it via
  # HF_HUB_ENABLE_HF_TRANSFER when the package is importable.
  # uv pip install needs the venv activated; we pass --python pointing
  # at the venv's interpreter to make it scope to that venv.
  #
  # transformers is CONSTRAINED, not floated: transformers 5.13.0 broke
  # mlx-lm's tokenizer registration (`AutoTokenizer.register("NewlineTokenizer",
  # ...)` with a string key → `AttributeError: 'str' object has no attribute
  # '__module__'` at import), which kills every engine spawn on a fresh
  # install. Because this script re-runs idempotently, the constraint also
  # REPAIRS an already-broken venv by downgrading it. Lift the ceiling once
  # mlx-lm registers its tokenizer with a real config class upstream.
  if ! "$COCORE_UV" pip install --python "$COCORE_PYTHON_VENV/bin/python" \
        "$pkg" mlx-lm uvicorn hf_transfer "transformers<5.13" >&2; then
    err "uv pip install $pkg failed"
    exit 3
  fi
  note "vllm-mlx + uvicorn + hf_transfer installed at $COCORE_PYTHON_VENV"
}

verify() {
  phase "verify"
  local py="$COCORE_PYTHON_VENV/bin/python"
  # Both packages are needed by the subprocess engine wrapper
  # (cocore_inference_server.py). uvicorn is technically a
  # transitive dep of vllm-mlx, but we install it explicitly to
  # decouple the version we serve under from vllm-mlx's pin.
  if "$py" -c 'import vllm_mlx.server, uvicorn' 2>/dev/null; then
    note "import vllm_mlx.server, uvicorn: ok"
  else
    # Hard failure, not a warning: a venv that installed but doesn't import
    # means EVERY engine spawn will crash at startup and the machine will
    # silently serve stub-only. Failing here surfaces the problem at install
    # time, where the user is watching, instead of at serve time, where they
    # aren't. (Exactly this bit a fresh install when transformers 5.13.0
    # broke mlx-lm's import — the old warn-and-continue let the install
    # "succeed" and the engine crash-loop.)
    err "venv verification failed — the installed packages don't import:"
    "$py" -c 'import vllm_mlx.server, uvicorn' 2>&1 | sed 's/^/    /' >&2 || true
    err "re-run this installer to retry; if it persists, DM @cocore.dev on Bluesky"
    exit 4
  fi
}

main() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    err "vllm-mlx is macOS / Apple Silicon only; refusing to bootstrap on $(uname -s)"
    exit 1
  fi
  ensure_uv
  install_python
  create_venv
  install_packages
  verify
  printf '\n'
  bold "==> done"
  note "venv:   $COCORE_PYTHON_VENV"
  note "python: $COCORE_PYTHON_VENV/bin/python"
  note "uv:     $COCORE_UV"
  note ""
  note "to choose models, run:"
  note "  cocore agent models add"
}

main "$@"
