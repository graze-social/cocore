#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# cocore Linux provider — build, pair, and run under podman
#
# For hosts where install.sh's approach (installing a compiler toolchain to
# the root filesystem) doesn't work — e.g. SteamOS's read-only root. Builds
# provider/Dockerfile, pairs with your AT Protocol identity if not already
# paired, then starts the provider as a long-running container.
#
#   ./build-podman.sh
#
# Environment overrides (set before running):
#   COCORE_IMAGE        image tag                                (default: cocore-provider)
#   COCORE_ROCM         bundle the AMD ROCm GPU backend at build  (default: auto-detected)
#   COCORE_GPU          pass GPU devices through at run           (default: auto-detected)
#   COCORE_GPU_VENDOR   amd | nvidia — which passthrough flags to use (default: auto-detected)
#
# COCORE_ROCM/COCORE_GPU/COCORE_GPU_VENDOR auto-detect a GPU and enable
# themselves together — set any of them explicitly to override detection.
#   AMD:    /sys/class/drm + /dev/kfd (ROCm/KFD kernel driver).
#   NVIDIA: /dev/nvidia0, plus an NVIDIA Container Toolkit CDI spec (podman
#           has no docker-style `--gpus` flag — GPU passthrough goes through
#           CDI instead). One-time host setup if you don't have this yet:
#             sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER_DIR="$ROOT_DIR/provider"

COCORE_IMAGE="${COCORE_IMAGE:-cocore-provider}"
COCORE_ROCM_SET="${COCORE_ROCM+x}"
COCORE_GPU_SET="${COCORE_GPU+x}"
COCORE_ROCM="${COCORE_ROCM:-0}"
COCORE_GPU="${COCORE_GPU:-0}"
COCORE_GPU_VENDOR="${COCORE_GPU_VENDOR:-}"

CONTAINER_NAME="cocore"
STATE_VOLUME="cocore-state"
OLLAMA_VOLUME="cocore-ollama"

# ── terminal colours (suppressed when not a tty) ──────────────────────────────
if [[ -t 1 ]]; then
  GRN='\033[0;32m' YLW='\033[1;33m' RED='\033[0;31m' BLD='\033[1m' RST='\033[0m'
else
  GRN='' YLW='' RED='' BLD='' RST=''
fi

step() { echo -e "\n${GRN}==>${RST} ${BLD}${*}${RST}"; }
warn() { echo -e "${YLW}[warn]${RST} ${*}"; }
die()  { echo -e "${RED}[error]${RST} ${*}" >&2; exit 1; }

have() { command -v "$1" &>/dev/null; }

have podman || die "podman not found. Install it and re-run."

# Detects an AMD GPU with a usable ROCm/KFD kernel driver: walks
# /sys/class/drm for a display-controller (PCI class 0x03xxxx) device with
# AMD's vendor ID (0x1002), and requires /dev/kfd to exist since that's the
# node podman passes through for compute (--device /dev/kfd) — without it
# ROCm has nothing to talk to even if the GPU itself is AMD.
detect_amd_gpu() {
  local dev vendor class
  [[ -e /dev/kfd ]] || return 1
  for dev in /sys/class/drm/card[0-9]*/device; do
    [[ -r "$dev/vendor" && -r "$dev/class" ]] || continue
    vendor="$(<"$dev/vendor")"
    class="$(<"$dev/class")"
    if [[ "$vendor" == "0x1002" && "$class" == 0x03* ]]; then
      return 0
    fi
  done
  return 1
}

# Detects an NVIDIA GPU bound to the proprietary driver. /dev/nvidia0 is the
# per-card device node; /proc/driver/nvidia/version is present as soon as the
# kernel module loads, even on headless compute instances that create device
# nodes lazily — checking both covers cloud GPU boxes that only have one.
detect_nvidia_gpu() {
  [[ -e /dev/nvidia0 || -e /proc/driver/nvidia/version ]]
}

# NVIDIA passthrough under podman goes through the Container Device
# Interface rather than a `--gpus` flag (podman has no docker-compatible
# equivalent). The CDI spec is generated once per host by the NVIDIA
# Container Toolkit, separate from the driver itself.
nvidia_cdi_ready() {
  [[ -e /etc/cdi/nvidia.yaml || -e /var/run/cdi/nvidia.yaml ]]
}

if [[ -z "$COCORE_GPU_VENDOR" ]]; then
  if detect_amd_gpu; then
    COCORE_GPU_VENDOR="amd"
  elif detect_nvidia_gpu; then
    COCORE_GPU_VENDOR="nvidia"
  fi
fi

if [[ -z "$COCORE_GPU_SET" ]]; then
  case "$COCORE_GPU_VENDOR" in
    amd)
      step "Detected an AMD GPU with ROCm/KFD support — enabling GPU passthrough"
      COCORE_GPU=1
      ;;
    nvidia)
      if nvidia_cdi_ready; then
        step "Detected an NVIDIA GPU with a CDI spec configured — enabling GPU passthrough"
        COCORE_GPU=1
      else
        warn "Detected an NVIDIA GPU, but no CDI spec found — building CPU-only. Run 'sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml' then re-run this script to enable GPU passthrough."
        COCORE_GPU_VENDOR=""
      fi
      ;;
    *)
      warn "No AMD or NVIDIA GPU detected — building CPU-only. Set COCORE_GPU=1 and COCORE_GPU_VENDOR=amd|nvidia to force GPU support."
      ;;
  esac
fi

if [[ -z "$COCORE_ROCM_SET" && "$COCORE_GPU_VENDOR" == "amd" && "$COCORE_GPU" == "1" ]]; then
  COCORE_ROCM=1
fi

VOLUME_ARGS=(-v "$STATE_VOLUME:/root/.cocore" -v "$OLLAMA_VOLUME:/root/.ollama")

GPU_ARGS=()
if [[ "$COCORE_GPU" == "1" ]]; then
  case "$COCORE_GPU_VENDOR" in
    amd)
      GPU_ARGS=(--device /dev/kfd --device /dev/dri --group-add keep-groups)
      if [[ "$COCORE_ROCM" != "1" ]]; then
        warn "COCORE_GPU=1 (amd) but COCORE_ROCM=0 — the image won't have the ROCm backend. Re-run with COCORE_ROCM=1 to rebuild it in."
      fi
      ;;
    nvidia)
      GPU_ARGS=(--device nvidia.com/gpu=all --security-opt=label=disable)
      ;;
    *)
      die "COCORE_GPU=1 but COCORE_GPU_VENDOR is unset/unrecognized ('${COCORE_GPU_VENDOR}') — set it to amd or nvidia."
      ;;
  esac
fi

# ── build ──────────────────────────────────────────────────────────────────
step "Building ${COCORE_IMAGE} (COCORE_ROCM=${COCORE_ROCM}, COCORE_GPU=${COCORE_GPU}${COCORE_GPU_VENDOR:+, vendor=$COCORE_GPU_VENDOR})"
podman build \
  --build-arg "COCORE_ROCM=${COCORE_ROCM}" \
  -t "$COCORE_IMAGE" \
  -f "$PROVIDER_DIR/Dockerfile" \
  "$PROVIDER_DIR"

# ── volumes ────────────────────────────────────────────────────────────────
step "Ensuring persistent volumes exist"
podman volume inspect "$STATE_VOLUME" &>/dev/null || podman volume create "$STATE_VOLUME" >/dev/null
podman volume inspect "$OLLAMA_VOLUME" &>/dev/null || podman volume create "$OLLAMA_VOLUME" >/dev/null

# ── pair ───────────────────────────────────────────────────────────────────
# Bypasses entrypoint.sh (--entrypoint cocore) so pairing doesn't wait on
# Ollama starting or a multi-gigabyte model pull — pairing needs neither.
already_paired() {
  podman run --rm --entrypoint test "${VOLUME_ARGS[@]}" "$COCORE_IMAGE" \
    -f /root/.cocore/session.json &>/dev/null
}

if already_paired; then
  echo "Already paired (found ~/.cocore/session.json in the ${STATE_VOLUME} volume)."
else
  step "Pairing with your AT Protocol identity"
  podman run --rm -it --entrypoint cocore "${VOLUME_ARGS[@]}" "$COCORE_IMAGE" agent pair
fi

# ── run ────────────────────────────────────────────────────────────────────
step "Starting cocore"
if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
  warn "Removing existing '${CONTAINER_NAME}' container"
  podman rm -f "$CONTAINER_NAME" >/dev/null
fi

podman run -d --name "$CONTAINER_NAME" \
  "${VOLUME_ARGS[@]}" \
  "${GPU_ARGS[@]}" \
  "$COCORE_IMAGE"

echo ""
echo -e "${GRN}${BLD}cocore is running as container '${CONTAINER_NAME}'${RST}"
echo ""
echo "  Logs:    podman logs -f ${CONTAINER_NAME}"
echo "  Stop:    podman stop ${CONTAINER_NAME}"
echo "  Restart: podman start ${CONTAINER_NAME}"
