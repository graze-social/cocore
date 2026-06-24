#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# cocore Linux provider — one-shot installer
#
# Installs Ollama, pulls a model, compiles the provider, and drops the binary
# in ~/.local/bin. Works on Debian/Ubuntu, Fedora/RHEL, Arch/CachyOS, openSUSE,
# TrueNAS SCALE, and NixOS.
#
#   curl -fsSL https://raw.githubusercontent.com/graze-social/cocore/main/install.sh | bash
#
# Environment overrides (set before piping):
#   COCORE_BRANCH   git branch to build from      (default: main)
#   COCORE_MODEL    Ollama model to pull           (default: llama3.1:8b)
#   COCORE_SRC      where to clone the source      (default: ~/src/cocore)
#   BIN_DIR         where to install the binary    (default: ~/.local/bin)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

COCORE_REPO="https://github.com/graze-social/cocore"
COCORE_BRANCH="${COCORE_BRANCH:-rchowe/linux}"
COCORE_MODEL="${COCORE_MODEL:-llama3.1:8b}"
COCORE_SRC="${COCORE_SRC:-$HOME/src/cocore}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

# ── terminal colours (suppressed when not a tty) ──────────────────────────────
if [[ -t 1 ]]; then
  GRN='\033[0;32m' YLW='\033[1;33m' RED='\033[0;31m' BLD='\033[1m' RST='\033[0m'
else
  GRN='' YLW='' RED='' BLD='' RST=''
fi

step() { echo -e "\n${GRN}==>${RST} ${BLD}${*}${RST}"; }
warn() { echo -e "${YLW}[warn]${RST} ${*}"; }
die()  { echo -e "${RED}[error]${RST} ${*}" >&2; exit 1; }

# yn <question> — always reads from /dev/tty so it works under curl|bash
yn() {
  local ans
  printf "${YLW}[?]${RST} %s [Y/n] " "$1"
  read -r ans </dev/tty 2>/dev/null || ans=y
  [[ "${ans:-y}" =~ ^[Yy] ]]
}

have() { command -v "$1" &>/dev/null; }

# ── privilege helper ──────────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
  SUDO=""
else
  if have sudo; then
    SUDO="sudo"
  else
    SUDO=""
    warn "sudo not found — package installs will be attempted without it"
  fi
fi

run_priv() { ${SUDO:+$SUDO} "$@"; }

# ── distro detection ──────────────────────────────────────────────────────────
OS_ID="" OS_LIKE="" OS_PRETTY=""
if [[ -f /etc/os-release ]]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_LIKE="${ID_LIKE:-}"
  OS_PRETTY="${PRETTY_NAME:-${NAME:-unknown}}"
fi

is_family() {
  [[ "$OS_ID" == "$1" ]] || [[ " $OS_LIKE " == *" $1 "* ]]
}

FAMILY="unknown"
if [[ "$OS_ID" == "nixos" ]];    then FAMILY="nixos"
elif is_family "arch";           then FAMILY="arch"
elif is_family "debian";         then FAMILY="debian"
elif is_family "fedora" || is_family "rhel" || is_family "centos"; then FAMILY="rpm"
elif is_family "suse" || is_family "opensuse"; then FAMILY="suse"
fi

echo ""
echo -e "${BLD}cocore Linux provider installer${RST}"
echo    "OS: ${OS_PRETTY:-unknown}"
echo    "Family: ${FAMILY}"
echo    "Model: ${COCORE_MODEL}"
echo    "Binary destination: ${BIN_DIR}"
echo ""

# ── locate source tree ────────────────────────────────────────────────────────
# If the script is run from within the cocore repo, build in place.
# Otherwise clone it.
if [[ -f "$(pwd)/provider/Cargo.toml" ]]; then
  PROVIDER_DIR="$(pwd)/provider"
  step "Building from current directory: $(pwd)"
else
  step "Cloning cocore (branch: ${COCORE_BRANCH})"
  if [[ -d "$COCORE_SRC/.git" ]]; then
    echo "Source already exists at $COCORE_SRC — pulling latest"
    git -C "$COCORE_SRC" fetch origin
    git -C "$COCORE_SRC" checkout "$COCORE_BRANCH"
    git -C "$COCORE_SRC" pull --ff-only
  else
    git clone --branch "$COCORE_BRANCH" --depth 1 "$COCORE_REPO" "$COCORE_SRC"
  fi
  PROVIDER_DIR="$COCORE_SRC/provider"
fi

# ── Rust toolchain ────────────────────────────────────────────────────────────
install_rust() {
  step "Installing Rust toolchain via rustup"
  if [[ "$FAMILY" == "nixos" ]]; then
    warn "On NixOS: installing rustup via nix-env (imperative)"
    nix-env -iA nixpkgs.rustup
  else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path
  fi
  export PATH="$HOME/.cargo/bin:$PATH"
}

if ! have cargo; then
  [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env" || true
fi

if ! have cargo; then
  if yn "Rust/cargo not found. Install it now?"; then
    install_rust
  else
    die "cargo is required to build cocore. Aborting."
  fi
else
  echo "Rust $(cargo --version) — OK"
  export PATH="$HOME/.cargo/bin:$PATH"
fi

# ── build dependencies ────────────────────────────────────────────────────────
# Required: a C compiler (cc/gcc/clang), cmake, libclang headers, pkg-config.
# aws-lc-rs (the rustls crypto backend) needs cmake + clang to build its C glue.

check_build_deps() {
  have cc || have gcc || have clang || return 1
  have cmake || return 1
  # Check for libclang — clang itself is sufficient on most systems
  have clang || have llvm-config || return 1
  have pkg-config || return 1
  return 0
}

install_build_deps_debian() {
  run_priv apt-get update -qq
  run_priv apt-get install -y build-essential pkg-config cmake libclang-dev
}

install_build_deps_rpm() {
  if have dnf; then
    run_priv dnf install -y gcc gcc-c++ pkg-config cmake clang clang-devel
  else
    run_priv yum install -y gcc gcc-c++ pkg-config cmake clang clang-devel
  fi
}

install_build_deps_arch() {
  run_priv pacman -S --needed --noconfirm base-devel cmake clang pkg-config
}

install_build_deps_suse() {
  run_priv zypper install -y gcc gcc-c++ cmake clang-devel pkg-config
}

install_build_deps_nixos() {
  warn "On NixOS: adding cmake, clang, pkg-config via nix-env"
  nix-env -iA nixpkgs.cmake nixpkgs.clang nixpkgs.pkg-config
}

if ! check_build_deps; then
  echo ""
  echo "Missing build dependencies: cc/gcc, cmake, clang/libclang, pkg-config"
  if yn "Install them now?"; then
    case "$FAMILY" in
      debian)  install_build_deps_debian ;;
      rpm)     install_build_deps_rpm    ;;
      arch)    install_build_deps_arch   ;;
      suse)    install_build_deps_suse   ;;
      nixos)   install_build_deps_nixos  ;;
      *)
        warn "Unknown distro family '${FAMILY}'. Attempting Debian-style install."
        if yn "Try: apt-get install build-essential pkg-config cmake libclang-dev?"; then
          install_build_deps_debian
        else
          die "Cannot install build deps automatically. Install them manually and re-run."
        fi
        ;;
    esac
  else
    echo ""
    echo "Install them manually, then re-run:"
    case "$FAMILY" in
      debian) echo "  sudo apt-get install -y build-essential pkg-config cmake libclang-dev" ;;
      rpm)    echo "  sudo dnf install -y gcc gcc-c++ pkg-config cmake clang clang-devel" ;;
      arch)   echo "  sudo pacman -S --needed base-devel cmake clang pkg-config" ;;
      suse)   echo "  sudo zypper install -y gcc gcc-c++ cmake clang-devel pkg-config" ;;
      nixos)  echo "  nix-env -iA nixpkgs.cmake nixpkgs.clang nixpkgs.pkg-config" ;;
      *)      echo "  (install gcc, cmake, clang/libclang, pkg-config for your distro)" ;;
    esac
    exit 1
  fi
else
  echo "Build dependencies — OK"
fi

# ── compile cocore ────────────────────────────────────────────────────────────
step "Compiling cocore provider (this takes a few minutes on first build)"

build_cocore() {
  (cd "$PROVIDER_DIR" && cargo build --release 2>&1)
}

if [[ "$FAMILY" == "nixos" ]]; then
  # On NixOS, patchelf fixes up the binary's rpath so it works outside nix-shell.
  # We wrap the build in a nix-shell that provides cmake + clang as build tools;
  # the Rust toolchain comes from the nix-env-installed rustup above.
  if ! have nix-shell; then
    die "nix-shell not found — is this really a NixOS system?"
  fi
  nix-shell -p cmake clang pkg-config patchelf --run "
    set -e
    export PATH=\"\$HOME/.cargo/bin:\$PATH\"
    cd '$PROVIDER_DIR'
    cargo build --release
    # Patch the binary's interpreter so it runs outside the nix store
    INTERP=\$(patchelf --print-interpreter \$(which bash))
    patchelf --set-interpreter \"\$INTERP\" target/release/cocore 2>/dev/null || true
  "
else
  build_cocore
fi

COCORE_BIN="$PROVIDER_DIR/target/release/cocore"
[[ -f "$COCORE_BIN" ]] || die "Build succeeded but binary not found at $COCORE_BIN"

# ── install binary ────────────────────────────────────────────────────────────
step "Installing binary to $BIN_DIR"
mkdir -p "$BIN_DIR"
install -m 755 "$COCORE_BIN" "$BIN_DIR/cocore"
echo "Installed: $BIN_DIR/cocore"

# Make sure BIN_DIR is on PATH for the next steps
export PATH="$BIN_DIR:$PATH"

# ── Ollama ────────────────────────────────────────────────────────────────────
install_ollama() {
  step "Installing Ollama"
  case "$FAMILY" in
    arch)
      # ollama is in the Arch/CachyOS repos
      run_priv pacman -S --needed --noconfirm ollama 2>/dev/null \
        || { warn "ollama not in pacman repos — falling back to official installer"; _ollama_official; }
      ;;
    nixos)
      warn "On NixOS: installing ollama via nix-env"
      nix-env -iA nixpkgs.ollama
      ;;
    *)
      _ollama_official
      ;;
  esac
}

_ollama_official() {
  echo "Downloading Ollama via the official installer script..."
  curl -fsSL https://ollama.com/install.sh | run_priv sh
}

if have ollama; then
  echo "Ollama $(ollama --version 2>/dev/null | head -1) — already installed"
else
  if yn "Ollama not found. Install it now?"; then
    install_ollama
  else
    die "Ollama is required. Install it from https://ollama.com/download/linux and re-run."
  fi
fi

# ── start Ollama service ──────────────────────────────────────────────────────
step "Starting Ollama"

ollama_running() {
  # Try the REST API; Ollama listens on 11434 by default
  curl -sf http://localhost:11434/ &>/dev/null
}

start_ollama_systemd() {
  if run_priv systemctl enable --now ollama 2>/dev/null; then
    return 0
  fi
  return 1
}

start_ollama_background() {
  echo "Starting ollama serve in the background..."
  ollama serve &>/tmp/ollama-install.log &
  OLLAMA_PID=$!
  local i
  for i in $(seq 1 15); do
    sleep 1
    if ollama_running; then
      echo "Ollama is up (pid $OLLAMA_PID)"
      return 0
    fi
  done
  die "Ollama did not start within 15 seconds. Check /tmp/ollama-install.log"
}

if ollama_running; then
  echo "Ollama is already running"
elif have systemctl && systemctl list-unit-files ollama.service &>/dev/null 2>&1; then
  start_ollama_systemd || start_ollama_background
else
  start_ollama_background
fi

# ── pull model ────────────────────────────────────────────────────────────────
step "Pulling model: ${COCORE_MODEL}"
echo "(this downloads several gigabytes — grab a coffee)"
ollama pull "$COCORE_MODEL"

# ── PATH reminder ─────────────────────────────────────────────────────────────
# Determine which shell config file to update
SHELL_RC=""
case "${SHELL:-}" in
  */zsh)   SHELL_RC="$HOME/.zshrc" ;;
  */bash)  SHELL_RC="$HOME/.bashrc" ;;
  */fish)  SHELL_RC="$HOME/.config/fish/config.fish" ;;
esac

PATH_LINE='export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"'

add_to_path() {
  if [[ -n "$SHELL_RC" ]] && ! grep -qF '.local/bin' "$SHELL_RC" 2>/dev/null; then
    echo "$PATH_LINE" >> "$SHELL_RC"
    echo "Added PATH update to $SHELL_RC"
  fi
}

if ! have cocore 2>/dev/null || [[ "$(command -v cocore)" != "$BIN_DIR/cocore" ]]; then
  warn "$BIN_DIR is not on your PATH yet."
  if [[ -n "$SHELL_RC" ]] && yn "Add it to $SHELL_RC?"; then
    add_to_path
  else
    echo "Add this to your shell config:"
    echo "  $PATH_LINE"
  fi
fi

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}${BLD}╔══════════════════════════════════════════════════════╗${RST}"
echo -e "${GRN}${BLD}║  cocore installed successfully                       ║${RST}"
echo -e "${GRN}${BLD}╚══════════════════════════════════════════════════════╝${RST}"
echo ""
echo "Next steps:"
echo ""
echo "  1. Pair with your AT Protocol identity (once per machine):"
echo "       cocore agent pair"
echo ""
echo "  2. Start serving:"
echo "       export COCORE_ENGINE_BACKEND=openai"
echo "       export COCORE_OPENAI_BASE_URL=http://127.0.0.1:11434"
echo "       export COCORE_INFERENCE_MODELS=\"${COCORE_MODEL}\""
echo "       cocore agent serve"
echo ""
echo "  Optional — enable deterministic/verifiable inference:"
echo "       export COCORE_DETERMINISTIC=1"
echo ""
echo "  See docs/linux-provider.md for the full configuration reference."
echo ""
