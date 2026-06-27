//! Out-of-process inference engine.
//!
//! Replaces the v0.5.x in-process PyO3+libpython embedding. The agent
//! binary itself has zero Python linkage; `otool -L cocore` shows only
//! libSystem + Apple frameworks. To actually serve inference, we spawn
//! a Python child that hosts `vllm-mlx`'s FastAPI app on a Unix domain
//! socket. Generate requests are proxied as `/v1/chat/completions`
//! over the UDS using a hand-rolled HTTP/1.1 client (no async/UDS-
//! transport dependency).
//!
//! ## Why a subprocess, not PyO3
//!
//! - **Distribution**: PyO3+auto-initialize bakes the build-machine's
//!   `LC_LOAD_DYLIB` path into the binary (e.g.
//!   `/opt/homebrew/opt/python@3.12/.../Python`). On a user's Mac that
//!   path doesn't exist and dyld aborts the process before `main`.
//!   v0.5.3 hit this on every install where the user wasn't running
//!   the exact same Homebrew Python the CI runner had.
//! - **Crash isolation**: a vllm-mlx segfault or OOM kill takes only
//!   this child; the agent restarts it and keeps publishing receipts.
//! - **Lifecycle**: model swap = kill + respawn; no daemon restart.
//!
//! ## Why UDS, not TCP localhost
//!
//! - No port allocation race.
//! - File-mode 0600 → access-controlled by uid.
//! - Path is unique per engine instance (model id + spawning agent
//!   PID + random nonce) so multi-model setups don't need port
//!   juggling AND no two live engines — even across concurrent or
//!   reparented agent processes serving the same model — ever share a
//!   socket file. This is load-bearing: the path is unlinked on
//!   shutdown (by us in `Drop`, by the wrapper's SIGTERM handler, and
//!   by uvicorn's own UDS cleanup), so a shared path means one
//!   engine's teardown deletes another's live socket. Uniqueness makes
//!   every unlink target strictly the unlinker's own socket.
//!
//! ## Lifecycle
//!
//! 1. `SubprocessEngine::new(model, venv_python)` — constructs but
//!    does not spawn. Generates a unique socket path under
//!    `$HOME/.cocore/sockets/`.
//! 2. `start()` — spawns the child (`<venv>/bin/python
//!    cocore_inference_server.py --model <id> --uds <path>`), watches
//!    stdout for `READY`, returns once the socket is bound.
//! 3. `generate()` — POSTs a JSON `/v1/chat/completions` to the UDS;
//!    parses the OpenAI-shaped response.
//! 4. `Drop` — SIGTERM the child, escalate to SIGKILL after 5s if it
//!    hasn't exited, unlink the socket.
//!
//! ## What lives where
//!
//! - The Python wrapper script is embedded into the binary at compile
//!   time via `include_str!` and written to
//!   `$HOME/.cocore/cocore_inference_server.py` on first start. The
//!   script is small (~80 lines) and self-contained; the only
//!   dependency it needs is the venv's `vllm-mlx` + `uvicorn`.
//! - The venv itself is bootstrapped by the install script via `uv`;
//!   `$HOME/.cocore/python/bin/python` is the canonical interpreter
//!   path the agent uses.

// The engine boundary runs on the serve path (and its Drop runs during
// unwind). Deny unwrap/expect/panic in production so a poisoned lock or a
// "can't happen" never aborts the agent the way it did in the field; the
// `#[cfg(test)]` module is exempt.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use anyhow::{anyhow, bail, Context, Result};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::engines::{
    model_prefills_think, DeltaChannel, Engine, GenerateRequest, GenerateResponse, ThinkTagSplitter,
};

/// Max stderr/stdout lines retained per stream for engine-crash
/// diagnostics. The agent NEVER logs child output during normal
/// operation (vllm-mlx's default logging configuration includes
/// prompt fragments, generated tokens, and request bodies; piping
/// any of that into `tracing` would create a content leak through
/// the agent's own log file). Instead, lines accumulate in a bounded
/// ring buffer that is only consulted when the child exits during
/// `start()` polling — at which point dumping the tail is a
/// reasonable tradeoff because (a) the agent is failing to come up
/// and the operator needs *some* signal, and (b) startup failures
/// occur before any inference request lands, so the buffer can't
/// hold prompt content. After `start()` returns Ok, the buffer is
/// orphaned in the worker threads and lines cycle through with
/// nobody reading them.
const ENGINE_RING_BUFFER_CAP: usize = 64;

/// Spawn a thread that drains `stream` line-by-line into `buffer`,
/// evicting oldest entries when the buffer reaches
/// [`ENGINE_RING_BUFFER_CAP`]. The thread exits when the stream's
/// far end closes (subprocess termination or pipe close).
fn spawn_drain<R: std::io::Read + Send + 'static>(stream: R, buffer: Arc<Mutex<VecDeque<String>>>) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        let r = std::io::BufReader::new(stream);
        for line in r.lines().map_while(|l| l.ok()) {
            let Ok(mut buf) = buffer.lock() else { return };
            if buf.len() >= ENGINE_RING_BUFFER_CAP {
                buf.pop_front();
            }
            buf.push_back(line);
        }
    });
}

/// Render the ring buffer as a multi-line string for inclusion in
/// an error message. Each line is prefixed with the stream name so
/// stdout and stderr are distinguishable in the rendered output.
fn render_ring(label: &str, buffer: &Arc<Mutex<VecDeque<String>>>) -> String {
    let Ok(buf) = buffer.lock() else {
        return format!("  [{label}]: <lock poisoned>");
    };
    if buf.is_empty() {
        return format!("  [{label}]: (no output captured)");
    }
    buf.iter()
        .map(|l| format!("  [{label}] {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Total bytes of `model_id`'s HuggingFace hub cache dir (including
/// in-progress `.incomplete` blobs) — the download-progress signal used
/// by the stall-based readiness wait. Best-effort: 0 when the dir
/// doesn't exist yet or can't be read. The agent sets no HF cache
/// override, so this is the default `$HOME/.cache/huggingface/hub`, and
/// a repo `org/name` maps to the `models--org--name` directory.
fn hf_cache_size(model_id: &str) -> u64 {
    let Ok(home) = std::env::var("HOME") else {
        return 0;
    };
    if home.is_empty() {
        return 0;
    }
    let dir = Path::new(&home)
        .join(".cache")
        .join("huggingface")
        .join("hub")
        .join(format!("models--{}", model_id.replace('/', "--")));
    dir_size_bytes(&dir)
}

/// Recursively sum regular-file sizes under `dir`. Uses
/// `symlink_metadata` so HF's `snapshots/*` symlinks (which point back
/// into `blobs/`) aren't double-counted — only the real `blobs/` files
/// (completed + `.incomplete`) are summed. Best-effort; returns 0 on
/// any read error.
fn dir_size_bytes(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        match std::fs::symlink_metadata(&path) {
            Ok(md) if md.is_dir() => total = total.saturating_add(dir_size_bytes(&path)),
            Ok(md) if md.is_file() => total = total.saturating_add(md.len()),
            _ => {}
        }
    }
    total
}

/// Content-safe adaptive human size for progress logs (bytes only, never
/// any prompt/token data). Scales B → TB so a multi-GB weight download
/// doesn't read as "20480 MB"; GB/TB keep one decimal.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut i = 0;
    while value >= 1024.0 && i < UNITS.len() - 1 {
        value /= 1024.0;
        i += 1;
    }
    let decimals = if i >= 3 { 1 } else { 0 };
    format!("{value:.decimals$} {}", UNITS[i])
}

/// HuggingFace token env vars we honor, in priority order. The first
/// non-empty one wins. `COCORE_HF_TOKEN` lets the operator scope a token
/// to cocore without touching the global `HF_TOKEN` that other tools on
/// the box read; the rest are the standard hub variables.
const HF_TOKEN_VARS: [&str; 4] = [
    "COCORE_HF_TOKEN",
    "HF_TOKEN",
    "HF_HUB_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
];

/// Whether `COCORE_DISABLE_XET` is set to an explicit "off" value. Used
/// to let an operator opt the Xet fast-path back ON (we disable it by
/// default — see [`apply_hf_download_env`]).
fn xet_reenabled_by_operator() -> bool {
    matches!(
        std::env::var("COCORE_DISABLE_XET")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// Configure a child `Command`'s HuggingFace download environment so the
/// weight download authenticates and isn't throttled. Applied to every
/// engine spawn (and the confidential pre-warm) — see issue #117.
///
/// Two problems this fixes, both observed when first-serving an uncached
/// Xet-backed model:
///
///  1. **Unauthenticated → 429 throttle collapse.** With no usable token,
///     HF rate-limits the traffic; the Xet adaptive-concurrency controller
///     hits a 429 storm, collapses to its concurrency floor (~40 KB/s), and
///     a multi-GB download can't finish inside the stall window. We resolve
///     a non-empty token from [`HF_TOKEN_VARS`] and export it under the two
///     names huggingface_hub reads (`HF_TOKEN` + `HF_HUB_TOKEN`). Crucially
///     we also **scrub** a set-but-EMPTY token (the launchd default on the
///     reporting host), which HF treats as unauthenticated — leaving it set
///     would shadow nothing useful and keep requests anonymous.
///
///  2. **Xet progress is invisible to the watchdog.** The Xet/CAS path
///     writes a 0-byte `.incomplete` until the head term commits, so the
///     on-disk byte counter the stall watchdog reads stays flat while GBs
///     cross the network — a healthy download reads as "no progress" and is
///     killed. Defaulting `HF_HUB_DISABLE_XET=1` forces the plain-LFS HTTPS
///     path, which both sidesteps the 429-prone Xet protocol AND advances
///     the on-disk counter incrementally so the watchdog sees real progress.
///     An operator who wants Xet back sets `COCORE_DISABLE_XET=0`.
///
/// Content-safe: never logs the token value.
pub fn apply_hf_download_env(cmd: &mut Command) {
    // (1) Token: first non-empty wins; export under both hub names. If none
    // is non-empty, strip any (possibly empty) token vars from the child so
    // an empty `HF_TOKEN` can't pin requests to the throttled anonymous tier.
    let token = HF_TOKEN_VARS
        .iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.trim().is_empty()));
    match token {
        Some(token) => {
            cmd.env("HF_TOKEN", &token).env("HF_HUB_TOKEN", &token);
        }
        None => {
            for var in HF_TOKEN_VARS {
                cmd.env_remove(var);
            }
        }
    }

    // (2) Xet: disabled by default (plain-LFS), opt back in with
    // COCORE_DISABLE_XET=0.
    if xet_reenabled_by_operator() {
        cmd.env_remove("HF_HUB_DISABLE_XET");
    } else {
        cmd.env("HF_HUB_DISABLE_XET", "1");
    }
}

/// Newest modification time (as seconds since the Unix epoch) of any file
/// under the HuggingFace Xet cache/log tree, or 0 if absent. The Xet/CAS
/// reconstruction path leaves the model's on-disk blob at 0 bytes until its
/// head term commits (see [`apply_hf_download_env`]), so [`hf_cache_size`]
/// reads flat during an active Xet transfer. This tree — chunk cache and the
/// per-generation structured logs under `~/.cache/huggingface/xet/` — IS
/// touched continuously while bytes flow, so an advancing mtime here is a
/// valid "transfer is alive" signal the stall watchdog can fall back on.
/// Best-effort; 0 on any read error.
fn xet_activity_mtime() -> u64 {
    // Mirror huggingface_hub's cache-root resolution:
    // HF_HOME > XDG_CACHE_HOME/huggingface > ~/.cache/huggingface.
    // (`std::env::var` returns a Result, so `.ok().filter(..)` to drop both
    // the unset and the set-but-empty cases before falling through.)
    let hf_cache_root =
        if let Some(hf_home) = std::env::var("HF_HOME").ok().filter(|v| !v.is_empty()) {
            PathBuf::from(hf_home)
        } else if let Some(xdg) = std::env::var("XDG_CACHE_HOME")
            .ok()
            .filter(|v| !v.is_empty())
        {
            Path::new(&xdg).join("huggingface")
        } else {
            let Ok(home) = std::env::var("HOME") else {
                return 0;
            };
            if home.is_empty() {
                return 0;
            }
            Path::new(&home).join(".cache").join("huggingface")
        };
    let dir = hf_cache_root.join("xet");
    newest_mtime_secs(&dir)
}

/// Recursively find the newest file mtime (seconds since epoch) under `dir`.
/// Uses `symlink_metadata` so symlinks are stat'd as links, not followed.
/// Best-effort; 0 on any read error or empty tree.
fn newest_mtime_secs(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut newest = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        match std::fs::symlink_metadata(&path) {
            Ok(md) if md.is_dir() => newest = newest.max(newest_mtime_secs(&path)),
            Ok(md) => {
                if let Ok(mtime) = md.modified() {
                    if let Ok(since) = mtime.duration_since(std::time::UNIX_EPOCH) {
                        newest = newest.max(since.as_secs());
                    }
                }
            }
            _ => {}
        }
    }
    newest
}

/// Stall timeout for the readiness wait, honoring a `COCORE_DOWNLOAD_STALL_TIMEOUT`
/// override (whole seconds). Defaults to [`READY_STALL_TIMEOUT`]. An operator on a
/// slow link pulling a large Xet model that genuinely needs more than the default
/// window can raise this; a malformed/zero value falls back to the default.
fn ready_stall_timeout() -> Duration {
    std::env::var("COCORE_DOWNLOAD_STALL_TIMEOUT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .map(Duration::from_secs)
        .unwrap_or(READY_STALL_TIMEOUT)
}

/// Embedded Python wrapper. Written to disk once at first spawn so the
/// agent ships as a single static binary, no separate file to install
/// alongside it.
const WRAPPER_SCRIPT: &str = include_str!("../../python/cocore_inference_server.py");

/// Where on disk we write the wrapper + sockets. Lives under
/// `~/.cocore/` next to the venv so a `rm -rf ~/.cocore` cleans
/// everything in one stroke.
fn state_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("no $HOME"))?;
    Ok(home.join(".cocore"))
}

/// Max bytes for the assembled ABSOLUTE socket path. The macOS `sun_path`
/// limit is 104; we hold a margin so a slightly longer sockets dir can
/// never push us over and trigger `ENAMETOOLONG` in the wrapper's bind().
const SOCKET_PATH_CEILING: usize = 100;

/// Build a length-safe socket *filename* for `model_id` under `sockets_dir`,
/// guaranteeing `sockets_dir.join(name)` stays within [`SOCKET_PATH_CEILING`].
///
/// The name is `engine-<model><-hash>-<pid>-<nonce>.sock`. Uniqueness comes
/// entirely from `pid` + `nonce`; the model text is cosmetic (so `ls
/// ~/.cocore/sockets` still tells you which model each socket serves) and is
/// truncated to whatever byte budget remains after the fixed parts. An 8-hex
/// SHA-256 prefix of the FULL model id keeps the name distinguishable and
/// stable even when the model text is truncated to nothing on a pathological
/// long home directory.
fn socket_filename(sockets_dir: &Path, model_id: &str, pid: u32, nonce: u32) -> String {
    use sha2::{Digest, Sha256};
    // 8 hex chars from the full id — survives truncation of the model text.
    let hash = hex::encode(&Sha256::digest(model_id.as_bytes())[..4]);
    // HF NSIDs contain slashes (would create subdirs); keep only chars that
    // are safe and readable in a filename.
    let sanitized: String = model_id
        .replace('/', "_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    // Fixed overhead = sockets_dir + path separator + "engine-" + model_seg
    // + "-" + hash(8) + "-" + pid + "-" + nonce(8) + ".sock". Everything but
    // model_seg is constant for this call, so compute the budget left for it.
    let suffix = format!("-{hash}-{pid}-{nonce:08x}.sock");
    let prefix = "engine-";
    let dir_len = sockets_dir.as_os_str().len() + 1; // + separator
    let fixed = dir_len + prefix.len() + suffix.len();
    let budget = SOCKET_PATH_CEILING.saturating_sub(fixed);
    let model_seg: String = sanitized.chars().take(budget).collect();
    format!("{prefix}{model_seg}{suffix}")
}

/// Readiness is **stall-based**, not a fixed total budget. A cold first
/// run downloads the model weights from HuggingFace inside the child
/// (can be tens of GB), then Metal-mmaps them — a 20 GB model at a
/// healthy ~6 MB/s is ~55 min, so the old fixed 300 s total budget
/// killed perfectly healthy slow downloads. Instead we watch the
/// model's HF cache dir grow: as long as bytes keep arriving (or the
/// post-download load makes the socket ready), we keep waiting. We give
/// up only when there's been NO readiness AND NO download progress for
/// `READY_STALL_TIMEOUT` (a truly stuck/failed download or a wedged
/// load), with `READY_HARD_CAP` as an absolute backstop.
const READY_STALL_TIMEOUT: Duration = Duration::from_secs(300);
/// Absolute ceiling regardless of progress — paranoia backstop so a
/// pathological "1 byte every 4 min forever" can't hang the serve loop.
/// Sized for a multi-tens-of-GB download on a slow link.
const READY_HARD_CAP: Duration = Duration::from_secs(6 * 60 * 60);

/// Per-request HTTP timeout against the subprocess. Inference can take
/// 30+ seconds for long completions on a small Mac; 300s is the same
/// ceiling vllm-mlx's `--timeout` uses by default.
const HTTP_TIMEOUT: Duration = Duration::from_secs(300);

/// Idle timeout between streamed body reads. Reset implicitly on each
/// successful read; if the engine stalls mid-stream for longer than
/// this we treat it as a disconnect.
const HTTP_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct SubprocessEngine {
    model_id: String,
    venv_python: PathBuf,
    socket_path: PathBuf,
    child: Mutex<Option<Child>>,
}

impl SubprocessEngine {
    /// Construct an engine bound to `model_id`. Does not spawn the
    /// child — call `start()` to do that. `venv_python` is the
    /// interpreter the install script bootstrapped (typically
    /// `$HOME/.cocore/python/bin/python`).
    pub fn new(model_id: impl Into<String>, venv_python: PathBuf) -> Result<Self> {
        let model_id = model_id.into();
        let sockets_dir = state_dir()?.join("sockets");
        std::fs::create_dir_all(&sockets_dir).with_context(|| {
            format!(
                "creating sockets dir {} for engine {}",
                sockets_dir.display(),
                model_id
            )
        })?;
        // Build a per-instance socket filename: `engine-<model>-<pid>-
        // <nonce>.sock`. The leading model segment keeps the path
        // human-readable (`ls ~/.cocore/sockets` tells you which model
        // each socket serves); the trailing pid + random nonce make it
        // UNIQUE to this engine instance.
        //
        // Uniqueness is the whole point. An earlier revision keyed the
        // path solely on the model id, so every engine instance for a
        // model shared one socket file. Because shutdown paths unlink
        // that file (our Drop, the wrapper's SIGTERM handler, uvicorn's
        // own UDS cleanup), terminating ANY process for the model —
        // including a stale orphan from a previous agent run — deleted
        // the socket the *live* engine was serving on, silently
        // breaking inference. Two concurrent agents (e.g. a reparented
        // old agent + a fresh one) also raced to unlink+rebind the same
        // path. A per-instance path removes both failure modes: every
        // unlink now targets only the unlinker's own socket.
        //
        // The model segment is cosmetic — uniqueness comes from the pid +
        // nonce — so `socket_filename` budgets it against the macOS
        // `sun_path` limit: with a long $HOME, capping only the model
        // segment (as an earlier revision did) still let the assembled
        // ABSOLUTE path overflow, and the wrapper's bind() then raised
        // `ENAMETOOLONG` and the engine never came up.
        let pid = std::process::id();
        let nonce: u32 = rand::random();
        let socket_path = sockets_dir.join(socket_filename(&sockets_dir, &model_id, pid, nonce));
        Ok(Self {
            model_id,
            venv_python,
            socket_path,
            child: Mutex::new(None),
        })
    }

    /// Write the embedded Python wrapper to disk (idempotent — only
    /// writes if the file is missing or its content differs). Lives at
    /// `~/.cocore/cocore_inference_server.py` so it's easy to inspect
    /// when debugging.
    fn ensure_wrapper_on_disk() -> Result<PathBuf> {
        let path = state_dir()?.join("cocore_inference_server.py");
        let needs_write = !matches!(
            std::fs::read_to_string(&path),
            Ok(existing) if existing == WRAPPER_SCRIPT
        );
        if needs_write {
            std::fs::write(&path, WRAPPER_SCRIPT)
                .with_context(|| format!("writing wrapper to {}", path.display()))?;
        }
        Ok(path)
    }

    /// Remove orphaned engine sockets under `sockets_dir` that no
    /// longer have a listener.
    ///
    /// A file matching our `engine-*.sock` naming scheme is "stale"
    /// when `connect()` is refused (`ECONNREFUSED`): the socket file
    /// exists on disk but no process is `accept()`ing on it, which
    /// means the engine that bound it died without unlinking (SIGKILL,
    /// crash, power loss). Such a file is provably unowned — removing
    /// it is safe.
    ///
    /// If `connect()` *succeeds*, some live engine is serving on the
    /// socket; we leave it strictly alone even though, post-uniqueness,
    /// it isn't ours. Any other error (permission denied, a `NotFound`
    /// race with another sweeper) is also left alone — we only delete
    /// on a definitive refusal, never on ambiguity. This is the
    /// "prove it's unowned" rule: when in doubt, don't touch it.
    fn sweep_stale_sockets(sockets_dir: &Path) {
        let Ok(entries) = std::fs::read_dir(sockets_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_engine_sock = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("engine-") && n.ends_with(".sock"));
            if !is_engine_sock {
                continue;
            }
            match UnixStream::connect(&path) {
                // A live engine is accept()ing here — not ours to remove.
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    // No listener: the creating engine is gone. Reap it.
                    if std::fs::remove_file(&path).is_ok() {
                        tracing::debug!(socket = %path.display(), "reaped stale engine socket");
                    }
                }
                // Ambiguous (permission, NotFound race, etc.) — leave it.
                Err(_) => {}
            }
        }
    }

    /// Spawn the Python child and block until it answers an HTTP
    /// probe against the UDS. Returns an error if the child crashes
    /// during startup or stalls (no readiness + no download progress
    /// for `READY_STALL_TIMEOUT`; see the stall-based wait below).
    ///
    /// "Ready" is defined as: (a) the child process is alive, (b)
    /// the socket file exists, and (c) `GET /v1/models` against the
    /// socket returns a 2xx response. (c) is the load-bearing check —
    /// the socket can briefly exist before uvicorn finishes setting
    /// up routes (a vllm-mlx initialization edge case where the
    /// bind() lands during the FastAPI lifespan startup phase but
    /// route handlers aren't installed yet). The HTTP probe catches
    /// that window.
    ///
    /// An earlier revision waited for a `READY` token on the child's
    /// stdout, printed from a `FastAPI.on_event("startup")` hook.
    /// That depended on FastAPI's lifespan ordering relative to
    /// vllm-mlx's own app construction and turned out to fire
    /// unpredictably — the hook would silently no-op or fire after
    /// uvicorn was already serving. An HTTP probe is independent of
    /// the Python lifecycle and surfaces the actual readable state.
    pub fn start(&self) -> Result<()> {
        // Poison-tolerant: a panic elsewhere must not permanently brick
        // this engine's ability to (re)start its child. See the Drop
        // impl for why we never `.unwrap()` this lock.
        let mut guard = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_some() {
            // Already started. Idempotent.
            return Ok(());
        }
        // Sweep the sockets dir for orphaned files left by engines
        // that died without cleaning up (SIGKILL, crash, power loss).
        // Now that paths are per-instance, nobody else reclaims our old
        // sockets, so without this they'd accumulate forever. The sweep
        // only removes a file it can *prove* is dead (connect refused),
        // so it never touches a socket another live engine is serving.
        if let Some(dir) = self.socket_path.parent() {
            Self::sweep_stale_sockets(dir);
        }

        // Clean up our own (unique) socket path on the off chance a
        // prior instance with an identical pid+nonce left one behind.
        // The Python wrapper also does this, but doing it here too
        // means we can give a cleaner error if the wrapper itself never
        // runs (e.g. venv missing).
        let _ = std::fs::remove_file(&self.socket_path);

        let wrapper = Self::ensure_wrapper_on_disk().context("writing embedded wrapper to disk")?;

        if !self.venv_python.exists() {
            bail!(
                "venv python missing at {}. Run `curl … cocore.dev/agent | sh` to (re)provision the venv.",
                self.venv_python.display()
            );
        }

        tracing::info!(
            model = %self.model_id,
            python = %self.venv_python.display(),
            socket = %self.socket_path.display(),
            "spawning inference subprocess"
        );

        let mut cmd = Command::new(&self.venv_python);
        // No `--vision` flag: vllm-mlx's `load_model` auto-detects MLLM vs LLM
        // from the model's own config, and a vision model loads through the
        // multimodal path on its own (the same /v1/chat/completions endpoint
        // then accepts image_url parts). Forcing MLLM from the model id was
        // brittle — a merge whose id contains "vl" but whose config carries no
        // (or an incomplete) vision_config would be force-loaded as multimodal
        // and crash in mlx_vlm, when auto-detect would have loaded it as text.
        cmd.arg(&wrapper)
            .arg("--model")
            .arg(&self.model_id)
            .arg("--uds")
            .arg(&self.socket_path)
            // Parent-death failsafe: tell the child our PID so its
            // watchdog thread can self-exit if we ever go away without a
            // clean SIGTERM (SIGKILL, crash, `kickstart -k`, the
            // `std::process::exit` we take on a tier/model switch — which
            // skips the Drop below — or an uninstall that just removes the
            // app). Without this the child reparents to launchd and runs
            // forever on a socket nobody can reach. The explicit Drop
            // teardown is still the fast path; this only backstops the
            // exits that never reach Drop.
            .arg("--parent-pid")
            .arg(std::process::id().to_string())
            // Capture stdout + stderr into a bounded ring buffer
            // (see ENGINE_RING_BUFFER_CAP). We deliberately do NOT
            // pipe child output into tracing: vllm-mlx logs prompt
            // fragments and generated tokens by default, and routing
            // any of that through the agent's logger would create a
            // content leak. The ring buffer is only consulted on
            // startup-failure bail paths below.
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Don't inherit a controlling tty. If the agent dies the
            // child does reparent to launchd, but it no longer *survives*
            // there: the `--parent-pid` watchdog above notices the agent
            // is gone and exits the child. Reparenting is just the kernel
            // mechanic; the failsafe is what bounds its lifetime.
            .stdin(Stdio::null());

        // Authenticate + de-throttle the HF weight download, and force the
        // plain-LFS path so the stall watchdog can see byte progress (#117).
        apply_hf_download_env(&mut cmd);

        let mut child = cmd.spawn().with_context(|| {
            format!(
                "spawning {} {} --model {} --uds {}",
                self.venv_python.display(),
                wrapper.display(),
                self.model_id,
                self.socket_path.display()
            )
        })?;

        // Hold a clone of each Arc on the stack so the drain threads
        // outlive the function in steady state (after start() returns
        // Ok, no one consults these — the threads keep cycling lines
        // through the bounded buffer with no consumer until the child
        // dies, at which point the threads exit on EOF).
        let stdout_buf: Arc<Mutex<VecDeque<String>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(ENGINE_RING_BUFFER_CAP)));
        let stderr_buf: Arc<Mutex<VecDeque<String>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(ENGINE_RING_BUFFER_CAP)));
        if let Some(stdout) = child.stdout.take() {
            spawn_drain(stdout, Arc::clone(&stdout_buf));
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_drain(stderr, Arc::clone(&stderr_buf));
        }

        // Poll for readiness. Three checks per iteration:
        //   1. Child still alive? — try_wait returns Some(status) if
        //      it exited; bail with the status.
        //   2. Socket exists? — fast filesystem check before paying
        //      for a connect+HTTP-write.
        //   3. HTTP probe succeeds? — `GET /v1/models` against the
        //      socket; treat any 2xx response as ready.
        //
        // Backoff: 250ms between iterations. Model load is dominated
        // by Metal mmap (seconds, not milliseconds), so polling
        // faster doesn't help much. 250ms keeps the polling overhead
        // negligible while still feeling responsive.
        // Stall-based wait: keep going as long as the child is alive AND
        // (it becomes ready OR the HF download keeps making progress).
        // Give up only after READY_STALL_TIMEOUT of no readiness + no new
        // bytes, or the absolute READY_HARD_CAP. This lets a healthy slow
        // download (tens of GB at a few MB/s) finish instead of being
        // killed by a fixed total budget.
        let started = Instant::now();
        let mut last_progress = started;
        let mut last_bytes = hf_cache_size(&self.model_id);
        // Xet/CAS transfers leave the on-disk blob at 0 bytes until the head
        // term commits, so `last_bytes` stays flat while GBs cross the wire.
        // The Xet cache/log tree IS touched continuously during the transfer,
        // so an advancing mtime there is our fallback "still alive" signal.
        let mut last_xet_mtime = xet_activity_mtime();
        let stall_timeout = ready_stall_timeout();
        let mut last_log = started;
        loop {
            if self.socket_path.exists() && self.probe_ready() {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                bail!(
                    "inference subprocess for {} exited during startup with {}\n\
                     Recent engine output (no request has been served yet — content-safe to share):\n{}\n{}",
                    self.model_id,
                    status,
                    render_ring("stdout", &stdout_buf),
                    render_ring("stderr", &stderr_buf),
                );
            }

            let now = Instant::now();
            let bytes = hf_cache_size(&self.model_id);
            if bytes > last_bytes {
                last_bytes = bytes;
                last_progress = now;
            }
            // Xet-aware progress: even when the on-disk byte counter is flat
            // (the head-term-commit behavior above), a freshly-written file in
            // the Xet cache/log tree means the transfer is actively moving, so
            // don't let the stall watchdog kill a healthy Xet download.
            let xet_mtime = xet_activity_mtime();
            if xet_mtime > last_xet_mtime {
                last_xet_mtime = xet_mtime;
                last_progress = now;
            }
            // Periodic, content-safe progress line (byte counts only — no
            // prompt/token data). Gives the agent log *some* visibility into
            // an otherwise-silent multi-GB download.
            if last_bytes > 0 && now.duration_since(last_log) >= Duration::from_secs(15) {
                tracing::info!(
                    model = %self.model_id,
                    downloaded = %human_bytes(last_bytes),
                    "provisioning: model weights downloading"
                );
                last_log = now;
            }

            if now.duration_since(last_progress) > stall_timeout {
                let _ = child.kill();
                bail!(
                    "inference subprocess for {} made no progress for {}s ({} downloaded so far) and never became ready. \
                     Common causes: a stalled/failed HF download, vllm-mlx import error, or missing venv.\n\
                     Recent engine output (no request has been served yet — content-safe to share):\n{}\n{}",
                    self.model_id,
                    stall_timeout.as_secs(),
                    human_bytes(last_bytes),
                    render_ring("stdout", &stdout_buf),
                    render_ring("stderr", &stderr_buf),
                );
            }
            if now.duration_since(started) > READY_HARD_CAP {
                let _ = child.kill();
                bail!(
                    "inference subprocess for {} did not become ready within the {}h hard cap ({} downloaded). \
                     Recent engine output (content-safe):\n{}\n{}",
                    self.model_id,
                    READY_HARD_CAP.as_secs() / 3600,
                    human_bytes(last_bytes),
                    render_ring("stdout", &stdout_buf),
                    render_ring("stderr", &stderr_buf),
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        tracing::info!(model = %self.model_id, "inference subprocess ready");
        *guard = Some(child);
        Ok(())
    }

    /// Probe `GET /v1/models` to confirm the FastAPI app under
    /// uvicorn is actually answering requests (not just listening on
    /// the socket). Any 2xx response is treated as ready; everything
    /// else (connect refused, 503, timeout) is treated as "not yet"
    /// and the caller retries.
    fn probe_ready(&self) -> bool {
        // Short timeouts here — we're inside a polling loop and don't
        // want a single hung probe to eat into the stall window.
        let Ok(mut stream) = UnixStream::connect(&self.socket_path) else {
            return false;
        };
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let req = b"GET /v1/models HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        if stream.write_all(req).is_err() {
            return false;
        }
        let _ = stream.flush();
        let mut buf = [0u8; 256];
        let n = match stream.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => return false,
        };
        // Look at the status line. `HTTP/1.1 2xx ...`.
        let s = match std::str::from_utf8(&buf[..n]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        s.starts_with("HTTP/1.1 2") || s.starts_with("HTTP/1.0 2")
    }

    /// Best-effort liveness check. True when the child is running and
    /// the socket exists. Does NOT round-trip a request — `generate()`
    /// will surface any deeper issue if there is one.
    fn is_alive(&self) -> bool {
        let mut guard = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(child) = guard.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_status)) => false, // child exited
            Ok(None) => self.socket_path.exists(),
            Err(_) => false,
        }
    }

    /// Synchronous HTTP/1.1 POST against the UDS. Hand-rolled to avoid
    /// pulling in `hyperlocal` / `hyper` just for one route — the
    /// agent binary already keeps a tight dep surface.
    fn http_post_uds(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "connecting to inference socket {}",
                self.socket_path.display()
            )
        })?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.set_read_timeout(Some(HTTP_TIMEOUT))?;

        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        );
        stream
            .write_all(req_head.as_bytes())
            .context("writing HTTP request head")?;
        stream
            .write_all(body)
            .context("writing HTTP request body")?;
        stream.flush().ok();

        let mut all = Vec::new();
        stream
            .read_to_end(&mut all)
            .context("reading HTTP response")?;

        // Find end-of-headers.
        let hdr_end = all
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow!("no header/body separator in response"))?;
        let headers = &all[..hdr_end];
        let body_start = hdr_end + 4;
        let body_bytes = &all[body_start..];

        // Parse status line.
        let status_line = std::str::from_utf8(headers)
            .ok()
            .and_then(|s| s.lines().next())
            .ok_or_else(|| anyhow!("non-UTF8 response headers"))?;
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        let status = parts
            .get(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow!("could not parse status from {status_line:?}"))?;
        if !(200..300).contains(&status) {
            // Do NOT log the response body — vllm-mlx's error
            // responses frequently echo back the request payload
            // (including the prompt) in the `error.message` field
            // and putting that into an anyhow chain would leak it
            // through the agent's error log. Status + length is
            // enough to triage; a structured replay against the
            // engine reproduces the body when needed.
            bail!(
                "engine returned HTTP {status} ({} body bytes elided to avoid content logging)",
                body_bytes.len()
            );
        }
        Ok(body_bytes.to_vec())
    }

    /// Render a message's content into the OpenAI `chat.completions`
    /// shape the engine server accepts. A text-only message keeps the
    /// scalar-string form (byte-identical to the historical text path);
    /// a message with images becomes the array-of-parts form, with each
    /// image emitted as an `image_url` data URI — exactly what mlx-vlm's
    /// OpenAI-compatible server consumes.
    fn render_content(m: &crate::engines::Message) -> serde_json::Value {
        use crate::engines::ContentPart;
        if !m.has_images() {
            return serde_json::Value::String(m.content_text());
        }
        let parts: Vec<serde_json::Value> = m
            .content
            .iter()
            .map(|p| match p {
                ContentPart::Text(text) => serde_json::json!({ "type": "text", "text": text }),
                ContentPart::Image { mime, data_b64 } => serde_json::json!({
                    "type": "image_url",
                    "image_url": { "url": format!("data:{mime};base64,{data_b64}") },
                }),
            })
            .collect();
        serde_json::Value::Array(parts)
    }

    fn build_chat_body(request: &GenerateRequest, stream: bool) -> Result<serde_json::Value> {
        let messages: Vec<serde_json::Value> = request
            .messages
            .iter()
            .map(|m| {
                serde_json::json!({
                    "role": m.role,
                    "content": Self::render_content(m),
                })
            })
            .collect();
        let mut body = serde_json::json!({
            "model": request.model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "stream": stream,
        });
        if let Some(t) = request.temperature {
            body["temperature"] = serde_json::json!(t);
        }
        if let Some(p) = request.top_p {
            body["top_p"] = serde_json::json!(p);
        }
        Ok(body)
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }

    fn parse_http_status(headers: &[u8]) -> Result<u16> {
        let s = std::str::from_utf8(headers).context("response headers not UTF-8")?;
        let line = s
            .lines()
            .next()
            .ok_or_else(|| anyhow!("empty HTTP response"))?;
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        parts
            .get(1)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| anyhow!("could not parse status from {line:?}"))
    }

    /// Drain complete `data:` lines from an SSE body buffer. Returns
    /// when the buffer ends mid-line so the caller can read more bytes.
    fn process_sse_buffer(
        buf: &mut Vec<u8>,
        cursor: &mut usize,
        splitter: &mut ThinkTagSplitter,
        on_data: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
        tokens: &mut (u64, u64),
    ) -> Result<()> {
        while *cursor < buf.len() {
            let rest = &buf[*cursor..];
            let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
                break;
            };
            let mut line = &rest[..nl];
            *cursor += nl + 1;
            if line.ends_with(b"\r") {
                line = &line[..line.len() - 1];
            }
            if line.is_empty() {
                continue;
            }
            let Ok(s) = std::str::from_utf8(line) else {
                continue;
            };
            let Some(data) = s.strip_prefix("data: ") else {
                continue;
            };
            if data == "[DONE]" {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
                continue;
            };
            // Reasoning ("thinking") arrives on a sibling field in
            // vLLM/DeepSeek-style servers; forward it verbatim on the
            // Reasoning channel.
            if let Some(reasoning) = v
                .pointer("/choices/0/delta/reasoning_content")
                .or_else(|| v.pointer("/choices/0/delta/reasoning"))
                .and_then(|c| c.as_str())
            {
                if !reasoning.is_empty() {
                    on_data(DeltaChannel::Reasoning, reasoning)?;
                }
            }
            // The answer text may itself carry inline <think>...</think>
            // markers (local MLX models that don't use a reasoning field);
            // the splitter separates those, buffering across deltas.
            if let Some(content) = v
                .pointer("/choices/0/delta/content")
                .and_then(|c| c.as_str())
            {
                if !content.is_empty() {
                    splitter.push(content, on_data)?;
                }
            }
            if let Some(u) = v.get("usage") {
                if let Some(p) = u.get("prompt_tokens").and_then(|v| v.as_u64()) {
                    tokens.0 = p;
                }
                if let Some(c) = u.get("completion_tokens").and_then(|v| v.as_u64()) {
                    tokens.1 = c;
                }
            }
        }
        if *cursor > 8192 {
            buf.drain(..*cursor);
            *cursor = 0;
        }
        Ok(())
    }

    fn http_post_stream_uds(
        &self,
        path: &str,
        body: &[u8],
        start_in_reasoning: bool,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<(u64, u64)> {
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "connecting to inference socket {}",
                self.socket_path.display()
            )
        })?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.set_read_timeout(Some(HTTP_STREAM_IDLE_TIMEOUT))?;

        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        );
        stream
            .write_all(req_head.as_bytes())
            .context("writing HTTP request head")?;
        stream
            .write_all(body)
            .context("writing HTTP request body")?;
        stream.flush().ok();

        let mut buf = Vec::new();
        let mut read_buf = [0u8; 4096];
        let mut header_end: Option<usize> = None;
        let mut body_cursor = 0usize;
        let mut tokens = (0u64, 0u64);
        let mut splitter = if start_in_reasoning {
            ThinkTagSplitter::new_in_reasoning()
        } else {
            ThinkTagSplitter::new()
        };

        loop {
            let n = match stream.read(&mut read_buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    bail!(
                        "engine stream stalled (no bytes for {}s)",
                        HTTP_STREAM_IDLE_TIMEOUT.as_secs()
                    );
                }
                Err(e) => return Err(e.into()),
            };
            buf.extend_from_slice(&read_buf[..n]);

            if header_end.is_none() {
                if let Some(end) = Self::find_header_end(&buf) {
                    let status = Self::parse_http_status(&buf[..end.saturating_sub(4)])?;
                    if !(200..300).contains(&status) {
                        bail!(
                            "engine returned HTTP {status} (streaming body elided to avoid content logging)"
                        );
                    }
                    header_end = Some(end);
                    body_cursor = end;
                }
                continue;
            }

            Self::process_sse_buffer(
                &mut buf,
                &mut body_cursor,
                &mut splitter,
                on_delta,
                &mut tokens,
            )?;
        }
        // Flush any partial <think> marker held at end of stream.
        splitter.finish(on_delta)?;

        Ok(tokens)
    }
}

impl SubprocessEngine {
    /// Reap the child (if running) and unlink its socket. SIGTERM first —
    /// the Python wrapper has a SIGTERM handler that unlinks the socket
    /// cleanly — then escalate to SIGKILL after 5s if it hasn't exited.
    ///
    /// Shared by `Drop` and [`Engine::terminate`] so both the unwind path
    /// and the explicit pre-`std::process::exit` reap behave identically.
    /// Takes the child out under the lock so a second call is a no-op.
    /// Poison-tolerant on the lock (see the Drop note below) and safe to
    /// call from any thread.
    fn terminate_child(&self) {
        // NEVER `.unwrap()` a lock here. When this runs from Drop during an
        // unwind, an `unwrap()` on a poisoned mutex would panic, and a panic
        // while panicking is `panic_in_cleanup` → an immediate `abort()`
        // (SIGABRT) that (a) kills the whole agent and (b) skips the SIGTERM
        // below, orphaning the Python inference child. Recover the guard from
        // the poison instead: the `Option<Child>` it protects is still valid
        // data, and we WANT to run the kill path regardless of whether some
        // other thread panicked.
        let mut guard = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(mut child) = guard.take() {
            tracing::info!(model = %self.model_id, "terminating inference subprocess");
            #[cfg(unix)]
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    _ if Instant::now() > deadline => {
                        let _ = child.kill();
                        break;
                    }
                    _ => std::thread::sleep(Duration::from_millis(100)),
                }
            }
            let _ = child.wait();
        }
        // Socket cleanup. The wrapper's SIGTERM handler should have
        // done this; we belt-and-suspenders here.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for SubprocessEngine {
    fn drop(&mut self) {
        self.terminate_child();
    }
}

impl Engine for SubprocessEngine {
    fn name(&self) -> &'static str {
        "subprocess-vllm-mlx"
    }

    fn ready(&self) -> bool {
        self.is_alive()
    }

    fn terminate(&self) {
        self.terminate_child();
    }

    /// Reap the dead child (if any) and respawn it on the same
    /// per-instance socket path.
    ///
    /// `start()` is idempotent on `child.is_some()`, so a dead-but-still-
    /// recorded child would make it short-circuit as "already started".
    /// We therefore `take()` the recorded child first — best-effort
    /// `kill()` + `wait()` to make sure it's gone and won't be left as a
    /// zombie — then let `start()` sweep stale sockets, rebind, and poll
    /// the new child to readiness. Poison-tolerant on the lock for the
    /// same reason `start()`/`Drop` are: a panic elsewhere must not brick
    /// recovery.
    fn restart(&self) -> Result<()> {
        {
            let mut guard = self
                .child
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        tracing::info!(model = %self.model_id, "respawning dead inference subprocess");
        self.start()
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        let body = Self::build_chat_body(request, false)?;
        let body_bytes = Zeroizing::new(serde_json::to_vec(&body)?);

        let resp_bytes = self.http_post_uds("/v1/chat/completions", &body_bytes)?;
        let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).with_context(|| {
            format!(
                "parsing engine JSON response ({} body bytes elided to avoid content logging)",
                resp_bytes.len()
            )
        })?;

        let text = resp
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tokens_in = resp
            .pointer("/usage/prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tokens_out = resp
            .pointer("/usage/completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        Ok(GenerateResponse {
            text,
            tokens_in,
            tokens_out,
        })
    }

    fn generate_stream(
        &self,
        request: &GenerateRequest,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        let body = Self::build_chat_body(request, true)?;
        let body_bytes = Zeroizing::new(serde_json::to_vec(&body)?);
        let (tokens_in, tokens_out) = self.http_post_stream_uds(
            "/v1/chat/completions",
            &body_bytes,
            model_prefills_think(&request.model),
            on_delta,
        )?;
        Ok(GenerateResponse {
            text: String::new(),
            tokens_in,
            tokens_out,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a full SSE body through the parser and collect channel-tagged
    /// deltas plus the final token counts.
    fn drain(body: &str) -> (Vec<(DeltaChannel, String)>, (u64, u64)) {
        let mut buf = body.as_bytes().to_vec();
        let mut cursor = 0usize;
        let mut splitter = ThinkTagSplitter::new();
        let mut tokens = (0u64, 0u64);
        let mut out: Vec<(DeltaChannel, String)> = Vec::new();
        SubprocessEngine::process_sse_buffer(
            &mut buf,
            &mut cursor,
            &mut splitter,
            &mut |ch, s| {
                out.push((ch, s.to_string()));
                Ok(())
            },
            &mut tokens,
        )
        .unwrap();
        splitter
            .finish(&mut |ch, s| {
                out.push((ch, s.to_string()));
                Ok(())
            })
            .unwrap();
        (out, tokens)
    }

    /// Serializes the env-mutating tests below — `std::env::set_var` is
    /// process-global, so they'd race each other under cargo's parallel runner.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Collect a Command's explicit env diffs into (key -> Option<value>).
    fn cmd_env(cmd: &Command) -> std::collections::HashMap<String, Option<String>> {
        cmd.get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    /// A non-empty token is exported under both hub names and Xet is disabled
    /// by default. Env vars are process-global, so this test owns HF_* state.
    #[test]
    fn apply_hf_env_passes_token_and_disables_xet() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for var in HF_TOKEN_VARS {
            std::env::remove_var(var);
        }
        std::env::remove_var("COCORE_DISABLE_XET");
        std::env::set_var("COCORE_HF_TOKEN", "hf_secret123");

        let mut cmd = Command::new("true");
        apply_hf_download_env(&mut cmd);
        let env = cmd_env(&cmd);

        assert_eq!(env.get("HF_TOKEN"), Some(&Some("hf_secret123".to_string())));
        assert_eq!(
            env.get("HF_HUB_TOKEN"),
            Some(&Some("hf_secret123".to_string()))
        );
        assert_eq!(env.get("HF_HUB_DISABLE_XET"), Some(&Some("1".to_string())));

        std::env::remove_var("COCORE_HF_TOKEN");
    }

    /// A set-but-EMPTY token (the launchd default that triggered #117) is
    /// scrubbed from the child env, not propagated as an empty value.
    #[test]
    fn apply_hf_env_scrubs_empty_token() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for var in HF_TOKEN_VARS {
            std::env::remove_var(var);
        }
        std::env::remove_var("COCORE_DISABLE_XET");
        std::env::set_var("HF_TOKEN", ""); // set-but-empty

        let mut cmd = Command::new("true");
        apply_hf_download_env(&mut cmd);
        let env = cmd_env(&cmd);

        // env_remove records the key with a None value.
        assert_eq!(env.get("HF_TOKEN"), Some(&None));
        assert_eq!(env.get("HF_HUB_TOKEN"), Some(&None));

        std::env::remove_var("HF_TOKEN");
    }

    /// COCORE_DISABLE_XET=0 re-enables the Xet fast path (no disable var set).
    #[test]
    fn apply_hf_env_xet_opt_out_reenables() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for var in HF_TOKEN_VARS {
            std::env::remove_var(var);
        }
        std::env::set_var("COCORE_DISABLE_XET", "0");

        let mut cmd = Command::new("true");
        apply_hf_download_env(&mut cmd);
        let env = cmd_env(&cmd);

        // Removed (operator wants Xet), not set to "1".
        assert_eq!(env.get("HF_HUB_DISABLE_XET"), Some(&None));

        std::env::remove_var("COCORE_DISABLE_XET");
    }

    #[test]
    fn extracts_reasoning_content_field_onto_reasoning_channel() {
        let body = "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"hmm\"}}]}\n\
                    data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\
                    data: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2}}\n\
                    data: [DONE]\n";
        let (out, tokens) = drain(body);
        let reasoning: String = out
            .iter()
            .filter(|(c, _)| *c == DeltaChannel::Reasoning)
            .map(|(_, s)| s.as_str())
            .collect();
        let content: String = out
            .iter()
            .filter(|(c, _)| *c == DeltaChannel::Content)
            .map(|(_, s)| s.as_str())
            .collect();
        assert_eq!(reasoning, "hmm");
        assert_eq!(content, "hi");
        assert_eq!(tokens, (4, 2));
    }

    #[test]
    fn splits_inline_think_tags_in_content_field() {
        // A model that has no reasoning_content field but inlines <think> in
        // its content stream is still separated.
        let body =
            "data: {\"choices\":[{\"delta\":{\"content\":\"<think>why</think>because\"}}]}\n\
             data: [DONE]\n";
        let (out, _) = drain(body);
        let reasoning: String = out
            .iter()
            .filter(|(c, _)| *c == DeltaChannel::Reasoning)
            .map(|(_, s)| s.as_str())
            .collect();
        let content: String = out
            .iter()
            .filter(|(c, _)| *c == DeltaChannel::Content)
            .map(|(_, s)| s.as_str())
            .collect();
        assert_eq!(reasoning, "why");
        assert_eq!(content, "because");
    }

    #[test]
    fn build_chat_body_emits_scalar_content_for_text() {
        let req = GenerateRequest {
            model: "m".into(),
            messages: vec![crate::engines::Message::text("user", "hi")],
            max_tokens: 8,
            temperature: None,
            top_p: None,
        };
        let body = SubprocessEngine::build_chat_body(&req, false).unwrap();
        // Text-only stays a scalar string — byte-identical to the legacy path.
        assert_eq!(body["messages"][0]["content"], serde_json::json!("hi"));
    }

    #[test]
    fn build_chat_body_emits_image_url_parts_for_vision() {
        use crate::engines::{ContentPart, Message};
        let req = GenerateRequest {
            model: "vlm".into(),
            messages: vec![Message {
                role: "user".into(),
                content: vec![
                    ContentPart::Text("describe".into()),
                    ContentPart::Image {
                        mime: "image/png".into(),
                        data_b64: "aGVsbG8=".into(),
                    },
                ],
            }],
            max_tokens: 8,
            temperature: None,
            top_p: None,
        };
        let body = SubprocessEngine::build_chat_body(&req, false).unwrap();
        let parts = body["messages"][0]["content"]
            .as_array()
            .expect("array content");
        assert_eq!(
            parts[0],
            serde_json::json!({ "type": "text", "text": "describe" })
        );
        assert_eq!(
            parts[1],
            serde_json::json!({
                "type": "image_url",
                "image_url": { "url": "data:image/png;base64,aGVsbG8=" },
            }),
        );
    }

    /// A pathological long home dir + a long model id must still produce an
    /// absolute path within the `sun_path` ceiling — the bug that made the
    /// wrapper's bind() raise `ENAMETOOLONG`.
    #[test]
    fn socket_filename_stays_under_ceiling() {
        let dir = Path::new("/Users/some.very.long.username.here/.cocore/sockets");
        let model = "lmstudio-community/gemma-4-12B-it-MLX-8bit-extra-long-suffix-padding";
        let name = socket_filename(dir, model, 99999, 0xdeadbeef);
        let full = dir.join(&name);
        assert!(
            full.as_os_str().len() <= SOCKET_PATH_CEILING,
            "path {} is {} bytes, over ceiling {}",
            full.display(),
            full.as_os_str().len(),
            SOCKET_PATH_CEILING
        );
        // Still recognizable as an engine socket for the stale-socket sweep.
        assert!(name.starts_with("engine-") && name.ends_with(".sock"));
    }

    /// Uniqueness comes from pid + nonce; differing nonces differ.
    #[test]
    fn socket_filename_unique_per_nonce() {
        let dir = Path::new("/Users/u/.cocore/sockets");
        let model = "mlx-community/Qwen2.5-7B-Instruct-4bit";
        let a = socket_filename(dir, model, 4242, 1);
        let b = socket_filename(dir, model, 4242, 2);
        assert_ne!(a, b);
    }

    /// Even when the dir is so long the model text budget is zero, the name
    /// is still a valid, hash-distinguished engine socket.
    #[test]
    fn socket_filename_pure_hash_when_no_room() {
        let long = format!("/{}/sockets", "x".repeat(SOCKET_PATH_CEILING));
        let dir = Path::new(&long);
        let name = socket_filename(dir, "mlx-community/some-model-4bit", 7, 9);
        assert!(name.starts_with("engine-") && name.ends_with(".sock"));
        // No model text survived, but the hash + pid + nonce keep it unique.
        assert!(!name.is_empty());
    }

    /// A normal short path keeps a readable model prefix.
    #[test]
    fn socket_filename_keeps_model_prefix_when_short() {
        let dir = Path::new("/Users/u/.cocore/sockets");
        let name = socket_filename(dir, "mlx-community/Qwen2.5-7B-Instruct-4bit", 1, 2);
        assert!(name.contains("mlx-community_Qwen"));
    }
}
