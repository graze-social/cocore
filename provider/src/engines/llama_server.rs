//! Managed `llama-server` inference engine (the primary Linux backend).
//!
//! This is the Linux counterpart to the macOS [`subprocess`](super::subprocess)
//! engine. It mirrors that engine's contract exactly: the agent **spawns and
//! supervises** one `llama-server` (llama.cpp's OpenAI-compatible HTTP server)
//! child per configured model, downloads the GGUF weights from HuggingFace,
//! health-checks the child, restarts it if it dies, and reaps it on exit. The
//! operator names models; the agent owns the whole lifecycle — it is NOT a
//! proxy to a server someone else runs (that is the unmanaged
//! [`openai`](super::openai) escape hatch).
//!
//! ## Why a managed subprocess (same rationale as the macOS path)
//!
//! - **Crash isolation**: a llama.cpp CUDA OOM / segfault kills only this
//!   child; the agent restarts it and keeps publishing receipts.
//! - **Lifecycle**: model swap = kill + respawn; no daemon restart.
//! - **Zero hand-management**: set `COCORE_INFERENCE_MODELS`, and the agent
//!   downloads + serves, exactly like the Mac.
//!
//! ## Transport: TCP loopback, not a Unix socket
//!
//! The macOS engine fronts vllm-mlx with a Unix domain socket (uvicorn binds
//! it) for access control + no port races. `llama-server`'s well-supported
//! path is TCP `--host/--port`, so we bind it to `127.0.0.1:<auto-port>` and
//! recover the access-control property with a **per-instance random
//! `--api-key`** (a local user without the key can't reach the engine). The
//! ephemeral port is OS-assigned (`bind :0`); a lost race on the rebind is
//! surfaced as a startup failure and retried by the recovery loop.
//!
//! ## What is reused vs. re-implemented
//!
//! Inference (request body, SSE parsing, `<think>` splitting, tool-call
//! channel, `Zeroizing` of bodies) is delegated to an inner
//! [`OpenAiEngine`](super::openai::OpenAiEngine) pointed at the spawned
//! server — llama-server speaks the identical OpenAI wire shape, so there is
//! nothing to duplicate. This module owns only the **process lifecycle**.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use anyhow::{anyhow, bail, Context, Result};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::openai::OpenAiEngine;
use super::{DeltaChannel, Engine, GenerateRequest, GenerateResponse};

/// No-progress stall window during startup (weight download + model load).
/// Matches the macOS engine's `READY_STALL_TIMEOUT`.
const READY_STALL_TIMEOUT: Duration = Duration::from_secs(300);
/// Absolute readiness backstop regardless of progress (slow link, huge GGUF).
const READY_HARD_CAP: Duration = Duration::from_secs(6 * 60 * 60);
/// SIGTERM→SIGKILL grace on teardown. Matches the macOS engine.
const TERMINATE_GRACE: Duration = Duration::from_secs(5);
/// Max retained stdout/stderr lines for a startup-failure diagnostic. Child
/// output is NEVER routed to tracing (llama.cpp logs prompts); this ring is
/// consulted only when the child dies during startup.
const RING_CAP: usize = 64;

/// Launch configuration for `llama-server`, assembled from the environment.
/// `None` from [`from_env`](LlamaServerConfig::from_env) means the Linux
/// managed path is not selected (no `COCORE_LLAMA_SERVER_BIN`), so
/// `build_engines` falls through to the next backend.
#[derive(Debug, Clone)]
pub struct LlamaServerConfig {
    /// Absolute path to the `llama-server` binary (`COCORE_LLAMA_SERVER_BIN`).
    pub server_bin: PathBuf,
    /// `-ngl` / `--n-gpu-layers` (`COCORE_LLAMA_NGL`, default 999 = offload
    /// every layer to the GPU(s); llama.cpp clamps to the model's real count).
    pub n_gpu_layers: i32,
    /// Enable `--jinja` so the model's chat template drives OpenAI-compatible
    /// tool/function calling (`COCORE_ENABLE_TOOL_CALLS`, shared with the
    /// macOS path). Advertised only after the startup canary proves it.
    pub enable_tool_calls: bool,
    /// Raw passthrough flags (`COCORE_LLAMA_EXTRA_ARGS`), split on ASCII
    /// whitespace — no shell evaluation. This is where multi-GPU knobs go
    /// (`--tensor-split 1,1`, `--main-gpu`, `--split-mode`, `--ctx-size`, …).
    pub extra_args: Vec<String>,
}

impl LlamaServerConfig {
    pub fn from_env() -> Option<Self> {
        let server_bin = nonempty_env("COCORE_LLAMA_SERVER_BIN").map(PathBuf::from)?;
        let n_gpu_layers = nonempty_env("COCORE_LLAMA_NGL")
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(999);
        let enable_tool_calls = std::env::var("COCORE_ENABLE_TOOL_CALLS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let extra_args = nonempty_env("COCORE_LLAMA_EXTRA_ARGS")
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        Some(Self {
            server_bin,
            n_gpu_layers,
            enable_tool_calls,
            extra_args,
        })
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub struct LlamaCppEngine {
    /// The cocore model id; also the `--alias` we hand llama-server so its
    /// `/v1/models` reports the id the requester named.
    model_id: String,
    config: LlamaServerConfig,
    /// The live child. `None` until `start()`, `None` again after teardown.
    /// Locks are poison-tolerant everywhere (a panic-while-holding must never
    /// brick restart or, worse, abort during a Drop unwind and orphan a GPU
    /// process).
    child: Mutex<Option<Child>>,
    /// HTTP client bound to the spawned server's loopback URL + api-key. Does
    /// all inference; rebuilt on each (re)start since the port changes.
    inner: Mutex<Option<Arc<OpenAiEngine>>>,
    /// Set true only after the startup tool-call canary proves structured
    /// tool_calls come back.
    verified_tool_calls: Mutex<bool>,
}

impl LlamaCppEngine {
    /// Construct an engine bound to `model_id`. Does NOT spawn — call
    /// [`start`](Self::start). No I/O.
    pub fn new(model_id: impl Into<String>, config: LlamaServerConfig) -> Self {
        Self {
            model_id: model_id.into(),
            config,
            child: Mutex::new(None),
            inner: Mutex::new(None),
            verified_tool_calls: Mutex::new(false),
        }
    }

    /// Spawn `llama-server` and block until it answers an HTTP readiness
    /// probe. Idempotent: a second call while already running returns `Ok`.
    ///
    /// Readiness mirrors the macOS engine: stall-based, not a fixed budget —
    /// a cold GGUF download can be tens of GB. We give up only when there has
    /// been no readiness AND no child output for [`READY_STALL_TIMEOUT`], with
    /// [`READY_HARD_CAP`] as an absolute backstop.
    pub fn start(&self) -> Result<()> {
        let mut guard = lock(&self.child);
        if guard.is_some() {
            return Ok(()); // already started
        }

        if !self.config.server_bin.exists() {
            bail!(
                "llama-server binary not found at {}",
                self.config.server_bin.display()
            );
        }

        let port = allocate_port().context("allocating a loopback port for llama-server")?;
        let api_key = random_api_key();
        let base_url = format!("http://127.0.0.1:{port}");

        let mut cmd = Command::new(&self.config.server_bin);
        cmd.arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--api-key")
            .arg(&api_key)
            .arg("--alias")
            .arg(&self.model_id)
            .arg("-ngl")
            .arg(self.config.n_gpu_layers.to_string());
        for arg in model_source_args(&self.model_id) {
            cmd.arg(arg);
        }
        if self.config.enable_tool_calls {
            cmd.arg("--jinja");
        }
        cmd.args(&self.config.extra_args);
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // HF token auth for the `-hf` GGUF download (same helper the macOS
        // engine uses; the Xet flags it also sets are inert for llama.cpp).
        crate::engines::subprocess::apply_hf_download_env(&mut cmd);

        // Kernel-enforced parent-death: if the agent dies however it dies
        // (SIGKILL, crash, std::process::exit), the kernel sends this child
        // SIGTERM. Strictly better than the macOS Python poll. Linux-only
        // (PR_SET_PDEATHSIG has no portable analogue).
        #[cfg(target_os = "linux")]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGTERM as libc::c_ulong,
                    0,
                    0,
                    0,
                );
                Ok(())
            });
        }

        let mut child = cmd.spawn().context("spawning llama-server")?;

        // Drain child output into a ring buffer for crash diagnostics only —
        // never to tracing (it can contain prompt content).
        let ring: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
        if let Some(out) = child.stdout.take() {
            spawn_drain(out, Arc::clone(&ring));
        }
        if let Some(err) = child.stderr.take() {
            spawn_drain(err, Arc::clone(&ring));
        }

        // The inner engine does no I/O at construction; its `ready()` (GET
        // /v1/models) is our readiness probe.
        let inner = Arc::new(
            OpenAiEngine::new(self.model_id.clone(), &base_url, Some(api_key))
                .context("building HTTP client for the spawned llama-server")?,
        );

        let started = Instant::now();
        let mut last_progress = started;
        let mut last_lines = ring_len(&ring);
        loop {
            if let Some(status) = child.try_wait().context("polling llama-server")? {
                bail!(
                    "llama-server exited during startup ({status}); recent output:\n{}",
                    ring_dump(&ring)
                );
            }
            if inner.ready() {
                break;
            }
            // Any new child output line counts as progress (download/load
            // chatter), the llama.cpp analogue of the macOS HF-cache byte +
            // Xet-mtime progress signals.
            let lines = ring_len(&ring);
            if lines != last_lines {
                last_lines = lines;
                last_progress = Instant::now();
            }
            if last_progress.elapsed() > READY_STALL_TIMEOUT {
                let _ = child.kill();
                bail!(
                    "llama-server made no progress for {}s (download stalled or model load wedged); recent output:\n{}",
                    READY_STALL_TIMEOUT.as_secs(),
                    ring_dump(&ring)
                );
            }
            if started.elapsed() > READY_HARD_CAP {
                let _ = child.kill();
                bail!(
                    "llama-server did not become ready within the {}h hard cap",
                    READY_HARD_CAP.as_secs() / 3600
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        // Tool-call canary — only advertise tool support the backend proves.
        let verified = if self.config.enable_tool_calls {
            match inner.probe_tool_calls() {
                Ok(true) => {
                    tracing::info!(model = %self.model_id, "llama-server tool-call canary passed");
                    true
                }
                Ok(false) => {
                    tracing::warn!(model = %self.model_id, "llama-server tool-call canary returned no structured tool_calls; not advertising tool support");
                    false
                }
                Err(e) => {
                    tracing::warn!(model = %self.model_id, error = %e, "llama-server tool-call canary failed; not advertising tool support");
                    false
                }
            }
        } else {
            false
        };

        *lock(&self.verified_tool_calls) = verified;
        *lock(&self.inner) = Some(inner);
        *guard = Some(child);
        tracing::info!(model = %self.model_id, port, "llama-server engine ready");
        Ok(())
    }

    /// Whether the startup tool-call canary proved structured tool_calls.
    pub fn verified_tool_calls(&self) -> bool {
        *lock(&self.verified_tool_calls)
    }

    /// True iff the child process is alive. Mirrors the macOS `is_alive`:
    /// best-effort, does not round-trip a request. Flips to `false` when
    /// llama-server dies, which is what lets the serve loop's health watchdog
    /// notice and restart (and keeps a dead model out of `supportedModels`).
    fn is_alive(&self) -> bool {
        let mut guard = lock(&self.child);
        match guard.as_mut() {
            None => false,
            Some(child) => matches!(child.try_wait(), Ok(None)),
        }
    }

    /// Cheaply clone the inner HTTP engine out from under a brief lock, so the
    /// (potentially long) inference call doesn't hold the registry's lock and
    /// block a concurrent restart/terminate.
    fn current_inner(&self) -> Result<Arc<OpenAiEngine>> {
        lock(&self.inner)
            .clone()
            .ok_or_else(|| anyhow!("llama-server engine is not started"))
    }

    /// SIGTERM → grace → SIGKILL, then reap and clear the inner engine. Shared
    /// by [`Engine::terminate`] and `Drop`. `take()` makes a second call a
    /// no-op, so Drop after an explicit terminate is safe.
    fn terminate_child(&self) {
        let mut guard = lock(&self.child);
        if let Some(mut child) = guard.take() {
            tracing::info!(model = %self.model_id, "terminating llama-server");
            #[cfg(unix)]
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
            let deadline = Instant::now() + TERMINATE_GRACE;
            loop {
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill(); // SIGKILL
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = child.wait(); // reap
        }
        *lock(&self.inner) = None;
    }
}

impl Engine for LlamaCppEngine {
    fn name(&self) -> &'static str {
        "llama-server"
    }

    fn ready(&self) -> bool {
        self.is_alive()
    }

    fn restart(&self) -> Result<()> {
        // Reap the dead child + drop the stale inner client, then respawn
        // (which allocates a fresh port). Mirrors the macOS engine.
        {
            let mut guard = lock(&self.child);
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        *lock(&self.inner) = None;
        tracing::info!(model = %self.model_id, "respawning dead llama-server");
        self.start()
    }

    fn terminate(&self) {
        self.terminate_child();
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        self.current_inner()?.generate_once(request)
    }

    fn generate_stream(
        &self,
        request: &GenerateRequest,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        self.current_inner()?.generate_stream(request, on_delta)
    }

    // in_process / metallib_hash / engine_lib_hash keep the trait defaults
    // (false / None): a subprocess llama-server is best-effort, not the
    // confidential in-process path.
}

impl Drop for LlamaCppEngine {
    fn drop(&mut self) {
        self.terminate_child();
    }
}

/// Poison-tolerant lock: recover the guard rather than propagating a panic.
/// Critical in `terminate_child`/`Drop` — an `unwrap()` on a poisoned mutex
/// during a Drop unwind is a panic-while-panicking → `abort()`, which would
/// kill the agent AND skip the SIGTERM, orphaning the GPU process.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Map a cocore model id to llama-server's model-source flags. An id that
/// looks like a HuggingFace repo (`org/name[:quant]`, no leading `/`) is
/// downloaded as GGUF via `-hf`; an absolute path is loaded locally via `-m`.
fn model_source_args(model_id: &str) -> Vec<String> {
    if model_id.starts_with('/') {
        vec!["-m".to_string(), model_id.to_string()]
    } else {
        vec!["-hf".to_string(), model_id.to_string()]
    }
}

/// Ask the OS for a free loopback TCP port by binding `:0` and reading the
/// assignment back. There is a small window between the close here and
/// llama-server's bind; a lost race surfaces as a startup failure that the
/// recovery loop retries.
fn allocate_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

/// 32 random bytes, hex-encoded — the per-instance `--api-key`. Uniqueness +
/// unpredictability come from the OS RNG; a local user without the key can't
/// reach the engine.
fn random_api_key() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

fn spawn_drain<R: std::io::Read + Send + 'static>(stream: R, ring: Arc<Mutex<VecDeque<String>>>) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        let r = std::io::BufReader::new(stream);
        for line in r.lines().map_while(|l| l.ok()) {
            let mut buf = lock(&ring);
            if buf.len() >= RING_CAP {
                buf.pop_front();
            }
            buf.push_back(line);
        }
    });
}

fn ring_len(ring: &Arc<Mutex<VecDeque<String>>>) -> usize {
    lock(ring).len()
}

fn ring_dump(ring: &Arc<Mutex<VecDeque<String>>>) -> String {
    let buf = lock(ring);
    if buf.is_empty() {
        "  (no output captured)".to_string()
    } else {
        buf.iter()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_is_none_without_server_bin() {
        // Snapshot + clear so the test is independent of the ambient env.
        let prev = std::env::var("COCORE_LLAMA_SERVER_BIN").ok();
        std::env::remove_var("COCORE_LLAMA_SERVER_BIN");
        assert!(LlamaServerConfig::from_env().is_none());
        if let Some(v) = prev {
            std::env::set_var("COCORE_LLAMA_SERVER_BIN", v);
        }
    }

    #[test]
    fn from_env_parses_when_bin_set() {
        let prev_bin = std::env::var("COCORE_LLAMA_SERVER_BIN").ok();
        let prev_ngl = std::env::var("COCORE_LLAMA_NGL").ok();
        std::env::set_var("COCORE_LLAMA_SERVER_BIN", "/usr/bin/llama-server");
        std::env::set_var("COCORE_LLAMA_NGL", "20");
        let cfg = LlamaServerConfig::from_env().expect("config present");
        assert_eq!(cfg.server_bin, PathBuf::from("/usr/bin/llama-server"));
        assert_eq!(cfg.n_gpu_layers, 20);
        // restore
        match prev_bin {
            Some(v) => std::env::set_var("COCORE_LLAMA_SERVER_BIN", v),
            None => std::env::remove_var("COCORE_LLAMA_SERVER_BIN"),
        }
        match prev_ngl {
            Some(v) => std::env::set_var("COCORE_LLAMA_NGL", v),
            None => std::env::remove_var("COCORE_LLAMA_NGL"),
        }
    }

    #[test]
    fn ngl_defaults_to_all_layers() {
        let prev_bin = std::env::var("COCORE_LLAMA_SERVER_BIN").ok();
        let prev_ngl = std::env::var("COCORE_LLAMA_NGL").ok();
        std::env::set_var("COCORE_LLAMA_SERVER_BIN", "/usr/bin/llama-server");
        std::env::remove_var("COCORE_LLAMA_NGL");
        let cfg = LlamaServerConfig::from_env().expect("config present");
        assert_eq!(cfg.n_gpu_layers, 999);
        match prev_bin {
            Some(v) => std::env::set_var("COCORE_LLAMA_SERVER_BIN", v),
            None => std::env::remove_var("COCORE_LLAMA_SERVER_BIN"),
        }
        if let Some(v) = prev_ngl {
            std::env::set_var("COCORE_LLAMA_NGL", v);
        }
    }

    #[test]
    fn model_source_hf_for_repo_id() {
        assert_eq!(
            model_source_args("bartowski/Qwen2.5-7B-Instruct-GGUF"),
            vec![
                "-hf".to_string(),
                "bartowski/Qwen2.5-7B-Instruct-GGUF".to_string()
            ]
        );
    }

    #[test]
    fn model_source_local_for_absolute_path() {
        assert_eq!(
            model_source_args("/models/qwen.gguf"),
            vec!["-m".to_string(), "/models/qwen.gguf".to_string()]
        );
    }

    #[test]
    fn allocate_port_returns_usable_port() {
        let p = allocate_port().expect("port");
        assert!(p > 0);
    }

    #[test]
    fn api_key_is_64_hex_chars() {
        let k = random_api_key();
        assert_eq!(k.len(), 64);
        assert!(k.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_before_start_errors_cleanly() {
        let cfg = LlamaServerConfig {
            server_bin: PathBuf::from("/nonexistent/llama-server"),
            n_gpu_layers: 999,
            enable_tool_calls: false,
            extra_args: vec![],
        };
        let engine = LlamaCppEngine::new("test/model-GGUF", cfg);
        assert!(!engine.ready());
        let req = GenerateRequest {
            model: "test/model-GGUF".into(),
            messages: vec![],
            max_tokens: 16,
            temperature: None,
            top_p: None,
            guided_json: None,
            tools: None,
            tool_choice: None,
        };
        assert!(engine.generate_once(&req).is_err());
    }

    #[test]
    fn start_fails_fast_when_binary_missing() {
        let cfg = LlamaServerConfig {
            server_bin: PathBuf::from("/nonexistent/llama-server"),
            n_gpu_layers: 999,
            enable_tool_calls: false,
            extra_args: vec![],
        };
        let engine = LlamaCppEngine::new("test/model-GGUF", cfg);
        let err = engine.start().unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
