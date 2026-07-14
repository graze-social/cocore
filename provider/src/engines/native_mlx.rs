//! Native in-process MLX inference engine (WS-ENGINE) — the long pole of
//! darkbloom parity. Feature-gated behind `native_mlx` (macOS + Apple silicon).
//!
//! WHY THIS EXISTS: the legacy path decrypts the prompt and hands it to an
//! owner-controlled Python subprocess (`engines/subprocess.rs`) that no
//! attestation covers — so the SE attestation vouches for the wrong process.
//! This engine processes the plaintext ENTIRELY inside the measured, signed
//! `cocore` binary via the `CoCoreMLX` dylib (no subprocess, no IPC), which is
//! the load-bearing confidential property (darkbloom's "in-process inference,
//! no observation surface"). Only with this does `inProcessBackend` become true
//! and the confidential tier become reachable.
//!
//! METAL / JIT (S1, see provider/spikes/SPIKE_RESULTS.md): MLX runs its standard
//! kernels from a PRECOMPILED `mlx.metallib` loaded at runtime — no runtime
//! shader JIT — so the agent is signed `allow-jit=false` and the metallib is
//! signed by the same team (library validation). The metallib is hashed at load
//! and pinned into the attestation (`metallibHash`).
//!
//! The MLX/Swift code lives in `libCoCoreMLX.dylib` (built + linked by build.rs).
//! It is loaded under ENFORCED library validation, so the owner cannot swap in a
//! different dylib, and its hash is pinned like the metallib's.

use super::{DeltaChannel, Engine, GenerateRequest, GenerateResponse};
// Only used by the macOS generate path below; on other targets the generate
// method is a stub, so gate the import to match and keep `-D warnings` happy.
#[cfg(target_os = "macos")]
use super::{model_prefills_think, ThinkTagSplitter};
use anyhow::Result;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod ffi {
    use std::os::raw::{c_char, c_int, c_void};
    extern "C" {
        pub fn cocore_mlx_load_model(
            model_dir: *const c_char,
            out_handle: *mut *mut c_void,
        ) -> c_int;
        pub fn cocore_mlx_generate(
            handle: *mut c_void,
            prompt: *const c_char,
            prompt_len: usize,
            // Inline images for vision models, as parallel arrays of raw
            // (already base64-decoded) image-file bytes. `image_count` is 0
            // for a text-only request, in which case the pointers may be
            // null. Swift reconstructs each `Data` → `CIImage` and feeds it
            // to the VLM as a `UserInput` image. The mime is recoverable from
            // the bytes themselves (CIImage auto-detects), so it isn't passed.
            image_ptrs: *const *const u8,
            image_lens: *const usize,
            image_count: usize,
            max_tokens: i32,
            on_delta: Option<extern "C" fn(*const c_char, usize, *mut c_void)>,
            ctx: *mut c_void,
            out_tokens_in: *mut i32,
            out_tokens_out: *mut i32,
        ) -> c_int;
        pub fn cocore_mlx_metallib_hash(handle: *mut c_void, out: *mut c_char, len: usize)
            -> c_int;
        /// Evict the Metal allocator's cached buffers (KV cache + scratch) so
        /// per-request generation state doesn't linger in the GPU pool between
        /// jobs. Best-effort scrub (ADR-0005 step 3): frees/evicts, does NOT
        /// guarantee GPU-page zeroing (Metal exposes no memset-on-free).
        pub fn cocore_mlx_clear_cache(handle: *mut c_void);
        pub fn cocore_mlx_release(handle: *mut c_void);
    }
}

/// In-process MLX engine. The Swift handle owns the loaded model + tokenizer;
/// generation is serialized (MLX is not reentrant on one model).
pub struct NativeMlxEngine {
    #[cfg(target_os = "macos")]
    handle: std::sync::Mutex<Handle>,
    metallib_hash: Option<String>,
    engine_lib_hash: Option<String>,
    #[allow(dead_code)]
    model_dir: PathBuf,
}

#[cfg(target_os = "macos")]
struct Handle(*mut std::os::raw::c_void);
// SAFETY: the raw pointer is an opaque Swift object; we never share it across
// threads concurrently — every use is behind the engine's Mutex.
#[cfg(target_os = "macos")]
unsafe impl Send for Handle {}

impl NativeMlxEngine {
    /// Load an MLX model from `model_dir` into THIS process via the CoCoreMLX
    /// dylib. The metallib hash is read back from MLX for attestation pinning.
    #[cfg(target_os = "macos")]
    pub fn load(model_dir: PathBuf, _metallib_path: Option<PathBuf>) -> Result<Self> {
        use std::ffi::CString;
        let c_dir = CString::new(model_dir.to_string_lossy().as_bytes())?;
        let mut handle: *mut std::os::raw::c_void = std::ptr::null_mut();
        let rc = unsafe { ffi::cocore_mlx_load_model(c_dir.as_ptr(), &mut handle) };
        if rc != 0 || handle.is_null() {
            anyhow::bail!(
                "cocore_mlx_load_model failed (rc={rc}) for {}",
                model_dir.display()
            );
        }
        // Read the metallib hash MLX actually loaded (None if it couldn't be
        // located — the confidential tier then won't qualify, which is correct).
        let mut buf = [0u8; 65];
        let hrc = unsafe {
            ffi::cocore_mlx_metallib_hash(
                handle,
                buf.as_mut_ptr() as *mut std::os::raw::c_char,
                buf.len(),
            )
        };
        let metallib_hash = if hrc == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            std::str::from_utf8(&buf[..end]).ok().map(|s| s.to_string())
        } else {
            None
        };
        Ok(Self {
            handle: std::sync::Mutex::new(Handle(handle)),
            metallib_hash,
            engine_lib_hash: dylib_hash(),
            model_dir,
        })
    }

    #[cfg(not(target_os = "macos"))]
    pub fn load(_model_dir: PathBuf, _metallib_path: Option<PathBuf>) -> Result<Self> {
        anyhow::bail!("native_mlx engine is macOS/Apple-silicon only")
    }
}

/// SHA-256 hex of the `libCoCoreMLX.dylib` actually loaded — located via
/// `dladdr` on one of its own exported symbols, then hashed. This pins the
/// dynamic engine library (which the main binary's cdHash does not cover) so a
/// confidential verifier can confirm it's a blessed build.
#[cfg(target_os = "macos")]
fn dylib_hash() -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let sym = ffi::cocore_mlx_load_model as *const std::os::raw::c_void;
    if unsafe { libc::dladdr(sym, &mut info) } == 0 || info.dli_fname.is_null() {
        return None;
    }
    let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }
        .to_str()
        .ok()?;
    let mut h = Sha256::new();
    let mut f = std::fs::File::open(path).ok()?;
    std::io::copy(&mut f, &mut h).ok()?;
    Some(hex::encode(h.finalize()))
}

#[cfg(target_os = "macos")]
impl Drop for NativeMlxEngine {
    fn drop(&mut self) {
        if let Ok(h) = self.handle.lock() {
            unsafe { ffi::cocore_mlx_release(h.0) };
        }
    }
}

/// Check whether the native MLX engine can serve this request. The native
/// FFI has no `tools` or `response_format` parameters, so requests using
/// those features must be rejected rather than silently served as
/// unconstrained plain text.
// The only callers — the `generate` impl and the unit tests — are
// `#[cfg(target_os = "macos")]`, so on non-macOS targets (CI runs clippy on
// Linux with `--all-features`) this is dead. It's genuinely used on macOS, so
// gate the allow rather than the function.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn check_native_capabilities(request: &GenerateRequest) -> Result<()> {
    if request.tools.is_some() {
        anyhow::bail!(
            "native-mlx engine does not support tool calling; \
             use the subprocess (vllm-mlx) engine with --enable-auto-tool-choice"
        );
    }
    if request.guided_json.is_some() {
        anyhow::bail!(
            "native-mlx engine does not support structured output (response_format); \
             use the subprocess (vllm-mlx) engine"
        );
    }
    Ok(())
}

impl Engine for NativeMlxEngine {
    fn name(&self) -> &'static str {
        "native-mlx"
    }

    fn ready(&self) -> bool {
        // Loaded + the metallib was located → ready to serve confidentially.
        // Without the metallib MLX can't run GPU kernels, so we are NOT ready.
        self.metallib_hash.is_some()
    }

    /// THE load-bearing confidential property: inference runs in this measured
    /// binary (the CoCoreMLX dylib, loaded under library validation), not an
    /// owner-controlled subprocess.
    fn in_process(&self) -> bool {
        true
    }

    fn metallib_hash(&self) -> Option<String> {
        self.metallib_hash.clone()
    }

    fn engine_lib_hash(&self) -> Option<String> {
        self.engine_lib_hash.clone()
    }

    #[cfg(target_os = "macos")]
    fn generate_stream(
        &self,
        request: &GenerateRequest,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        use super::ContentPart;
        use base64::Engine as _;
        use std::os::raw::{c_char, c_void};

        // The native MLX FFI has no tools or response_format parameters, so
        // tool-calling and structured-output requests cannot be served. Reject
        // explicitly rather than silently ignoring the constraints — a silent
        // drop would produce unconstrained plain text that violates the
        // requester's contract (and the receipt's schema/tool hashes).
        check_native_capabilities(request)?;

        // The agent flattens the request to a single user turn; the Swift side
        // applies the model's chat template. Text parts are concatenated;
        // image parts are decoded from base64 into raw file bytes and passed
        // alongside so a VLM model gets its images in-process.
        let prompt: String = request
            .messages
            .iter()
            .map(|m| m.content_text())
            .collect::<Vec<_>>()
            .join("\n");

        // Decode every image part to raw bytes. Kept in `image_bufs` (owned)
        // for the duration of the FFI call; the parallel pointer/len arrays
        // borrow from it. base64 decode failure aborts the request rather than
        // silently dropping an image the requester paid to have considered.
        let mut image_bufs: Vec<Vec<u8>> = Vec::new();
        for m in &request.messages {
            for part in &m.content {
                if let ContentPart::Image { data_b64, .. } = part {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(data_b64.as_bytes())
                        .map_err(|e| anyhow::anyhow!("invalid base64 image data: {e}"))?;
                    image_bufs.push(bytes);
                }
            }
        }
        let image_ptrs: Vec<*const u8> = image_bufs.iter().map(|b| b.as_ptr()).collect();
        let image_lens: Vec<usize> = image_bufs.iter().map(|b| b.len()).collect();

        // Trampoline: the C callback forwards each decoded delta to the Rust
        // closure. Decoded tokens may carry inline <think>...</think> markers,
        // so each delta is fed through a splitter that separates reasoning from
        // the answer. We stash any closure error and stop forwarding (MLX still
        // finishes, but we report the error and never fabricate output).
        struct Ctx<'a> {
            splitter: ThinkTagSplitter,
            on_delta: &'a mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
            err: Option<anyhow::Error>,
        }
        extern "C" fn trampoline(delta: *const c_char, len: usize, ctx: *mut c_void) {
            if ctx.is_null() || delta.is_null() {
                return;
            }
            let ctx = unsafe { &mut *(ctx as *mut Ctx) };
            if ctx.err.is_some() {
                return;
            }
            let bytes = unsafe { std::slice::from_raw_parts(delta as *const u8, len) };
            if let Ok(s) = std::str::from_utf8(bytes) {
                // Disjoint field borrows: splitter is `&mut self`, on_delta is
                // the sink.
                if let Err(e) = ctx.splitter.push(s, &mut *ctx.on_delta) {
                    ctx.err = Some(e);
                }
            }
        }

        let mut ctx = Ctx {
            splitter: if model_prefills_think(&request.model) {
                ThinkTagSplitter::new_in_reasoning()
            } else {
                ThinkTagSplitter::new()
            },
            on_delta,
            err: None,
        };
        let mut tin: i32 = 0;
        let mut tout: i32 = 0;
        let guard = self
            .handle
            .lock()
            .map_err(|_| anyhow::anyhow!("native mlx engine mutex poisoned"))?;
        let rc = unsafe {
            ffi::cocore_mlx_generate(
                guard.0,
                prompt.as_ptr() as *const c_char,
                prompt.len(),
                if image_ptrs.is_empty() {
                    std::ptr::null()
                } else {
                    image_ptrs.as_ptr()
                },
                if image_lens.is_empty() {
                    std::ptr::null()
                } else {
                    image_lens.as_ptr()
                },
                image_bufs.len(),
                request.max_tokens as i32,
                Some(trampoline),
                &mut ctx as *mut Ctx as *mut c_void,
                &mut tin,
                &mut tout,
            )
        };
        // Scrub the Metal cache before releasing the lock, on every path
        // (success or error): the just-served prompt's KV cache + scratch
        // shouldn't sit in the GPU allocator pool waiting to be reused. Best
        // effort — see the FFI doc.
        unsafe { ffi::cocore_mlx_clear_cache(guard.0) };
        drop(guard);
        // Flush any partial <think> marker buffered at end of stream.
        if ctx.err.is_none() {
            let Ctx {
                splitter, on_delta, ..
            } = &mut ctx;
            if let Err(e) = splitter.finish(&mut **on_delta) {
                ctx.err = Some(e);
            }
        }
        if let Some(e) = ctx.err {
            return Err(e);
        }
        if rc != 0 {
            anyhow::bail!("cocore_mlx_generate failed (rc={rc})");
        }
        Ok(GenerateResponse {
            text: String::new(), // streamed via the callback; caller accumulates
            tokens_in: tin.max(0) as u64,
            tokens_out: tout.max(0) as u64,
        })
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        let mut text = String::new();
        let resp = self.generate_stream(request, &mut |channel, delta| {
            if channel == DeltaChannel::Content {
                text.push_str(delta);
            }
            Ok(())
        })?;
        Ok(GenerateResponse {
            text,
            tokens_in: resp.tokens_in,
            tokens_out: resp.tokens_out,
        })
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::engines::{GenerateRequest, Message};

    /// End-to-end: load a real MLX model and stream tokens IN-PROCESS. Ignored
    /// by default (needs a model dir + the colocated metallib); run with:
    ///   COCORE_TEST_MODEL_DIR=/path/to/snapshot \
    ///     cargo test -p cocore-provider --features native_mlx -- --ignored native_mlx
    #[test]
    #[ignore]
    fn streams_tokens_in_process() {
        let dir = match std::env::var("COCORE_TEST_MODEL_DIR") {
            Ok(d) => PathBuf::from(d),
            Err(_) => return,
        };
        let eng = NativeMlxEngine::load(dir, None).expect("load model");
        assert!(eng.in_process());
        assert!(
            eng.ready(),
            "metallib must be located for the engine to be ready"
        );
        assert_eq!(eng.metallib_hash().map(|h| h.len()), Some(64));

        let req = GenerateRequest {
            model: "qwen".into(),
            messages: vec![Message::text(
                "user",
                "In one sentence, what is the Apple Secure Enclave?",
            )],
            max_tokens: 48,
            temperature: None,
            top_p: None,
            guided_json: None,
            tools: None,
            tool_choice: None,
        };
        let mut streamed = String::new();
        let resp = eng
            .generate_stream(&req, &mut |_channel, d| {
                streamed.push_str(d);
                Ok(())
            })
            .expect("generate");
        assert!(!streamed.is_empty(), "expected streamed tokens");
        assert!(
            resp.tokens_out > 0 && resp.tokens_in > 0,
            "expected real token counts"
        );
    }

    /// The native engine must reject requests that carry tool definitions
    /// rather than silently ignoring them and producing unconstrained text.
    #[test]
    fn rejects_tool_calling_requests() {
        let req = GenerateRequest {
            model: "test".into(),
            messages: vec![Message::text("user", "hello")],
            max_tokens: 16,
            temperature: None,
            top_p: None,
            guided_json: None,
            tools: Some(serde_json::json!([{"type":"function","function":{"name":"f"}}])),
            tool_choice: None,
        };
        let err = check_native_capabilities(&req).unwrap_err();
        assert!(
            err.to_string().contains("tool calling"),
            "error should mention tool calling, got: {err}"
        );
    }

    /// The native engine must reject requests that carry structured-output
    /// (response_format) constraints rather than silently ignoring them.
    #[test]
    fn rejects_structured_output_requests() {
        let req = GenerateRequest {
            model: "test".into(),
            messages: vec![Message::text("user", "hello")],
            max_tokens: 16,
            temperature: None,
            top_p: None,
            guided_json: Some(serde_json::json!({"name":"schema","schema":{}})),
            tools: None,
            tool_choice: None,
        };
        let err = check_native_capabilities(&req).unwrap_err();
        assert!(
            err.to_string().contains("structured output"),
            "error should mention structured output, got: {err}"
        );
    }

    /// Plain text requests (no tools, no guided_json) must pass the
    /// capability check without error.
    #[test]
    fn allows_plain_text_requests() {
        let req = GenerateRequest {
            model: "test".into(),
            messages: vec![Message::text("user", "hello")],
            max_tokens: 16,
            temperature: None,
            top_p: None,
            guided_json: None,
            tools: None,
            tool_choice: None,
        };
        check_native_capabilities(&req).expect("plain text should be allowed");
    }
}
