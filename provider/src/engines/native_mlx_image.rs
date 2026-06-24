//! Native in-process MLX DIFFUSION engine (Phase 10) — the image-generation
//! counterpart of [`super::native_mlx::NativeMlxEngine`]. Feature-gated behind
//! `native_mlx` (macOS + Apple silicon).
//!
//! Same load-bearing confidential property as the LLM native engine: the
//! decrypted prompt is processed ENTIRELY inside the measured, signed `cocore`
//! binary via the `CoCoreMLX` dylib (no subprocess, no IPC), so the SE
//! attestation covers it and `inProcessBackend` stays true. The metallib is
//! hashed at load and pinned into the attestation.
//!
//! Wire-compatible drop-in for [`super::image_subprocess::ImageSubprocessEngine`]:
//! it emits the finished image via [`DeltaChannel::Image`] exactly the same way,
//! so the advisor's images-v1 receipt path is unchanged — only the backend
//! moves in-process.

use super::{encode_image_delta, DeltaChannel, Engine, GenerateRequest, GenerateResponse};
use crate::pricing;
use anyhow::Result;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod ffi {
    use std::os::raw::{c_char, c_int, c_void};
    extern "C" {
        pub fn cocore_mlx_load_diffusion_model(
            model_id: *const c_char,
            model_dir: *const c_char,
            out_handle: *mut *mut c_void,
        ) -> c_int;
        #[allow(clippy::too_many_arguments)]
        pub fn cocore_mlx_generate_image(
            handle: *mut c_void,
            prompt: *const c_char,
            prompt_len: usize,
            image_ptrs: *const *const u8,
            image_lens: *const usize,
            image_count: usize,
            steps: i32,
            seed: i32,
            out_png: *mut *mut u8,
            out_png_len: *mut usize,
            out_tokens_in: *mut i32,
            out_tokens_out: *mut i32,
        ) -> c_int;
        pub fn cocore_mlx_free_buffer(buf: *mut u8);
        pub fn cocore_mlx_diffusion_metallib_hash(
            handle: *mut c_void,
            out: *mut c_char,
            len: usize,
        ) -> c_int;
        pub fn cocore_mlx_release_diffusion(handle: *mut c_void);
    }
}

/// In-process MLX diffusion engine. The Swift handle owns the loaded pipeline;
/// generation is serialized (MLX is not reentrant on one model).
pub struct NativeMlxImageEngine {
    #[cfg(target_os = "macos")]
    handle: std::sync::Mutex<Handle>,
    metallib_hash: Option<String>,
    engine_lib_hash: Option<String>,
    #[allow(dead_code)]
    model_dir: PathBuf,
}

#[cfg(target_os = "macos")]
struct Handle(*mut std::os::raw::c_void);
// SAFETY: opaque Swift object, only ever used behind the engine's Mutex.
#[cfg(target_os = "macos")]
unsafe impl Send for Handle {}

impl NativeMlxImageEngine {
    /// Load an MLX diffusion model into THIS process via the CoCoreMLX dylib.
    /// `model_id` selects the in-process preset (SDXL-Turbo / SD-2.1);
    /// `model_dir` is the weight-cache base (may be empty). The metallib hash
    /// is read back for attestation pinning.
    #[cfg(target_os = "macos")]
    pub fn load(model_id: &str, model_dir: PathBuf) -> Result<Self> {
        use std::ffi::CString;
        let c_id = CString::new(model_id.as_bytes())?;
        let c_dir = CString::new(model_dir.to_string_lossy().as_bytes())?;
        let mut handle: *mut std::os::raw::c_void = std::ptr::null_mut();
        let rc = unsafe {
            ffi::cocore_mlx_load_diffusion_model(c_id.as_ptr(), c_dir.as_ptr(), &mut handle)
        };
        if rc != 0 || handle.is_null() {
            anyhow::bail!(
                "cocore_mlx_load_diffusion_model failed (rc={rc}) for model {model_id}"
            );
        }
        let mut buf = [0u8; 65];
        let hrc = unsafe {
            ffi::cocore_mlx_diffusion_metallib_hash(
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
    pub fn load(_model_id: &str, _model_dir: PathBuf) -> Result<Self> {
        anyhow::bail!("native_mlx image engine is macOS/Apple-silicon only")
    }
}

/// SHA-256 hex of `libCoCoreMLX.dylib` actually loaded — located via `dladdr`
/// on one of its diffusion symbols, then hashed. Same pinning the LLM native
/// engine does; the dylib is shared, so the hash matches.
#[cfg(target_os = "macos")]
fn dylib_hash() -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let sym = ffi::cocore_mlx_load_diffusion_model as *const std::os::raw::c_void;
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
impl Drop for NativeMlxImageEngine {
    fn drop(&mut self) {
        if let Ok(h) = self.handle.lock() {
            unsafe { ffi::cocore_mlx_release_diffusion(h.0) };
        }
    }
}

impl Engine for NativeMlxImageEngine {
    fn name(&self) -> &'static str {
        "native-mlx-image"
    }

    fn ready(&self) -> bool {
        // Loaded + the metallib located → ready to serve confidentially.
        self.metallib_hash.is_some()
    }

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
        use std::os::raw::c_char;

        // Flatten text parts for the prompt; decode image parts to raw bytes
        // for img2img (empty for text-to-image).
        let prompt: String = request
            .messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter_map(|p| match p {
                ContentPart::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
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

        let mut out_png: *mut u8 = std::ptr::null_mut();
        let mut out_png_len: usize = 0;
        let mut tin: i32 = 0;
        let mut tout: i32 = 0;
        // `max_tokens` is reinterpreted opaquely as the step count (same as the
        // subprocess image engine) until a lexicon step field lands.
        let steps = request.max_tokens.clamp(1, 200) as i32;
        let guard = self
            .handle
            .lock()
            .map_err(|_| anyhow::anyhow!("native mlx image engine mutex poisoned"))?;
        let rc = unsafe {
            ffi::cocore_mlx_generate_image(
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
                steps,
                // Deterministic-ish default seed from the prompt length; a
                // lexicon seed field can override this later.
                (prompt.len() as i32).max(1),
                &mut out_png,
                &mut out_png_len,
                &mut tin,
                &mut tout,
            )
        };
        drop(guard);
        if rc != 0 || out_png.is_null() {
            anyhow::bail!("cocore_mlx_generate_image failed (rc={rc})");
        }
        // Copy the PNG out of the Swift-owned buffer, then free it.
        let png = unsafe { std::slice::from_raw_parts(out_png, out_png_len).to_vec() };
        unsafe { ffi::cocore_mlx_free_buffer(out_png) };

        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&png);
        on_delta(DeltaChannel::Image, &encode_image_delta("image/png", &data_b64))?;
        Ok(GenerateResponse {
            text: String::new(),
            tokens_in: if tin > 0 {
                tin as u64
            } else {
                pricing::estimate_tokens(prompt.as_bytes())
            },
            tokens_out: if tout > 0 {
                tout as u64
            } else {
                pricing::estimate_tokens(&png)
            },
        })
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        // Run a generation and drop the image (callers use the streaming path).
        let mut tokens = (0u64, 0u64);
        let resp = self.generate_stream(request, &mut |_ch, _d| Ok(()))?;
        tokens.0 = resp.tokens_in;
        tokens.1 = resp.tokens_out;
        Ok(GenerateResponse {
            text: String::new(),
            tokens_in: tokens.0,
            tokens_out: tokens.1,
        })
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// End-to-end: load a real MLX diffusion model and generate IN-PROCESS.
    /// Ignored by default (needs a snapshot dir + the colocated metallib + a
    /// diffusion-linked confidential build). Run with:
    ///   COCORE_TEST_IMAGE_MODEL_DIR=/path/to/flux \
    ///     cargo test -p cocore-provider --features native_mlx -- --ignored native_mlx_image
    #[test]
    #[ignore]
    fn generates_image_in_process() {
        let dir = match std::env::var("COCORE_TEST_IMAGE_MODEL_DIR") {
            Ok(d) => PathBuf::from(d),
            Err(_) => return,
        };
        let eng = NativeMlxImageEngine::load("stabilityai/sdxl-turbo", dir)
            .expect("load diffusion model");
        assert!(eng.in_process());
        assert!(eng.ready(), "metallib must be located");

        let req = GenerateRequest {
            model: "flux".into(),
            messages: vec![crate::engines::Message::text("user", "a red apple on a table")],
            max_tokens: 4,
            temperature: None,
            top_p: None,
        };
        let mut got_image = false;
        eng.generate_stream(&req, &mut |ch, d| {
            if ch == DeltaChannel::Image {
                let (mime, _data) = crate::engines::decode_image_delta(d).unwrap();
                assert_eq!(mime, "image/png");
                got_image = true;
            }
            Ok(())
        })
        .expect("generate");
        assert!(got_image, "expected an image delta");
    }
}
