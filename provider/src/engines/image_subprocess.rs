//! Out-of-process MLX **image-generation** engine (Phase 8).
//!
//! Sibling of [`super::subprocess::SubprocessEngine`] (chat/VLM). The
//! lifecycle is the same shape — spawn a Python child bound to a
//! per-instance Unix domain socket, probe it for readiness, reap it on
//! Drop / explicit terminate, respawn on death — but the wire protocol is
//! cocore-owned and minimal (`POST /generate` returning PNG bytes), NOT
//! the OpenAI chat-completions SSE stream. Diffusion is request/response:
//! there is no token stream, so [`Engine::generate_stream`] emits the
//! finished image(s) as a single [`DeltaChannel::Image`] delta at the end.
//!
//! Kept deliberately separate from `subprocess.rs` rather than bolted onto
//! its SSE path: the two engines share a spawn/probe SHAPE but nothing
//! about how a request is serialized or a response parsed, and tangling
//! diffusion into the chat path would make both harder to reason about.

use anyhow::{anyhow, bail, Context, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::engines::{encode_image_delta, DeltaChannel, Engine, GenerateRequest, GenerateResponse};
use crate::pricing;

/// Embedded image-server wrapper, written to disk at first spawn (same
/// single-static-binary story as the chat wrapper).
const IMAGE_WRAPPER_SCRIPT: &str = include_str!("../../python/cocore_image_server.py");

/// Readiness wait: diffusion weights (FLUX is multi-GB) download + mmap on
/// first run, so this is generous. The probe is `GET /health`.
const READY_STALL_TIMEOUT: Duration = Duration::from_secs(600);
const READY_HARD_CAP: Duration = Duration::from_secs(6 * 60 * 60);
/// A single image can take many seconds (steps × model size); be generous.
const HTTP_TIMEOUT: Duration = Duration::from_secs(600);

fn state_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("no $HOME"))?;
    Ok(home.join(".cocore"))
}

pub struct ImageSubprocessEngine {
    model_id: String,
    venv_python: PathBuf,
    socket_path: PathBuf,
    child: Mutex<Option<Child>>,
}

impl ImageSubprocessEngine {
    /// Bind an engine to `model_id`. Does not spawn — call [`start`](Self::start).
    pub fn new(model_id: impl Into<String>, venv_python: PathBuf) -> Result<Self> {
        let model_id = model_id.into();
        let sockets_dir = state_dir()?.join("sockets");
        std::fs::create_dir_all(&sockets_dir)
            .with_context(|| format!("creating sockets dir {}", sockets_dir.display()))?;
        // Per-instance socket path (see subprocess.rs for the uniqueness
        // rationale): `imgengine-<model>-<pid>-<nonce>.sock`.
        let sanitized: String = model_id.replace('/', "_").chars().take(36).collect();
        let pid = std::process::id();
        let nonce: u32 = rand::random();
        let socket_path = sockets_dir.join(format!("imgengine-{sanitized}-{pid}-{nonce:08x}.sock"));
        Ok(Self {
            model_id,
            venv_python,
            socket_path,
            child: Mutex::new(None),
        })
    }

    fn ensure_wrapper_on_disk() -> Result<PathBuf> {
        let path = state_dir()?.join("cocore_image_server.py");
        let needs_write = !matches!(
            std::fs::read_to_string(&path),
            Ok(existing) if existing == IMAGE_WRAPPER_SCRIPT
        );
        if needs_write {
            std::fs::write(&path, IMAGE_WRAPPER_SCRIPT)
                .with_context(|| format!("writing image wrapper to {}", path.display()))?;
        }
        Ok(path)
    }

    /// Spawn the Python child and block until `GET /health` returns 2xx.
    pub fn start(&self) -> Result<()> {
        let mut guard = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_some() {
            return Ok(());
        }
        let _ = std::fs::remove_file(&self.socket_path);
        let wrapper = Self::ensure_wrapper_on_disk().context("writing embedded image wrapper")?;
        if !self.venv_python.exists() {
            bail!(
                "venv python missing at {}. Run the provider bootstrap to provision the venv.",
                self.venv_python.display()
            );
        }

        tracing::info!(
            model = %self.model_id,
            socket = %self.socket_path.display(),
            "spawning image-generation subprocess"
        );

        let mut cmd = Command::new(&self.venv_python);
        cmd.arg(&wrapper)
            .arg("--model")
            .arg(&self.model_id)
            .arg("--uds")
            .arg(&self.socket_path)
            .arg("--parent-pid")
            .arg(std::process::id().to_string())
            // Same content-safety posture as the chat engine: never pipe
            // child output into tracing (diffusion logs prompts at INFO).
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawning image wrapper for {}", self.model_id))?;

        let started = Instant::now();
        let mut last_progress = started;
        let mut last_bytes = hf_cache_size(&self.model_id);
        loop {
            if self.socket_path.exists() && self.probe_ready() {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                bail!(
                    "image subprocess for {} exited during startup with {status}",
                    self.model_id
                );
            }
            let now = Instant::now();
            let bytes = hf_cache_size(&self.model_id);
            if bytes > last_bytes {
                last_bytes = bytes;
                last_progress = now;
            }
            if now.duration_since(last_progress) > READY_STALL_TIMEOUT {
                let _ = child.kill();
                bail!(
                    "image subprocess for {} made no progress for {}s and never became ready",
                    self.model_id,
                    READY_STALL_TIMEOUT.as_secs()
                );
            }
            if now.duration_since(started) > READY_HARD_CAP {
                let _ = child.kill();
                bail!(
                    "image subprocess for {} did not become ready within the hard cap",
                    self.model_id
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        tracing::info!(model = %self.model_id, "image subprocess ready");
        *guard = Some(child);
        Ok(())
    }

    fn probe_ready(&self) -> bool {
        let Ok(mut stream) = UnixStream::connect(&self.socket_path) else {
            return false;
        };
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let req = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        if stream.write_all(req).is_err() {
            return false;
        }
        let _ = stream.flush();
        let mut buf = [0u8; 64];
        let n = match stream.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => return false,
        };
        let s = std::str::from_utf8(&buf[..n]).unwrap_or("");
        s.starts_with("HTTP/1.1 2") || s.starts_with("HTTP/1.0 2")
    }

    fn is_alive(&self) -> bool {
        let mut guard = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(child) = guard.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => self.socket_path.exists(),
            Err(_) => false,
        }
    }

    /// Hand-rolled HTTP/1.1 POST against the UDS (same approach as the chat
    /// engine — avoids pulling in an async HTTP client for one route).
    fn http_post_uds(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!("connecting to image socket {}", self.socket_path.display())
        })?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.set_read_timeout(Some(HTTP_TIMEOUT))?;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .context("writing request head")?;
        stream.write_all(body).context("writing request body")?;
        stream.flush().ok();

        let mut all = Vec::new();
        stream.read_to_end(&mut all).context("reading response")?;
        let hdr_end = all
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow!("no header/body separator in response"))?;
        let headers = &all[..hdr_end];
        let body_bytes = &all[hdr_end + 4..];
        let status_line = std::str::from_utf8(headers)
            .ok()
            .and_then(|s| s.lines().next())
            .ok_or_else(|| anyhow!("non-UTF8 response headers"))?;
        let status = status_line
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow!("could not parse status from {status_line:?}"))?;
        if !(200..300).contains(&status) {
            // Never log the body — an error response may echo the prompt.
            bail!(
                "image engine returned HTTP {status} ({} body bytes elided)",
                body_bytes.len()
            );
        }
        Ok(body_bytes.to_vec())
    }

    /// Serialize a `GenerateRequest` into the `/generate` body: the prompt
    /// text (flattened from the messages) plus any reference images for
    /// img2img, and `max_tokens` reinterpreted opaquely as the step count
    /// until lexicon step pricing lands.
    fn build_generate_body(request: &GenerateRequest) -> serde_json::Value {
        use crate::engines::ContentPart;
        // Prompt = concatenated text parts across turns; reference images =
        // every image part (img2img). For pure t2i there are no images.
        let mut prompt = String::new();
        let mut images: Vec<serde_json::Value> = Vec::new();
        for m in &request.messages {
            for part in &m.content {
                match part {
                    ContentPart::Text(t) => {
                        if !prompt.is_empty() {
                            prompt.push('\n');
                        }
                        prompt.push_str(t);
                    }
                    ContentPart::Image { mime, data_b64 } => {
                        images.push(serde_json::json!({ "mime": mime, "data": data_b64 }));
                    }
                }
            }
        }
        let mut body = serde_json::json!({
            "prompt": prompt,
            "steps": request.max_tokens,
        });
        if !images.is_empty() {
            body["images"] = serde_json::Value::Array(images);
        }
        body
    }

    /// Parse the `/generate` response into `(mime, data_b64)` images.
    fn parse_generate_response(bytes: &[u8]) -> Result<Vec<(String, String)>> {
        let v: serde_json::Value =
            serde_json::from_slice(bytes).context("image response not valid JSON")?;
        let arr = v
            .get("images")
            .and_then(|x| x.as_array())
            .ok_or_else(|| anyhow!("image response missing images array"))?;
        let mut out = Vec::with_capacity(arr.len());
        for (i, im) in arr.iter().enumerate() {
            let mime = im
                .get("mime")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("image {i} missing mime"))?;
            let data = im
                .get("data")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("image {i} missing data"))?;
            out.push((mime.to_string(), data.to_string()));
        }
        if out.is_empty() {
            bail!("image engine returned no images");
        }
        Ok(out)
    }

    fn terminate_child(&self) {
        let mut guard = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for ImageSubprocessEngine {
    fn drop(&mut self) {
        self.terminate_child();
    }
}

impl Engine for ImageSubprocessEngine {
    fn name(&self) -> &'static str {
        "image-subprocess"
    }

    fn ready(&self) -> bool {
        self.is_alive()
    }

    fn terminate(&self) {
        self.terminate_child();
    }

    fn restart(&self) -> Result<()> {
        // Reap the dead child, then respawn on the same per-instance path.
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
        let _ = std::fs::remove_file(&self.socket_path);
        tracing::info!(model = %self.model_id, "respawning dead image subprocess");
        self.start()
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        // Non-streaming generate isn't the image path's primary surface, but
        // the trait requires it. Run a generation and discard the images
        // (the streaming path is what callers use); return token estimates.
        let _ = self.generate_image_parts(request)?;
        let prompt_bytes = request
            .messages
            .iter()
            .map(|m| m.content_text())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        Ok(GenerateResponse {
            text: String::new(),
            tokens_in: pricing::estimate_tokens(&prompt_bytes),
            tokens_out: 0,
        })
    }

    fn generate_stream(
        &self,
        request: &GenerateRequest,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        let images = self.generate_image_parts(request)?;
        let prompt_bytes = request
            .messages
            .iter()
            .map(|m| m.content_text())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        let mut out_bytes = 0u64;
        for (mime, data_b64) in &images {
            out_bytes += pricing::estimate_tokens(data_b64.as_bytes());
            on_delta(DeltaChannel::Image, &encode_image_delta(mime, data_b64))?;
        }
        Ok(GenerateResponse {
            text: String::new(),
            tokens_in: pricing::estimate_tokens(&prompt_bytes),
            tokens_out: out_bytes,
        })
    }
}

impl ImageSubprocessEngine {
    /// POST `/generate` and parse the resulting images. Lazily (re)starts
    /// the child if it isn't alive.
    fn generate_image_parts(&self, request: &GenerateRequest) -> Result<Vec<(String, String)>> {
        if !self.is_alive() {
            self.start()?;
        }
        let body = Self::build_generate_body(request);
        let body_bytes = serde_json::to_vec(&body).context("serializing /generate body")?;
        let resp = self.http_post_uds("/generate", &body_bytes)?;
        Self::parse_generate_response(&resp)
    }
}

/// Best-effort size of `model_id`'s HuggingFace cache dir, used as a
/// download-progress signal during the readiness wait. Mirrors the chat
/// engine's `hf_cache_size` but kept local to avoid widening that module's
/// surface. Returns 0 when the cache can't be sized.
fn hf_cache_size(model_id: &str) -> u64 {
    let Some(home) = dirs::home_dir() else {
        return 0;
    };
    // huggingface_hub stores snapshots under
    // ~/.cache/huggingface/hub/models--<org>--<name>.
    let sanitized = model_id.replace('/', "--");
    let dir = home
        .join(".cache")
        .join("huggingface")
        .join("hub")
        .join(format!("models--{sanitized}"));
    dir_size_bytes(&dir)
}

fn dir_size_bytes(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            total += dir_size_bytes(&entry.path());
        } else {
            total += meta.len();
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::{ContentPart, Message};

    fn req(model: &str, parts: Vec<ContentPart>) -> GenerateRequest {
        GenerateRequest {
            model: model.into(),
            messages: vec![Message {
                role: "user".into(),
                content: parts,
            }],
            max_tokens: 4,
            temperature: None,
            top_p: None,
        }
    }

    #[test]
    fn build_generate_body_t2i_has_prompt_and_steps_no_images() {
        let body = ImageSubprocessEngine::build_generate_body(&req(
            "flux",
            vec![ContentPart::Text("a red apple".into())],
        ));
        assert_eq!(body["prompt"], "a red apple");
        assert_eq!(body["steps"], 4);
        assert!(body.get("images").is_none());
    }

    #[test]
    fn build_generate_body_img2img_carries_reference_images() {
        let body = ImageSubprocessEngine::build_generate_body(&req(
            "flux",
            vec![
                ContentPart::Text("make it watercolor".into()),
                ContentPart::Image {
                    mime: "image/png".into(),
                    data_b64: "AAAA".into(),
                },
            ],
        ));
        assert_eq!(body["prompt"], "make it watercolor");
        let images = body["images"].as_array().unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0]["mime"], "image/png");
        assert_eq!(images[0]["data"], "AAAA");
    }

    #[test]
    fn parse_generate_response_extracts_images() {
        let json = br#"{"images":[{"mime":"image/png","data":"AAAA"},{"mime":"image/png","data":"BBBB"}]}"#;
        let out = ImageSubprocessEngine::parse_generate_response(json).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], ("image/png".to_string(), "AAAA".to_string()));
        assert_eq!(out[1].1, "BBBB");
    }

    #[test]
    fn parse_generate_response_rejects_empty_and_malformed() {
        assert!(ImageSubprocessEngine::parse_generate_response(br#"{"images":[]}"#).is_err());
        assert!(
            ImageSubprocessEngine::parse_generate_response(br#"{"images":[{"mime":"x"}]}"#)
                .is_err()
        );
        assert!(ImageSubprocessEngine::parse_generate_response(b"not json").is_err());
    }
}
