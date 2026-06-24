//! Inference-engine abstraction.
//!
//! `cocore agent serve` ships a stub engine by default — it echoes the
//! prompt with metadata, enough to wire-test the protocol but not to
//! actually answer anything. To serve real inference the agent spawns
//! one `SubprocessEngine` per configured model (see `subprocess.rs`).
//! Each instance owns a Python child process that hosts `vllm-mlx`'s
//! FastAPI app on a Unix domain socket; the Rust side proxies
//! `/v1/chat/completions` over the socket using a hand-rolled
//! HTTP/1.1 client.
//!
//! The v0.5.x in-process PyO3 design (and the `inference` feature
//! flag that gated it) is gone. PyO3+auto-initialize baked the build
//! machine's libpython path into the binary's Mach-O load commands,
//! which crashed dyld on every user whose Mac didn't have Homebrew
//! Python 3.12 at exactly `/opt/homebrew/opt/python@3.12/...`. The
//! subprocess design has zero libpython linkage and runs unchanged
//! across Macs whose Python toolchain came from python.org, brew,
//! conda, Xcode CLT, or — with the v0.6+ installer — `uv`-managed
//! python-build-standalone.
//!
//! The trait sits between the advisor's `handle_inference_request`
//! and whichever backend is in scope. It keeps three concerns local
//! to the engine implementation:
//!
//!   1. Tokenization (real engines use the model's tokenizer; stub
//!      uses estimate_tokens).
//!   2. Generation (real engines spawn a subprocess and proxy
//!      requests; stub builds a string).
//!   3. Model lifecycle (real engines load once + reuse across
//!      requests; stub has no state).

use anyhow::Result;
use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(feature = "native_mlx")]
pub mod native_mlx;
pub mod stub;
pub mod subprocess;

/// A directory of engines keyed by the NSID the requester names in
/// `chat.completions { model: ... }`.
///
/// The agent advertises `supportedModels = registry.live_models()` on
/// its provider record — the health-gated subset, so a dead engine is
/// never advertised. The advisor's `handle_inference_request` looks up
/// `req.model` and routes to the matching engine; a miss is surfaced to
/// the requester as an error chunk so they can pick a model that's
/// actually loaded.
///
/// Today every registry includes a `stub` entry (for protocol-level
/// smoke tests + as a "this provider exists but isn't running real
/// inference" signal). For each model id the operator listed in
/// `COCORE_INFERENCE_MODELS` the registry additionally carries one
/// `subprocess::SubprocessEngine` — each engine instance owns a
/// Python child process that hosts vllm-mlx on a per-model Unix
/// domain socket.
pub struct EngineRegistry {
    by_model: BTreeMap<String, Arc<dyn Engine>>,
}

impl EngineRegistry {
    pub fn new() -> Self {
        Self {
            by_model: BTreeMap::new(),
        }
    }

    /// Register an engine under one or more model ids. Common case is
    /// one id; the stub engine registers under `stub`. Engines are
    /// stored behind an `Arc` so a clone can be handed to a
    /// `spawn_blocking` closure with a `'static` lifetime (the engine
    /// call is synchronous + blocking and must run off the advisor's
    /// async task — see `handle_inference_request`).
    pub fn register(&mut self, model_id: impl Into<String>, engine: Arc<dyn Engine>) {
        self.by_model.insert(model_id.into(), engine);
    }

    /// Look up the engine for a model id. Returns `None` when no
    /// engine is registered — the caller is expected to reject with a
    /// "this provider does not load model X" signal. The returned
    /// `Arc` clone is cheap and can outlive the registry borrow,
    /// which is what lets the caller move it into `spawn_blocking`.
    pub fn for_model(&self, model_id: &str) -> Option<Arc<dyn Engine>> {
        self.by_model.get(model_id).cloned()
    }

    /// Every model id ever registered, sorted (BTreeMap order). This
    /// includes engines whose subprocess has since died — registration
    /// is not retracted on death — so it is the wrong set to advertise.
    /// Use it only for diagnostics ("what does this agent know about")
    /// and the belt-and-suspenders model-miss error. Advertise
    /// [`live_models`](Self::live_models) instead.
    pub fn loaded_models(&self) -> Vec<String> {
        self.by_model.keys().cloned().collect()
    }

    /// Model ids whose engine reports [`ready`](Engine::ready) right now,
    /// sorted (BTreeMap order). This — NOT `loaded_models()` — is what
    /// the provider record's `supportedModels` must be built from. An
    /// engine whose Python child died (OOM, crash) stays registered while
    /// no longer serveable; advertising it makes the advisor route jobs
    /// that get dropped locally — no receipt, no credit — while the
    /// network counts them dispatched. Health-gating the advertised set
    /// closes that gap.
    pub fn live_models(&self) -> Vec<String> {
        self.by_model
            .iter()
            .filter(|(_, e)| e.ready())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Snapshot of every registered engine as `(model_id, engine)`
    /// pairs. The cloned `Arc`s are `Send + 'static`, so the serve loop
    /// can move them into a `spawn_blocking` health check (which calls
    /// the blocking [`Engine::restart`]) without holding a borrow of the
    /// registry across an `.await`.
    pub fn entries(&self) -> Vec<(String, Arc<dyn Engine>)> {
        self.by_model
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect()
    }

    /// Reap every engine's external process, synchronously. Call this
    /// immediately before any `std::process::exit` on the serve path
    /// (trust-tier / model switch) — `std::process::exit` runs no
    /// destructors, so without this the engines' `Drop` never fires and
    /// their Python children orphan to launchd until their own watchdog
    /// notices. Idempotent and safe after a partial reap.
    pub fn terminate_all(&self) {
        for engine in self.by_model.values() {
            engine.terminate();
        }
    }
}

impl Default for EngineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// One message in a chat conversation. Mirrors OpenAI's
/// `chat.completions` message shape so we can pass it directly into
/// vllm-mlx's `engine.chat(messages=...)` without translation.
#[derive(Debug, Clone)]
pub struct Message {
    pub role: String,
    pub content: String,
}

/// Inputs to a single inference call.
#[derive(Debug)]
pub struct GenerateRequest {
    /// Model identifier as supplied by the requester (e.g. `"stub"`,
    /// `"qwen2.5-0.5b-instruct-4bit"`). The engine decides how to
    /// resolve this to a concrete model on disk.
    pub model: String,
    pub messages: Vec<Message>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
}

/// Result of a non-streaming inference call.
#[derive(Debug)]
pub struct GenerateResponse {
    pub text: String,
    pub tokens_in: u64,
    pub tokens_out: u64,
}

/// Which logical channel a streamed delta belongs to. Thinking-capable
/// models produce reasoning ("thinking") text that we keep distinct from
/// the answer the requester acts on, so it can be committed, transported,
/// and rendered separately. Defaults to [`Content`](DeltaChannel::Content)
/// so engines and peers that know nothing about reasoning behave exactly
/// as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeltaChannel {
    #[default]
    Content,
    Reasoning,
}

const THINK_OPEN: &str = "<think>";
const THINK_CLOSE: &str = "</think>";

/// Heuristic: does this model's chat template prefill the opening `<think>`, so
/// generation begins inside the reasoning block and the stream carries only the
/// closing `</think>`? True for the Qwen3-*-Thinking-2507 family and similarly
/// named dedicated thinking models. Drives whether the [`ThinkTagSplitter`]
/// starts in reasoning mode ([`ThinkTagSplitter::new_in_reasoning`]). Unlabelled
/// thinking models can be opted in via `COCORE_THINKING_PREFILL_MODELS` (a
/// comma-separated list of substrings matched case-insensitively against the id).
pub fn model_prefills_think(model: &str) -> bool {
    let m = model.to_ascii_lowercase();
    if m.contains("thinking") {
        return true;
    }
    std::env::var("COCORE_THINKING_PREFILL_MODELS")
        .ok()
        .is_some_and(|list| {
            list.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .any(|s| !s.is_empty() && m.contains(&s))
        })
}

/// Substrings that mark a vision / multimodal (image-input) model. The
/// subprocess inference path is text-only (vllm-mlx serves text LLMs and the
/// chat sends no images), so these can't be served — loading one just makes the
/// Python child exit with status 1 and fails provisioning. Mirrors the console's
/// `isVisionModel` (packages/console/src/lib/model-directory.server.ts).
const VISION_MODEL_MARKERS: &[&str] = &[
    "vl",
    "vlm",
    "vision",
    "llava",
    "internvl",
    "pixtral",
    "moondream",
    "minicpm-v",
    "idefics",
    "smolvlm",
    "paligemma",
    "florence",
];

/// Whether `model` looks like a vision/multimodal model the text-only path
/// can't serve. Single-token markers match only at id-segment boundaries (ids
/// split on `/-._`) so a bare `vl` doesn't match unrelated words; multi-token
/// markers (those containing `-`) match as plain substrings.
pub fn is_vision_model(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    VISION_MODEL_MARKERS.iter().any(|marker| {
        if marker.contains('-') {
            lower.contains(marker)
        } else {
            marker_at_boundary(&lower, marker)
        }
    })
}

/// True if `marker` occurs in `haystack` not flanked by ASCII letters on either
/// side — the Rust equivalent of the console's `(^|[^a-z])marker([^a-z]|$)`.
fn marker_at_boundary(haystack: &str, marker: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mlen = marker.len();
    let mut search_from = 0;
    while let Some(rel) = haystack[search_from..].find(marker) {
        let start = search_from + rel;
        let end = start + mlen;
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_lowercase();
        let after_ok = end == bytes.len() || !bytes[end].is_ascii_lowercase();
        if before_ok && after_ok {
            return true;
        }
        search_from = start + 1;
    }
    false
}

/// Splits a plaintext content stream into [`Content`](DeltaChannel::Content)
/// and [`Reasoning`](DeltaChannel::Reasoning) fragments by recognizing inline
/// `<think>` / `</think>` markers. Local MLX models (Qwen, R1-distills) emit
/// these tags directly in their token stream rather than on a separate field.
///
/// State is carried across [`push`](ThinkTagSplitter::push) calls so a marker
/// split across two deltas (`"<thi"` then `"nk>"`) still parses: the splitter
/// holds back any trailing bytes that could begin the marker it is currently
/// hunting for, and emits them once the next delta resolves the ambiguity.
/// Call [`finish`](ThinkTagSplitter::finish) at end of stream to flush a
/// dangling partial marker as literal text.
#[derive(Default)]
pub struct ThinkTagSplitter {
    inside: bool,
    /// Bytes withheld because they might be the start of a marker that
    /// completes in a later delta. Always valid UTF-8 (each delta is).
    pending: String,
}

impl ThinkTagSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// For models whose chat template PREFILLS the opening `<think>` (the
    /// Qwen3-*-Thinking-2507 family and similar): generation begins already
    /// inside the reasoning block, so the stream carries the reasoning then a
    /// lone closing `</think>` with no opener. Start inside so leading
    /// reasoning is captured and the dangling close ends it. A stray `<think>`
    /// the model echoes anyway is treated as noise and dropped.
    pub fn new_in_reasoning() -> Self {
        Self {
            inside: true,
            pending: String::new(),
        }
    }

    /// Feed one raw content delta. Emits zero or more channel-tagged
    /// fragments through `sink`.
    pub fn push(
        &mut self,
        text: &str,
        sink: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<()> {
        self.pending.push_str(text);
        loop {
            if self.inside {
                // While reasoning, close on `</think>`. A `<think>` seen first
                // is a redundant/echoed opener (prefill templates emit it, some
                // both-tag models nest one) — drop it and stay inside rather
                // than leaking the literal tag into the reasoning text.
                let close = self.pending.find(THINK_CLOSE);
                let open = self.pending.find(THINK_OPEN);
                match earliest_marker(close, open) {
                    Some((idx, Marker::Close)) => {
                        if idx > 0 {
                            sink(DeltaChannel::Reasoning, &self.pending[..idx])?;
                        }
                        self.pending.drain(..idx + THINK_CLOSE.len());
                        self.inside = false;
                        continue;
                    }
                    Some((idx, Marker::Open)) => {
                        if idx > 0 {
                            sink(DeltaChannel::Reasoning, &self.pending[..idx])?;
                        }
                        self.pending.drain(..idx + THINK_OPEN.len());
                        continue;
                    }
                    None => {
                        // Hold back a suffix that could begin EITHER marker
                        // (both start with `<`).
                        let hold = longest_marker_prefix_suffix(&self.pending, THINK_CLOSE)
                            .max(longest_marker_prefix_suffix(&self.pending, THINK_OPEN));
                        self.emit_held(DeltaChannel::Reasoning, hold, sink)?;
                        break;
                    }
                }
            } else if let Some(idx) = self.pending.find(THINK_OPEN) {
                if idx > 0 {
                    sink(DeltaChannel::Content, &self.pending[..idx])?;
                }
                self.pending.drain(..idx + THINK_OPEN.len());
                self.inside = true;
                continue;
            } else {
                let hold = longest_marker_prefix_suffix(&self.pending, THINK_OPEN);
                self.emit_held(DeltaChannel::Content, hold, sink)?;
                break;
            }
        }
        Ok(())
    }

    /// Emit everything in `pending` except the trailing `hold` bytes (kept back
    /// because they may begin a marker completing in a later delta).
    fn emit_held(
        &mut self,
        channel: DeltaChannel,
        hold: usize,
        sink: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<()> {
        let emit_len = self.pending.len() - hold;
        if emit_len > 0 {
            sink(channel, &self.pending[..emit_len])?;
            self.pending.drain(..emit_len);
        }
        Ok(())
    }

    /// Flush any buffered tail at end of stream. A dangling partial marker
    /// is surfaced as literal text on the current channel.
    pub fn finish(&mut self, sink: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>) -> Result<()> {
        if !self.pending.is_empty() {
            let channel = if self.inside {
                DeltaChannel::Reasoning
            } else {
                DeltaChannel::Content
            };
            sink(channel, &self.pending)?;
            self.pending.clear();
        }
        Ok(())
    }
}

enum Marker {
    Open,
    Close,
}

/// Pick whichever marker position comes first in the buffer (close wins ties,
/// so an empty `<think></think>` resolves to a clean close).
fn earliest_marker(close: Option<usize>, open: Option<usize>) -> Option<(usize, Marker)> {
    match (close, open) {
        (Some(c), Some(o)) if c <= o => Some((c, Marker::Close)),
        (Some(_), Some(o)) => Some((o, Marker::Open)),
        (Some(c), None) => Some((c, Marker::Close)),
        (None, Some(o)) => Some((o, Marker::Open)),
        (None, None) => None,
    }
}

/// Length (in bytes) of the longest suffix of `buf` that is a prefix of
/// `marker`. Markers are ASCII, so a matching suffix is ASCII too and the
/// returned offset always lands on a char boundary.
fn longest_marker_prefix_suffix(buf: &str, marker: &str) -> usize {
    let buf = buf.as_bytes();
    let marker = marker.as_bytes();
    let max = marker.len().min(buf.len());
    (1..=max)
        .rev()
        .find(|&n| buf[buf.len() - n..] == marker[..n])
        .unwrap_or(0)
}

/// Anything that can answer an inference request. Implementations may
/// be expensive to construct (a vllm-mlx engine takes several seconds
/// to warm a model into MLX-managed Metal buffers); the advisor is
/// expected to construct one engine per process and reuse it.
pub trait Engine: Send + Sync {
    /// Human-readable backend identifier. Logged on the receipt's
    /// path for diagnostic purposes.
    fn name(&self) -> &'static str;

    /// True when this engine is fully ready to serve. The vllm-mlx
    /// engine returns `false` until its Python sandbox has loaded
    /// the model — and `false` again if that child later dies; the
    /// stub engine is always `true`.
    fn ready(&self) -> bool;

    /// Attempt to bring an engine that is no longer [`ready`](Engine::ready)
    /// back to a serving state. The default is a no-op returning `Ok` —
    /// correct for engines with no external process (the stub is always
    /// ready). The subprocess engine reaps its dead child and respawns
    /// it. Bounded retry / backoff around this call is the caller's job
    /// (see the serve loop's engine health check). Returns `Ok` once the
    /// restart has been attempted; the caller re-checks `ready()` to learn
    /// whether it took.
    fn restart(&self) -> Result<()> {
        Ok(())
    }

    /// Reap any external process this engine owns, synchronously, before
    /// the agent exits. The default is a no-op — correct for engines with
    /// no subprocess (the stub). The subprocess engine SIGTERMs (then
    /// SIGKILLs) its Python child and unlinks its socket.
    ///
    /// `Drop` already does this on the normal unwind path, but the serve
    /// loop also exits via `std::process::exit` on a trust-tier or model
    /// switch (the supervisor must re-select the worker shape), and
    /// `std::process::exit` runs no destructors. Calling `terminate()`
    /// explicitly at those sites reaps the children promptly instead of
    /// leaning on the child-side parent-death watchdog's poll latency.
    fn terminate(&self) {}

    /// Synchronous, non-streaming generate. Collects a streaming
    /// response when the engine only implements token deltas.
    fn generate(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        let mut text = String::new();
        let resp = self.generate_stream(request, &mut |channel, delta| {
            // The buffered convenience result is the answer only; reasoning
            // is dropped here (callers that want it use the streaming path).
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

    /// Emit plaintext token deltas through `on_delta` as they are
    /// produced. Returns final token counts once generation finishes.
    /// Engines with native streaming should override this; the default
    /// emits the full buffered completion as a single delta.
    fn generate_stream(
        &self,
        request: &GenerateRequest,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        let resp = self.generate_once(request)?;
        on_delta(DeltaChannel::Content, &resp.text)?;
        Ok(resp)
    }

    /// Backing implementation for engines that only expose a buffered
    /// completion. Override `generate_stream` instead when the
    /// backend can stream token deltas natively.
    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse>;

    /// True iff this engine processes the plaintext prompt ENTIRELY inside the
    /// measured provider binary — no owner-controlled subprocess, interpreter,
    /// or IPC the attestation doesn't cover. This is the load-bearing
    /// confidential property (darkbloom's "in-process inference"). Only a
    /// native in-process engine returns true; the subprocess and stub engines
    /// return the default `false`. The attestation producer reads this to set
    /// `inProcessBackend` honestly, and the confidential tier requires it.
    fn in_process(&self) -> bool {
        false
    }

    /// SHA-256 hex of the precompiled GPU shader library (e.g. `mlx.metallib`)
    /// this engine loads, when it has one. The kernels that touch plaintext
    /// live there, so a confidential verifier pins it alongside the cdHash.
    /// `None` for engines without a measured metallib (subprocess/stub).
    fn metallib_hash(&self) -> Option<String> {
        None
    }

    /// SHA-256 hex of the dynamic library that actually runs the in-process
    /// engine (e.g. `libCoCoreMLX.dylib`), when one is loaded. Because a
    /// dynamic engine lib is a measurable component the main binary's cdHash
    /// does NOT cover, a confidential verifier pins this too (enforced library
    /// validation already blocks a different team's dylib; this also locks the
    /// hash within our own team's releases). `None` for engines whose code is
    /// fully inside the measured binary (stub) or in a subprocess.
    fn engine_lib_hash(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Drive a splitter over a sequence of deltas and collect the
    /// channel-tagged fragments it emits (including the end-of-stream flush).
    fn split(deltas: &[&str]) -> Vec<(DeltaChannel, String)> {
        let mut splitter = ThinkTagSplitter::new();
        let mut out: Vec<(DeltaChannel, String)> = Vec::new();
        let mut sink = |ch: DeltaChannel, s: &str| {
            out.push((ch, s.to_string()));
            Ok(())
        };
        for d in deltas {
            splitter.push(d, &mut sink).unwrap();
        }
        splitter.finish(&mut sink).unwrap();
        out
    }

    /// Concatenate the fragments emitted on one channel.
    fn channel_text(frags: &[(DeltaChannel, String)], want: DeltaChannel) -> String {
        frags
            .iter()
            .filter(|(ch, _)| *ch == want)
            .map(|(_, s)| s.as_str())
            .collect()
    }

    #[test]
    fn splitter_separates_inline_think_block() {
        let frags = split(&["<think>reasoning here</think>the answer"]);
        assert_eq!(
            channel_text(&frags, DeltaChannel::Reasoning),
            "reasoning here"
        );
        assert_eq!(channel_text(&frags, DeltaChannel::Content), "the answer");
    }

    #[test]
    fn splitter_handles_marker_split_across_deltas() {
        // The opening and closing markers are each split mid-tag across delta
        // boundaries — the splitter must buffer and still recognize them.
        let frags = split(&["<thi", "nk>deep ", "thoughts</th", "ink>done"]);
        assert_eq!(
            channel_text(&frags, DeltaChannel::Reasoning),
            "deep thoughts"
        );
        assert_eq!(channel_text(&frags, DeltaChannel::Content), "done");
    }

    #[test]
    fn splitter_passes_through_plain_content() {
        let frags = split(&["just ", "an answer"]);
        assert_eq!(
            channel_text(&frags, DeltaChannel::Content),
            "just an answer"
        );
        assert_eq!(channel_text(&frags, DeltaChannel::Reasoning), "");
    }

    #[test]
    fn splitter_flushes_dangling_partial_marker_as_literal() {
        // A `<` that never completes into `<think>` is real content, surfaced
        // by `finish` rather than swallowed.
        let frags = split(&["answer <"]);
        assert_eq!(channel_text(&frags, DeltaChannel::Content), "answer <");
    }

    #[test]
    fn splitter_treats_unclosed_think_as_reasoning() {
        let frags = split(&["<think>still thinking"]);
        assert_eq!(
            channel_text(&frags, DeltaChannel::Reasoning),
            "still thinking"
        );
        assert_eq!(channel_text(&frags, DeltaChannel::Content), "");
    }

    /// Drive a splitter that starts inside the reasoning block (prefilled
    /// `<think>` template), over a sequence of deltas.
    fn split_in_reasoning(deltas: &[&str]) -> Vec<(DeltaChannel, String)> {
        let mut splitter = ThinkTagSplitter::new_in_reasoning();
        let mut out: Vec<(DeltaChannel, String)> = Vec::new();
        let mut sink = |ch: DeltaChannel, s: &str| {
            out.push((ch, s.to_string()));
            Ok(())
        };
        for d in deltas {
            splitter.push(d, &mut sink).unwrap();
        }
        splitter.finish(&mut sink).unwrap();
        out
    }

    #[test]
    fn prefilled_think_splits_dangling_close_as_reasoning() {
        // Qwen3-*-Thinking-2507: the opening <think> is prefilled by the
        // template, so the stream is reasoning followed by a lone </think>.
        let frags = split_in_reasoning(&["weighing options", "</think>\n\nFinal answer."]);
        assert_eq!(
            channel_text(&frags, DeltaChannel::Reasoning),
            "weighing options"
        );
        assert_eq!(
            channel_text(&frags, DeltaChannel::Content),
            "\n\nFinal answer."
        );
    }

    #[test]
    fn prefilled_mode_drops_a_redundant_echoed_open_tag() {
        // If a thinking model ALSO emits an explicit <think> while we already
        // assume we're inside, the stray opener is dropped, not leaked.
        let frags = split_in_reasoning(&["<think>reasoning</think>answer"]);
        assert_eq!(channel_text(&frags, DeltaChannel::Reasoning), "reasoning");
        assert_eq!(channel_text(&frags, DeltaChannel::Content), "answer");
    }

    #[test]
    fn prefill_detection_matches_thinking_models() {
        assert!(model_prefills_think(
            "lmstudio-community/Qwen3-4B-Thinking-2507-MLX-4bit"
        ));
        assert!(!model_prefills_think(
            "mlx-community/Qwen2.5-3B-Instruct-4bit"
        ));
    }

    #[test]
    fn vision_models_are_detected() {
        for id in [
            "McG-221/gemma-3-12b-it-vl-Polaris-GLM-4.7-Flash-VAR-Thinking-Instruct-Heretic-Uncensored-mlx-8Bit",
            "mlx-community/Qwen2.5-VL-7B-Instruct-4bit",
            "mlx-community/llava-1.5-7b-4bit",
            "mlx-community/paligemma2-3b-mix-448-8bit",
            "OpenGVLab/InternVL2-8B",
            "mlx-community/pixtral-12b-4bit",
        ] {
            assert!(is_vision_model(id), "{id} should be vision");
        }
    }

    #[test]
    fn text_models_are_not_flagged_as_vision() {
        for id in [
            "lmstudio-community/Qwen3-4B-Thinking-2507-MLX-4bit",
            "coderavi/Llama3.3-8B-Instruct-Thinking-Heretic-Uncensored-Claude-4.5-Opus-High-Reasoning-mlx-8Bit",
            "AutisticAF/Qwen3.6-27B-Heretic2-Uncensored-Finetune-Thinking-mlx-4Bit",
            "mlx-community/Qwen2.5-7B-Instruct-4bit",
            "stub",
        ] {
            assert!(!is_vision_model(id), "{id} should NOT be vision");
        }
    }

    /// Engine whose readiness is flippable, standing in for a subprocess
    /// engine whose Python child dies mid-serve.
    struct FlakyEngine {
        alive: AtomicBool,
    }
    impl Engine for FlakyEngine {
        fn name(&self) -> &'static str {
            "flaky-test-engine"
        }
        fn ready(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }
        fn generate_once(&self, _request: &GenerateRequest) -> Result<GenerateResponse> {
            Ok(GenerateResponse {
                text: String::new(),
                tokens_in: 0,
                tokens_out: 0,
            })
        }
    }

    #[test]
    fn live_models_excludes_dead_engines_but_loaded_models_keeps_them() {
        let mut reg = EngineRegistry::new();
        reg.register("stub", Arc::new(stub::StubEngine));
        let flaky = Arc::new(FlakyEngine {
            alive: AtomicBool::new(true),
        });
        reg.register("mlx-community/Qwen2.5-3B-Instruct-4bit", flaky.clone());

        // While the child is alive, both accessors agree.
        assert_eq!(
            reg.live_models(),
            vec![
                "mlx-community/Qwen2.5-3B-Instruct-4bit".to_string(),
                "stub".to_string()
            ]
        );
        assert_eq!(reg.live_models(), reg.loaded_models());

        // Child dies: live_models drops it, loaded_models still lists it
        // (registration is not retracted on death) — exactly the gap that
        // let a dead model keep being advertised.
        flaky.alive.store(false, Ordering::SeqCst);
        assert_eq!(reg.live_models(), vec!["stub".to_string()]);
        assert_eq!(
            reg.loaded_models(),
            vec![
                "mlx-community/Qwen2.5-3B-Instruct-4bit".to_string(),
                "stub".to_string()
            ]
        );
    }

    #[test]
    fn entries_snapshots_every_registered_engine() {
        let mut reg = EngineRegistry::new();
        reg.register("stub", Arc::new(stub::StubEngine));
        reg.register(
            "dead",
            Arc::new(FlakyEngine {
                alive: AtomicBool::new(false),
            }),
        );
        let entries = reg.entries();
        // Snapshot carries every registered engine regardless of liveness,
        // so the health check can see (and try to restart) the dead one.
        let ids: Vec<&str> = entries.iter().map(|(m, _)| m.as_str()).collect();
        assert_eq!(ids, vec!["dead", "stub"]);
        assert!(!entries.iter().find(|(m, _)| m == "dead").unwrap().1.ready());
    }
}
