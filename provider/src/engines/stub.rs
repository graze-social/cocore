//! Echo-back stub engine. Always available, no Python or model
//! required. Preserves the v0.3.x behavior so the agent stays useful
//! without any inference runtime — wires up the protocol but admits
//! it isn't running a real model.
//!
//! Token counts use the same byte→token estimate the v0.3.x stub
//! used (`pricing::estimate_tokens`), so receipts produced by this
//! engine settle correctly against the exchange's tokenRate.

use anyhow::Result;

use crate::engines::{
    encode_image_delta, is_image_model, DeltaChannel, Engine, GenerateRequest, GenerateResponse,
};
use crate::pricing;

/// A fixed, valid 1×1 PNG (transparent pixel), base64-encoded. The stub
/// image path emits exactly this for any image-generation request — it
/// proves the protocol, receipts, and chat UX end-to-end without any GPU
/// or diffusion backend. Real pixels arrive with the Phase 8 subprocess /
/// Phase 10 native engines.
const STUB_PNG_B64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

pub struct StubEngine;

impl Engine for StubEngine {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn ready(&self) -> bool {
        true
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        // Reconstruct the v0.3.x reply shape so any downstream
        // consumer that pattern-matched the old "[cocore stub
        // provider] received N bytes" string keeps working.
        let prompt_bytes: Vec<u8> = request
            .messages
            .iter()
            .map(|m| format!("{}: {}", m.role, m.content_text()))
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        let preview: String = prompt_bytes
            .iter()
            .take(80)
            .map(|&b| {
                if (32..127).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        let reply = format!(
            "[cocore stub provider] received {} bytes; preview={:?}; model={}; max_tokens_out={}\n",
            prompt_bytes.len(),
            preview,
            request.model,
            request.max_tokens,
        );
        let tokens_in = pricing::estimate_tokens(&prompt_bytes);
        let tokens_out = pricing::estimate_tokens(reply.as_bytes());
        Ok(GenerateResponse {
            text: reply,
            tokens_in,
            tokens_out,
        })
    }

    fn generate_stream(
        &self,
        request: &GenerateRequest,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        // Image-generation models (e.g. `stub-flux`): emit one fixed PNG on
        // the image channel instead of echoing text. The prompt — t2i raw
        // text or the last user turn of a `messages-v1` envelope — is read
        // only to size the token estimate; the pixels are constant.
        if is_image_model(&request.model) {
            let prompt_bytes: Vec<u8> = request
                .messages
                .iter()
                .map(|m| m.content_text())
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes();
            let has_reference = request.messages.iter().any(|m| m.has_images());
            on_delta(
                DeltaChannel::Image,
                &encode_image_delta("image/png", STUB_PNG_B64),
            )?;
            let tokens_in = pricing::estimate_tokens(&prompt_bytes);
            // Output "tokens" for an image are a byte-estimate over the
            // emitted image payload until step-based pricing lands.
            let tokens_out = pricing::estimate_tokens(STUB_PNG_B64.as_bytes());
            tracing::debug!(
                model = %request.model,
                has_reference,
                "stub image engine emitted fixed 1x1 PNG"
            );
            return Ok(GenerateResponse {
                text: String::new(),
                tokens_in,
                tokens_out,
            });
        }
        let resp = self.generate_once(request)?;
        // Slice the stub reply so local/dev runs exercise multi-chunk
        // relay even without a real tokenizer backend.
        for chunk in resp.text.as_bytes().chunks(32) {
            let piece = std::str::from_utf8(chunk).unwrap_or("");
            if !piece.is_empty() {
                on_delta(DeltaChannel::Content, piece)?;
            }
        }
        Ok(resp)
    }
}
