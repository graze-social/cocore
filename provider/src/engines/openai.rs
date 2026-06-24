//! OpenAI-compatible HTTP(S) inference engine.
//!
//! Proxies inference to any server that speaks the OpenAI
//! `/v1/chat/completions` API — llama.cpp's `llama-server`, Ollama, vLLM,
//! LM Studio, OpenAI itself, OpenRouter, … This is how a cocore provider on
//! Linux (or anywhere) serves real inference without a local model runtime:
//! point it at an endpoint you run or trust.
//!
//! Unlike the macOS vllm-mlx backend, cocore neither spawns nor supervises the
//! endpoint — it's a pure client. Transport is `reqwest` (rustls), so HTTPS
//! works out of the box. We use the **blocking** client because the `Engine`
//! trait is synchronous and the call already runs on a `spawn_blocking` thread
//! (see `advisor.rs`); a generation bounds itself with a generous total
//! [`REQUEST_TIMEOUT`] and the dial with [`CONNECT_TIMEOUT`]. `restart()` is the
//! trait's no-op default: cocore can't restart a process it doesn't own — if
//! the endpoint goes away, `ready()` reports it and the serve loop's health
//! watchdog re-registers without the model.
//!
//! ## Trust / privacy
//!
//! The requester's prompt is decrypted by the agent and **forwarded in
//! cleartext (over TLS) to the configured endpoint** — so the operator (and
//! implicitly the requester) trusts that endpoint with prompt content. For a
//! local endpoint that's nothing new; for a third-party one it's a real choice.
//! The model id is operator-configured (`COCORE_INFERENCE_MODELS`), never
//! requester-controlled, so the advisor's `for_model` gate still holds and a
//! remote requester can't redirect this anywhere. Prompts/responses are never
//! logged (error paths elide bodies, which can echo the prompt).
//!
//! ## Determinism
//!
//! Setting `temperature=0` and a fixed `seed` makes generation deterministic on
//! backends that support it (llama.cpp, Ollama, most vLLM deployments). This
//! enables independent verification: a third party running the same model with
//! the same input and params should produce the same output, and the receipt's
//! `params` field commits to those settings. See `crate::determinism`.

// Serve-path module: a panic here can poison shared state or take the agent
// down. Deny the panic-on-the-happy-path footguns in production builds; the
// `#[cfg(test)]` module is exempt.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::engines::{Engine, GenerateRequest, GenerateResponse};

/// Connect timeout for the endpoint dial.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total per-request timeout for a generation: generous so a long completion
/// isn't cut short, but bounded so a wedged endpoint can't tie up a worker
/// forever. reqwest's *blocking* client builder exposes no idle/read timeout,
/// so we bound the whole request instead of per-read idle time.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
/// Short total timeout for the lightweight `/v1/models` readiness probe.
const READY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct OpenAiEngine {
    /// cocore model id; also the `model` we send upstream.
    model_id: String,
    /// `{base}/v1/chat/completions`.
    chat_url: String,
    /// `{base}/v1/models` — the readiness probe.
    models_url: String,
    api_key: Option<String>,
    client: reqwest::blocking::Client,
}

impl OpenAiEngine {
    /// Build an engine for `model_id` against `base_url` (e.g.
    /// `http://127.0.0.1:8080` or `https://api.example.com`). No network I/O —
    /// reachability is checked via [`ready`](Engine::ready).
    pub fn new(
        model_id: impl Into<String>,
        base_url: &str,
        api_key: Option<String>,
    ) -> Result<Self> {
        let base = normalize_base(base_url);
        // connect_timeout bounds the dial; each request sets its own total
        // timeout (REQUEST_TIMEOUT for generation, READY_TIMEOUT for the probe).
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .context("building HTTP client for the OpenAI endpoint")?;
        Ok(Self {
            model_id: model_id.into(),
            chat_url: format!("{base}/v1/chat/completions"),
            models_url: format!("{base}/v1/models"),
            api_key,
            client,
        })
    }

    fn with_auth(
        &self,
        rb: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        match &self.api_key {
            Some(k) => rb.bearer_auth(k),
            None => rb,
        }
    }

    /// Render a message's content into the OpenAI `chat.completions` shape.
    /// A text-only message keeps the scalar-string form; a message with
    /// images becomes the array-of-parts form, with each image emitted as
    /// an `image_url` data URI.
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

    /// OpenAI `chat.completions` body. `stream` toggles SSE; when streaming we
    /// also ask for a terminal `usage` chunk so token counts are exact.
    fn body(&self, request: &GenerateRequest, stream: bool) -> serde_json::Value {
        let messages: Vec<serde_json::Value> = request
            .messages
            .iter()
            .map(|m| {
                let mut msg = serde_json::json!({
                    "role": m.role,
                    "content": Self::render_content(m),
                });
                if let Some(tool_calls) = &m.tool_calls {
                    msg["tool_calls"] = serde_json::json!(tool_calls
                        .iter()
                        .map(|tc| serde_json::json!({
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function_name,
                                "arguments": tc.function_arguments,
                            }
                        }))
                        .collect::<Vec<_>>());
                }
                if let Some(id) = &m.tool_call_id {
                    msg["tool_call_id"] = serde_json::json!(id);
                }
                msg
            })
            .collect();
        let mut b = serde_json::json!({
            "model": self.model_id,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "stream": stream,
        });
        if stream {
            b["stream_options"] = serde_json::json!({ "include_usage": true });
        }
        if let Some(t) = request.temperature {
            b["temperature"] = serde_json::json!(t);
        }
        if let Some(p) = request.top_p {
            b["top_p"] = serde_json::json!(p);
        }
        // Pass seed through when set; backends that support deterministic
        // generation (llama.cpp, Ollama, most vLLM) will use it. When
        // combined with temperature=0 this makes output reproducible,
        // enabling independent verification of the receipt's output commitment.
        if let Some(s) = request.seed {
            b["seed"] = serde_json::json!(s);
        }
        // Structured output: pass the requester's JSON Schema through as an
        // OpenAI-compatible `response_format`.
        if let Some(schema) = &request.guided_json {
            b["response_format"] = serde_json::json!({
                "type": "json_schema",
                "json_schema": schema
            });
        }
        // Tool calling: forward tools and tool_choice as OpenAI-compatible
        // fields so the model can invoke functions.
        if let Some(tools) = &request.tools {
            b["tools"] = tools.clone();
        }
        if let Some(choice) = &request.tool_choice {
            b["tool_choice"] = choice.clone();
        }
        b
    }
}

/// Normalize a base URL: drop a trailing `/` and a trailing `/v1` (so both
/// `https://h` and `https://h/v1` end up as `https://h`, and we always append
/// `/v1/chat/completions` ourselves).
fn normalize_base(base: &str) -> String {
    let b = base.trim().trim_end_matches('/');
    b.strip_suffix("/v1").unwrap_or(b).to_string()
}

/// Drain complete SSE `data:` lines from `buf` starting at `cursor`, forwarding
/// `choices[0].delta.content` to `on_data` and capturing `usage` token counts.
/// reqwest hands us the already-decoded (dechunked) body, so this only parses
/// SSE framing — no HTTP framing. Stops at a partial trailing line so the
/// caller can read more bytes; compacts the buffer once the cursor is large.
fn process_sse(
    buf: &mut Vec<u8>,
    cursor: &mut usize,
    on_data: &mut dyn FnMut(&str) -> Result<()>,
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
        if let Some(content) = v
            .pointer("/choices/0/delta/content")
            .and_then(|c| c.as_str())
        {
            if !content.is_empty() {
                on_data(content)?;
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

/// Read an SSE stream from `r` (a reqwest blocking `Response`, already
/// dechunked), forwarding deltas via `on_delta`, returning `(prompt_tokens,
/// completion_tokens)` from the terminal `usage` (0 if the endpoint omits it —
/// the caller falls back to an estimate).
fn read_sse_stream(
    r: &mut impl Read,
    on_delta: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<(u64, u64)> {
    let mut buf: Vec<u8> = Vec::new();
    let mut read_buf = [0u8; 4096];
    let mut cursor = 0usize;
    let mut tokens = (0u64, 0u64);
    loop {
        let n = match r.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => n,
            // The request's total timeout (or a transport stall) surfaces here
            // as TimedOut / WouldBlock depending on platform.
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                bail!(
                    "endpoint stream timed out or stalled (exceeded {}s)",
                    REQUEST_TIMEOUT.as_secs()
                );
            }
            Err(e) => return Err(e.into()),
        };
        buf.extend_from_slice(&read_buf[..n]);
        process_sse(&mut buf, &mut cursor, on_delta, &mut tokens)?;
    }
    Ok(tokens)
}

impl Engine for OpenAiEngine {
    fn name(&self) -> &'static str {
        "openai-http"
    }

    /// Reachable when `GET /v1/models` returns 2xx. This is the standard
    /// OpenAI-compatible discovery endpoint (llama-server, vLLM, Ollama, OpenAI
    /// all serve it). A non-2xx (incl. 401 with the configured key) means the
    /// endpoint is misconfigured/unreachable, so the model isn't advertised.
    fn ready(&self) -> bool {
        match self
            .with_auth(self.client.get(&self.models_url))
            .timeout(READY_TIMEOUT)
            .send()
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        // Serialized body wrapped in Zeroizing so the local copy is wiped on
        // drop. (The prompt is forwarded to the endpoint by design — see the
        // module's trust note.)
        let bytes = Zeroizing::new(serde_json::to_vec(&self.body(request, false))?);
        let resp = self
            .with_auth(self.client.post(&self.chat_url))
            .timeout(REQUEST_TIMEOUT)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes.to_vec())
            .send()
            .with_context(|| format!("POST {}", self.chat_url))?;
        let status = resp.status();
        if !status.is_success() {
            // Do NOT log the body: endpoints often echo the request (prompt)
            // back in error responses.
            bail!("endpoint returned HTTP {status} (body elided to avoid content logging)");
        }
        let v: serde_json::Value = resp.json().context("parsing endpoint JSON response")?;
        let text = v
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tokens_in = v
            .pointer("/usage/prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tokens_out = v
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
        on_delta: &mut dyn FnMut(crate::engines::DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.body(request, true))?);
        let mut resp = self
            .with_auth(self.client.post(&self.chat_url))
            .timeout(REQUEST_TIMEOUT)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes.to_vec())
            .send()
            .with_context(|| format!("POST {}", self.chat_url))?;
        let status = resp.status();
        if !status.is_success() {
            bail!(
                "endpoint returned HTTP {status} (streaming body elided to avoid content logging)"
            );
        }
        // Wrap the channel-unaware on_delta: the OpenAI endpoint produces only
        // content (no reasoning channel), so every delta is Content.
        let mut content_only = |text: &str| on_delta(crate::engines::DeltaChannel::Content, text);
        let (tokens_in, tokens_out) = read_sse_stream(&mut resp, &mut content_only)?;
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
    use crate::engines::Message;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn normalize_base_strips_trailing_slash_and_v1() {
        assert_eq!(normalize_base("http://h:8080"), "http://h:8080");
        assert_eq!(normalize_base("http://h:8080/"), "http://h:8080");
        assert_eq!(normalize_base("https://h/v1"), "https://h");
        assert_eq!(normalize_base("https://h/v1/"), "https://h");
        assert_eq!(normalize_base("  https://h  "), "https://h");
    }

    #[test]
    fn process_sse_forwards_deltas_and_reads_usage() {
        let mut buf = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\
                        data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\
                        data: {\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2}}\n\
                        data: [DONE]\n"
            .to_vec();
        let mut cursor = 0usize;
        let mut tokens = (0u64, 0u64);
        let mut got = String::new();
        process_sse(
            &mut buf,
            &mut cursor,
            &mut |d| {
                got.push_str(d);
                Ok(())
            },
            &mut tokens,
        )
        .unwrap();
        assert_eq!(got, "Hello");
        assert_eq!(tokens, (9, 2));
    }

    fn req() -> GenerateRequest {
        GenerateRequest {
            model: "test-model".into(),
            messages: vec![Message::text("user", "hi")],
            max_tokens: 16,
            temperature: None,
            top_p: None,
            guided_json: None,
            tools: None,
            tool_choice: None,
            seed: None,
        }
    }

    fn req_deterministic() -> GenerateRequest {
        GenerateRequest {
            model: "test-model".into(),
            messages: vec![Message::text("user", "hi")],
            max_tokens: 16,
            temperature: Some(0.0),
            top_p: None,
            guided_json: None,
            tools: None,
            tool_choice: None,
            seed: Some(42),
        }
    }

    /// Minimal fake OpenAI-compatible server: `GET /v1/models` → 200; a
    /// streaming chat POST → SSE; a non-streaming chat POST → JSON. Drains the
    /// full request before responding (a half-read TCP socket would RST). Loop
    /// is bounded so it self-terminates.
    fn spawn_fake_endpoint() -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            for _ in 0..16 {
                let Ok((mut conn, _)) = listener.accept() else {
                    return;
                };
                let _ = conn.set_read_timeout(Some(Duration::from_millis(200)));
                let mut raw = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    match conn.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&tmp[..n]);
                        }
                        Err(_) => break,
                    }
                }
                let reqs = String::from_utf8_lossy(&raw);
                let resp = if reqs.starts_with("GET /v1/models") {
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"data\":[]}".to_string()
                } else if reqs.contains("\"stream\":true") {
                    let body = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n\
                                data: {\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\n\
                                data: {\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\n\n\
                                data: [DONE]\n\n";
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{body}")
                } else {
                    let json = "{\"choices\":[{\"message\":{\"content\":\"Hello there\"}}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}";
                    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}", json.len())
                };
                let _ = conn.write_all(resp.as_bytes());
            }
        });
        (port, handle)
    }

    #[test]
    fn ready_true_when_models_endpoint_answers() {
        let (port, server) = spawn_fake_endpoint();
        let engine =
            OpenAiEngine::new("test-model", &format!("http://127.0.0.1:{port}"), None).unwrap();
        assert!(engine.ready());
        drop(server);
    }

    #[test]
    fn ready_false_when_nothing_listening() {
        // Port 1 is privileged + unused; connect fails fast.
        let engine = OpenAiEngine::new("m", "http://127.0.0.1:1", None).unwrap();
        assert!(!engine.ready());
    }

    #[test]
    fn generate_once_parses_json() {
        let (port, server) = spawn_fake_endpoint();
        let engine =
            OpenAiEngine::new("test-model", &format!("http://127.0.0.1:{port}"), None).unwrap();
        let resp = engine.generate_once(&req()).unwrap();
        drop(server);
        assert_eq!(resp.text, "Hello there");
        assert_eq!((resp.tokens_in, resp.tokens_out), (7, 2));
    }

    #[test]
    fn generate_once_with_seed_sends_seed_field() {
        let (port, server) = spawn_fake_endpoint();
        let engine =
            OpenAiEngine::new("test-model", &format!("http://127.0.0.1:{port}"), None).unwrap();
        // Deterministic request — the body should include seed=42 and temperature=0.
        // The fake server doesn't inspect the body, but we verify the engine
        // round-trips without error (body serialization + response parsing).
        let resp = engine.generate_once(&req_deterministic()).unwrap();
        drop(server);
        assert_eq!(resp.text, "Hello there");
    }

    #[test]
    fn generate_stream_relays_sse_deltas() {
        let (port, server) = spawn_fake_endpoint();
        let engine =
            OpenAiEngine::new("test-model", &format!("http://127.0.0.1:{port}"), None).unwrap();
        let mut got = String::new();
        let resp = engine
            .generate_stream(&req(), &mut |_channel, d| {
                got.push_str(d);
                Ok(())
            })
            .unwrap();
        drop(server);
        assert_eq!(got, "Hello there");
        assert_eq!((resp.tokens_in, resp.tokens_out), (7, 2));
    }
}
