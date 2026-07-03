//! OpenAI-compatible HTTP(S) inference engine.
//!
//! Proxies inference to any server that speaks the OpenAI
//! `/v1/chat/completions` API — llama.cpp's `llama-server`, Ollama, vLLM,
//! LM Studio, OpenAI itself, OpenRouter, etc. This is how a cocore provider on
//! Linux serves real inference: point it at an endpoint you run or trust.
//!
//! Unlike the macOS vllm-mlx subprocess backend, cocore neither spawns nor
//! supervises the endpoint — it is a pure HTTP client. Transport is `reqwest`
//! (rustls), so HTTPS works out of the box. We use the **blocking** client
//! because the `Engine` trait is synchronous and the call already runs on a
//! `spawn_blocking` thread (see `advisor.rs`).
//!
//! ## Trust / privacy
//!
//! The requester's prompt is decrypted by the agent and **forwarded in
//! cleartext (over TLS) to the configured endpoint**. The operator (and
//! implicitly the requester) trusts that endpoint with prompt content. The
//! model id is operator-configured (`COCORE_INFERENCE_MODELS`), never
//! requester-controlled, so the advisor's `for_model` gate still holds.
//! Prompts/responses are never logged (error paths elide bodies).

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::engines::{
    ContentPart, DeltaChannel, Engine, GenerateRequest, GenerateResponse, ThinkTagSplitter,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
const READY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct OpenAiEngine {
    model_id: String,
    chat_url: String,
    models_url: String,
    api_key: Option<String>,
    client: reqwest::blocking::Client,
}

impl OpenAiEngine {
    pub fn new(
        model_id: impl Into<String>,
        base_url: &str,
        api_key: Option<String>,
    ) -> Result<Self> {
        let base = normalize_base(base_url);
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

    /// Forced-tool-call canary: POST a request that forces one function call
    /// and verify the endpoint returns a structured `tool_calls` array naming
    /// our canary function. Mirrors the macOS subprocess engine's
    /// `verify_tool_call_support` — cocore advertises tool support only for
    /// what the backend proves at runtime, keeping no model/parser matrix.
    /// Non-streaming; bodies are `Zeroizing`. Returns `Ok(false)` (not an
    /// error) when the endpoint answers without a tool call.
    pub fn probe_tool_calls(&self) -> Result<bool> {
        let body = serde_json::json!({
            "model": self.model_id,
            "messages": [
                { "role": "system", "content": "tool-calling canary" },
                { "role": "user", "content": "Call report_status with status set to ok." },
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "report_status",
                    "parameters": {
                        "type": "object",
                        "properties": { "status": { "type": "string" } },
                        "required": ["status"],
                        "additionalProperties": false,
                    },
                },
            }],
            "tool_choice": { "type": "function", "function": { "name": "report_status" } },
            "max_tokens": 96,
            "temperature": 0,
            "stream": false,
        });
        let bytes = Zeroizing::new(serde_json::to_vec(&body)?);
        let resp = self
            .with_auth(self.client.post(&self.chat_url))
            .timeout(REQUEST_TIMEOUT)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes.to_vec())
            .send()
            .with_context(|| format!("POST {}", self.chat_url))?;
        if !resp.status().is_success() {
            return Ok(false);
        }
        let v: serde_json::Value = resp.json().context("parsing tool-call canary response")?;
        let ok = v
            .pointer("/choices/0/message/tool_calls")
            .and_then(|tc| tc.as_array())
            .is_some_and(|arr| {
                arr.iter().any(|c| {
                    c.pointer("/function/name").and_then(|n| n.as_str()) == Some("report_status")
                })
            });
        Ok(ok)
    }

    fn body(&self, request: &GenerateRequest, stream: bool) -> serde_json::Value {
        let messages: Vec<serde_json::Value> = request
            .messages
            .iter()
            .map(|m| {
                let content = serialize_content_parts(&m.content);
                let mut msg = serde_json::json!({ "role": m.role, "content": content });
                if let Some(tc) = &m.tool_calls {
                    let tc_json: Vec<serde_json::Value> = tc
                        .iter()
                        .map(|t| {
                            serde_json::json!({
                                "id": t.id,
                                "type": "function",
                                "function": {
                                    "name": t.function_name,
                                    "arguments": t.function_arguments,
                                }
                            })
                        })
                        .collect();
                    msg["tool_calls"] = serde_json::Value::Array(tc_json);
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
        if let Some(ref gj) = request.guided_json {
            b["response_format"] = serde_json::json!({
                "type": "json_schema",
                "json_schema": gj,
            });
        }
        if let Some(ref tools) = request.tools {
            b["tools"] = tools.clone();
        }
        if let Some(ref tc) = request.tool_choice {
            b["tool_choice"] = tc.clone();
        }
        b
    }
}

fn serialize_content_parts(parts: &[ContentPart]) -> serde_json::Value {
    if parts.len() == 1 {
        if let ContentPart::Text(s) = &parts[0] {
            return serde_json::json!(s);
        }
    }
    let arr: Vec<serde_json::Value> = parts
        .iter()
        .map(|p| match p {
            ContentPart::Text(s) => serde_json::json!({ "type": "text", "text": s }),
            ContentPart::Image { mime, data_b64 } => serde_json::json!({
                "type": "image_url",
                "image_url": {
                    "url": format!("data:{mime};base64,{data_b64}"),
                }
            }),
        })
        .collect();
    serde_json::Value::Array(arr)
}

fn normalize_base(base: &str) -> String {
    let b = base.trim().trim_end_matches('/');
    b.strip_suffix("/v1").unwrap_or(b).to_string()
}

fn process_sse(
    buf: &mut Vec<u8>,
    cursor: &mut usize,
    on_data: &mut dyn FnMut(&serde_json::Value) -> Result<()>,
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
        on_data(&v)?;
    }
    if *cursor > 8192 {
        buf.drain(..*cursor);
        *cursor = 0;
    }
    Ok(())
}

fn read_sse_stream(
    r: &mut impl Read,
    on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    model: &str,
) -> Result<(u64, u64)> {
    let mut buf: Vec<u8> = Vec::new();
    let mut read_buf = [0u8; 4096];
    let mut cursor = 0usize;
    let mut tokens = (0u64, 0u64);

    let mut splitter = if crate::engines::model_prefills_think(model) {
        ThinkTagSplitter::new_in_reasoning()
    } else {
        ThinkTagSplitter::new()
    };

    let mut handler = |v: &serde_json::Value| {
        // Reasoning channel: backends that surface thinking on a dedicated
        // field (llama-server with --reasoning-format, vLLM reasoning
        // parsers) rather than inline <think> tags. Mirrors the subprocess
        // engine's process_sse_buffer.
        if let Some(reasoning) = v
            .pointer("/choices/0/delta/reasoning_content")
            .or_else(|| v.pointer("/choices/0/delta/reasoning"))
            .and_then(|c| c.as_str())
        {
            if !reasoning.is_empty() {
                on_delta(DeltaChannel::Reasoning, reasoning)?;
            }
        }
        if let Some(tc) = v
            .pointer("/choices/0/delta/tool_calls")
            .filter(|t| !t.is_null())
        {
            if let Ok(tc_str) = serde_json::to_string(tc) {
                on_delta(DeltaChannel::ToolCall, &tc_str)?;
            }
        }
        if let Some(content) = v
            .pointer("/choices/0/delta/content")
            .and_then(|c| c.as_str())
        {
            if !content.is_empty() {
                splitter.push(content, on_delta)?;
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
        Ok(())
    };

    loop {
        let n = match r.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => n,
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
        process_sse(&mut buf, &mut cursor, &mut handler)?;
    }

    splitter.finish(on_delta)?;
    Ok(tokens)
}

impl Engine for OpenAiEngine {
    fn name(&self) -> &'static str {
        "openai-http"
    }

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
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
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
        let (tokens_in, tokens_out) = read_sse_stream(&mut resp, on_delta, &request.model)?;
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
        let mut got = String::new();
        let mut tokens = (0u64, 0u64);
        process_sse(&mut buf, &mut cursor, &mut |v| {
            if let Some(content) = v
                .pointer("/choices/0/delta/content")
                .and_then(|c| c.as_str())
            {
                got.push_str(content);
            }
            if let Some(u) = v.get("usage") {
                if let Some(p) = u.get("prompt_tokens").and_then(|v| v.as_u64()) {
                    tokens.0 = p;
                }
                if let Some(c) = u.get("completion_tokens").and_then(|v| v.as_u64()) {
                    tokens.1 = c;
                }
            }
            Ok(())
        })
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
        }
    }

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
                        Ok(n) => raw.extend_from_slice(&tmp[..n]),
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
    fn generate_stream_relays_sse_deltas() {
        let (port, server) = spawn_fake_endpoint();
        let engine =
            OpenAiEngine::new("test-model", &format!("http://127.0.0.1:{port}"), None).unwrap();
        let mut got = String::new();
        let resp = engine
            .generate_stream(&req(), &mut |channel, d| {
                if channel == DeltaChannel::Content {
                    got.push_str(d);
                }
                Ok(())
            })
            .unwrap();
        drop(server);
        assert_eq!(got, "Hello there");
        assert_eq!((resp.tokens_in, resp.tokens_out), (7, 2));
    }

    #[test]
    fn serialize_content_parts_single_text() {
        let parts = vec![ContentPart::Text("hello".into())];
        let v = serialize_content_parts(&parts);
        assert_eq!(v, serde_json::json!("hello"));
    }

    #[test]
    fn serialize_content_parts_multimodal() {
        let parts = vec![
            ContentPart::Text("look at this".into()),
            ContentPart::Image {
                mime: "image/png".into(),
                data_b64: "abc123".into(),
            },
        ];
        let v = serialize_content_parts(&parts);
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["type"], "text");
        assert_eq!(arr[1]["type"], "image_url");
    }

    /// Drive `read_sse_stream` over an in-memory body and collect the
    /// channel-tagged deltas + token counts. Mirrors the subprocess test
    /// module's `drain` helper so channel-routing tests read the same way
    /// in both engines.
    fn drain(body: &str, model: &str) -> (Vec<(DeltaChannel, String)>, (u64, u64)) {
        let mut out: Vec<(DeltaChannel, String)> = Vec::new();
        let mut cursor = std::io::Cursor::new(body.as_bytes().to_vec());
        let tokens = read_sse_stream(
            &mut cursor,
            &mut |ch, s| {
                out.push((ch, s.to_string()));
                Ok(())
            },
            model,
        )
        .expect("in-memory SSE stream");
        (out, tokens)
    }

    fn channel_text(out: &[(DeltaChannel, String)], want: DeltaChannel) -> String {
        out.iter()
            .filter(|(c, _)| *c == want)
            .map(|(_, s)| s.as_str())
            .collect()
    }

    #[test]
    fn extracts_reasoning_content_field_onto_reasoning_channel() {
        // llama-server with --reasoning-format (and vLLM reasoning parsers)
        // surface thinking on a dedicated delta field rather than inline
        // <think> tags; it must land on the Reasoning channel, not Content.
        // Mirrors the subprocess engine's test of the same name.
        let body = "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"hmm\"}}]}\n\
                    data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\
                    data: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2}}\n\
                    data: [DONE]\n";
        let (out, tokens) = drain(body, "test-model");
        assert_eq!(channel_text(&out, DeltaChannel::Reasoning), "hmm");
        assert_eq!(channel_text(&out, DeltaChannel::Content), "hi");
        assert_eq!(tokens, (4, 2));
    }

    #[test]
    fn splits_inline_think_tags_in_content_field() {
        // A model with no reasoning_content field but inline <think> in its
        // content stream is still separated by the ThinkTagSplitter.
        let body =
            "data: {\"choices\":[{\"delta\":{\"content\":\"<think>why</think>because\"}}]}\n\
                    data: [DONE]\n";
        let (out, _) = drain(body, "test-model");
        assert_eq!(channel_text(&out, DeltaChannel::Reasoning), "why");
        assert_eq!(channel_text(&out, DeltaChannel::Content), "because");
    }

    #[test]
    fn prefill_think_model_starts_stream_in_reasoning() {
        // A dedicated thinking model prefills the opening <think> in its chat
        // template, so the stream carries only the closing tag. The splitter
        // must start inside reasoning for such model ids.
        let body = "data: {\"choices\":[{\"delta\":{\"content\":\"pondering</think>done\"}}]}\n\
                    data: [DONE]\n";
        let (out, _) = drain(body, "qwen3-thinking-2507");
        assert_eq!(channel_text(&out, DeltaChannel::Reasoning), "pondering");
        assert_eq!(channel_text(&out, DeltaChannel::Content), "done");
    }

    #[test]
    fn separates_tool_calls_from_content_and_skips_null() {
        // Structured tool_calls fragments ride the ToolCall channel as JSON;
        // an explicit `"tool_calls": null` (some backends emit it on the
        // terminal chunk) must not be forwarded as the literal string "null".
        let body = "data: {\"choices\":[{\"delta\":{\"content\":\"Let me check\"}}]}\n\
                    data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{}\"}}]}}]}\n\
                    data: {\"choices\":[{\"delta\":{\"content\":\"\",\"tool_calls\":null}}]}\n\
                    data: [DONE]\n";
        let (out, _) = drain(body, "test-model");
        assert_eq!(channel_text(&out, DeltaChannel::Content), "Let me check");
        let tool_calls: Vec<&str> = out
            .iter()
            .filter(|(c, _)| *c == DeltaChannel::ToolCall)
            .map(|(_, s)| s.as_str())
            .collect();
        assert_eq!(tool_calls.len(), 1, "null tool_calls must not be forwarded");
        let parsed: serde_json::Value = serde_json::from_str(tool_calls[0]).expect("json");
        assert_eq!(parsed[0]["function"]["name"], "get_weather");
    }

    #[test]
    fn body_includes_tools_tool_choice_and_response_format() {
        let engine = OpenAiEngine::new("m", "http://127.0.0.1:1", None).unwrap();
        let mut request = req();
        request.guided_json = Some(serde_json::json!({"name": "s", "schema": {}}));
        request.tools = Some(serde_json::json!([{"type": "function"}]));
        request.tool_choice = Some(serde_json::json!("auto"));
        let b = engine.body(&request, true);
        assert_eq!(b["response_format"]["type"], "json_schema");
        assert!(b["tools"].is_array());
        assert_eq!(b["tool_choice"], "auto");
        // Streaming bodies ask for the terminal usage chunk so token counts
        // are exact rather than estimated.
        assert_eq!(b["stream_options"]["include_usage"], true);
    }

    #[test]
    fn body_omits_optional_fields_when_absent() {
        // Optional knobs must be absent, not null — some backends reject
        // explicit nulls, and the non-streaming body must not carry
        // stream_options.
        let engine = OpenAiEngine::new("m", "http://127.0.0.1:1", None).unwrap();
        let b = engine.body(&req(), false);
        for key in [
            "response_format",
            "tools",
            "tool_choice",
            "temperature",
            "top_p",
            "stream_options",
        ] {
            assert!(b.get(key).is_none(), "{key} should be omitted");
        }
        assert_eq!(b["stream"], false);
    }

    /// One-shot fake endpoint that answers every request with `response`
    /// (a full raw HTTP response). For canary/error-path tests where the
    /// richer `spawn_fake_endpoint` routing is noise.
    fn spawn_static_endpoint(response: String) -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            for _ in 0..4 {
                let Ok((mut conn, _)) = listener.accept() else {
                    return;
                };
                let _ = conn.set_read_timeout(Some(Duration::from_millis(200)));
                let mut raw = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    match conn.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => raw.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                let _ = conn.write_all(response.as_bytes());
            }
        });
        (port, handle)
    }

    fn json_response(json: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
            json.len()
        )
    }

    #[test]
    fn probe_tool_calls_true_when_endpoint_returns_structured_call() {
        // The canary gates tool-call advertising: a backend that returns a
        // real tool_calls array naming the canary function passes.
        let json = "{\"choices\":[{\"message\":{\"tool_calls\":[{\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"report_status\",\"arguments\":\"{\\\"status\\\":\\\"ok\\\"}\"}}]}}]}";
        let (port, server) = spawn_static_endpoint(json_response(json));
        let engine =
            OpenAiEngine::new("test-model", &format!("http://127.0.0.1:{port}"), None).unwrap();
        assert!(engine.probe_tool_calls().unwrap());
        drop(server);
    }

    #[test]
    fn probe_tool_calls_false_when_endpoint_answers_with_text() {
        // A backend that ignores the forced tool_choice and answers in prose
        // must NOT be advertised as tool-capable — Ok(false), not an error.
        let json = "{\"choices\":[{\"message\":{\"content\":\"status is ok!\"}}]}";
        let (port, server) = spawn_static_endpoint(json_response(json));
        let engine =
            OpenAiEngine::new("test-model", &format!("http://127.0.0.1:{port}"), None).unwrap();
        assert!(!engine.probe_tool_calls().unwrap());
        drop(server);
    }

    #[test]
    fn error_status_elides_response_body() {
        // Endpoints echo the request (prompt included) back in error bodies;
        // the error we surface must carry the status but never those bytes.
        let body = "{\"error\":{\"message\":\"SECRET-PROMPT-ECHO\"}}";
        let resp = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (port, server) = spawn_static_endpoint(resp);
        let engine =
            OpenAiEngine::new("test-model", &format!("http://127.0.0.1:{port}"), None).unwrap();
        let err = engine.generate_once(&req()).unwrap_err().to_string();
        drop(server);
        assert!(err.contains("500"), "status surfaced: {err}");
        assert!(
            !err.contains("SECRET-PROMPT-ECHO"),
            "body must be elided: {err}"
        );
    }
}
