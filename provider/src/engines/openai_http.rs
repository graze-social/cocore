//! OpenAI-compatible HTTP/1.1 client shared by every out-of-process engine.
//!
//! The vllm-mlx subprocess engine (`subprocess.rs`) and the attached engine
//! (`attached.rs`, any already-running OpenAI-compatible server such as
//! `mei`, `mlx_lm.server` or `llama-server`) speak the same wire protocol:
//! `POST /v1/chat/completions` (SSE-streamed or buffered) plus a
//! `GET /v1/models` readiness probe. What differs is only the transport —
//! a Unix domain socket for the child we spawn, TCP for a server the
//! operator runs. This module owns everything above the socket: request
//! body shaping, response parsing, the SSE delta codec, the time budgets,
//! and the two startup canaries (forced tool call, structured output) that
//! decide what a model is *advertised* as supporting.
//!
//! The client stays hand-rolled (no hyper/reqwest) for the same reason the
//! subprocess engine always was: one route, a tight dependency surface, and
//! full control over the read-timeout semantics that separate "slow prefill"
//! from "stalled stream". Nothing here ever logs a request or response body
//! — engine error responses routinely echo the prompt.

use anyhow::{anyhow, bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::engines::{
    ContentPart, DeltaChannel, GenerateRequest, GenerateResponse, Message, ThinkTagSplitter,
};

/// Per-request HTTP timeout against the engine. Inference can take 30+
/// seconds for long completions on a small Mac; 300s is the same ceiling
/// vllm-mlx's `--timeout` uses by default. For the streaming path this is
/// the budget for the FIRST token (prefill of a big tool-schema prompt can
/// legitimately run for minutes on slow hardware).
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(300);

/// Idle timeout between streamed body reads, applied only AFTER the engine
/// has started emitting meaningful output.
pub const HTTP_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Granularity at which the streaming read loop wakes to re-evaluate its
/// time budgets. The socket read timeout is set to this short slice so a
/// `WouldBlock`/`TimedOut` wakeup lets us decide whether we're still within
/// the first-token or idle budget rather than bailing on the first quiet
/// slice.
pub const HTTP_STREAM_READ_POLL: Duration = Duration::from_secs(5);

/// A connected byte stream the client can drive. Implemented for the two
/// transports we use; the socket-timeout setters are the only thing
/// `Read + Write` doesn't already give us.
pub trait EngineStream: Read + Write {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
}

impl EngineStream for UnixStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_write_timeout(self, dur)
    }
}

impl EngineStream for TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_write_timeout(self, dur)
    }
}

/// Render a message's content into the OpenAI `chat.completions` shape. A
/// text-only message keeps the scalar-string form (byte-identical to the
/// historical text path); a message with images becomes the array-of-parts
/// form, with each image emitted as an `image_url` data URI.
pub fn render_content(m: &Message) -> serde_json::Value {
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

/// Build the `chat.completions` request body for `request`. `stream`
/// selects SSE vs. buffered. Structured output (`guided_json`) is wrapped in
/// the `response_format.json_schema` envelope; tools and tool_choice are
/// forwarded verbatim.
pub fn build_chat_body(request: &GenerateRequest, stream: bool) -> Result<serde_json::Value> {
    let messages: Vec<serde_json::Value> = request
        .messages
        .iter()
        .map(|m| {
            let mut msg = serde_json::json!({
                "role": m.role,
                "content": render_content(m),
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
    if let Some(schema) = &request.guided_json {
        body["response_format"] = serde_json::json!({
            "type": "json_schema",
            "json_schema": schema
        });
    }
    if let Some(tools) = &request.tools {
        body["tools"] = tools.clone();
    }
    if let Some(choice) = &request.tool_choice {
        body["tool_choice"] = choice.clone();
    }
    Ok(body)
}

/// Ask for a terminal `usage` chunk on a streamed request. Servers that
/// follow the OpenAI contract (mei, llama-server, vLLM) only emit usage on a
/// stream when asked. Kept separate from [`build_chat_body`] so the
/// subprocess path's request bytes stay exactly what vllm-mlx has always
/// received (it emits usage unprompted).
pub fn request_stream_usage(body: &mut serde_json::Value) {
    body["stream_options"] = serde_json::json!({ "include_usage": true });
}

/// Offset just past the `\r\n\r\n` header terminator, if it has arrived.
pub fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Status code from a raw header block.
pub fn parse_http_status(headers: &[u8]) -> Result<u16> {
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

/// Drain complete `data:` lines from an SSE body buffer. Returns when the
/// buffer ends mid-line so the caller can read more bytes.
///
/// The boolean return value reports whether this call emitted at least one
/// meaningful, user-visible delta (content, reasoning, or tool_calls).
pub fn process_sse_buffer(
    buf: &mut Vec<u8>,
    cursor: &mut usize,
    splitter: &mut ThinkTagSplitter,
    on_data: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    tokens: &mut (u64, u64),
) -> Result<bool> {
    let mut emitted_delta = false;
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
                emitted_delta = true;
                on_data(DeltaChannel::Reasoning, reasoning)?;
            }
        }
        // Tool calls arrive as structured `tool_calls` deltas — forward the
        // raw JSON array on the ToolCall channel so the provider can seal
        // and forward it. The client reassembles the fragments.
        if let Some(tool_calls) = v.pointer("/choices/0/delta/tool_calls") {
            if !tool_calls.is_null() {
                let json = serde_json::to_string(tool_calls).unwrap_or_default();
                if !json.is_empty() {
                    emitted_delta = true;
                    on_data(DeltaChannel::ToolCall, &json)?;
                }
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
                emitted_delta = true;
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
    Ok(emitted_delta)
}

fn write_request_head(
    stream: &mut dyn EngineStream,
    host: &str,
    path: &str,
    body_len: usize,
) -> Result<()> {
    let req_head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         Content-Length: {body_len}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(req_head.as_bytes())
        .context("writing HTTP request head")
}

/// Synchronous, buffered HTTP/1.1 POST. Returns the body bytes on any 2xx;
/// on a non-2xx the body is elided from the error (engine error responses
/// frequently echo the request payload, prompt included).
pub fn http_post(
    stream: &mut dyn EngineStream,
    host: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<u8>> {
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT))?;
    write_request_head(stream, host, path, body.len())?;
    stream
        .write_all(body)
        .context("writing HTTP request body")?;
    stream.flush().ok();

    let mut all = Vec::new();
    stream
        .read_to_end(&mut all)
        .context("reading HTTP response")?;

    let hdr_end = all
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("no header/body separator in response"))?;
    let headers = &all[..hdr_end];
    let body_bytes = &all[hdr_end + 4..];
    let status = parse_http_status(headers)?;
    if !(200..300).contains(&status) {
        bail!(
            "engine returned HTTP {status} ({} body bytes elided to avoid content logging)",
            body_bytes.len()
        );
    }
    // `Connection: close` + `read_to_end` means a chunked body arrives
    // whole; dechunk it if the server framed it that way (NIO-based servers
    // such as mei do for buffered JSON, uvicorn does not).
    if headers_declare_chunked(headers) {
        return Ok(dechunk(body_bytes));
    }
    Ok(body_bytes.to_vec())
}

fn headers_declare_chunked(headers: &[u8]) -> bool {
    std::str::from_utf8(headers).is_ok_and(|s| {
        s.lines().skip(1).any(|l| {
            let lower = l.to_ascii_lowercase();
            lower.starts_with("transfer-encoding:") && lower.contains("chunked")
        })
    })
}

/// Decode a complete `Transfer-Encoding: chunked` body. Tolerant: a
/// malformed size line ends decoding with whatever was collected.
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0usize;
    while i < body.len() {
        let Some(nl) = body[i..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let size_line = std::str::from_utf8(&body[i..i + nl]).unwrap_or("").trim();
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_hex, 16) else {
            break;
        };
        i += nl + 1;
        if size == 0 {
            break;
        }
        let end = (i + size).min(body.len());
        out.extend_from_slice(&body[i..end]);
        i = end + 2; // skip trailing CRLF
    }
    out
}

/// Streamed HTTP/1.1 POST. Parses the SSE body incrementally, forwarding
/// channel-tagged deltas to `on_delta`, and returns `(prompt_tokens,
/// completion_tokens)` from the terminal `usage` (zeros when the server
/// omitted it — the caller estimates then).
///
/// Two time budgets: `HTTP_TIMEOUT` until the first meaningful delta,
/// `HTTP_STREAM_IDLE_TIMEOUT` between reads after that. Chunked
/// transfer framing is stripped on the fly.
pub fn http_post_stream(
    stream: &mut dyn EngineStream,
    host: &str,
    path: &str,
    body: &[u8],
    start_in_reasoning: bool,
    on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
) -> Result<(u64, u64)> {
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(HTTP_STREAM_READ_POLL))?;
    write_request_head(stream, host, path, body.len())?;
    stream
        .write_all(body)
        .context("writing HTTP request body")?;
    stream.flush().ok();

    let mut buf = Vec::new();
    let mut read_buf = [0u8; 4096];
    let mut header_end: Option<usize> = None;
    let mut chunked = false;
    let mut dechunker = Dechunker::default();
    let mut sse_body: Vec<u8> = Vec::new();
    let mut body_cursor = 0usize;
    let mut tokens = (0u64, 0u64);
    let mut splitter = if start_in_reasoning {
        ThinkTagSplitter::new_in_reasoning()
    } else {
        ThinkTagSplitter::new()
    };

    let started = Instant::now();
    let mut last_progress = Instant::now();
    let mut meaningful_stream_started = false;

    loop {
        let n = match stream.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if meaningful_stream_started {
                    if last_progress.elapsed() > HTTP_STREAM_IDLE_TIMEOUT {
                        bail!(
                            "engine stream stalled (no bytes for {}s)",
                            HTTP_STREAM_IDLE_TIMEOUT.as_secs()
                        );
                    }
                } else if started.elapsed() > HTTP_TIMEOUT {
                    bail!(
                        "engine produced no output within {}s",
                        HTTP_TIMEOUT.as_secs()
                    );
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let read_at = Instant::now();

        if header_end.is_none() {
            buf.extend_from_slice(&read_buf[..n]);
            if let Some(end) = find_header_end(&buf) {
                let headers = &buf[..end.saturating_sub(4)];
                let status = parse_http_status(headers)?;
                if !(200..300).contains(&status) {
                    bail!(
                        "engine returned HTTP {status} (streaming body elided to avoid content logging)"
                    );
                }
                chunked = headers_declare_chunked(headers);
                header_end = Some(end);
                let first_body = buf[end..].to_vec();
                buf.clear();
                if chunked {
                    dechunker.feed(&first_body, &mut sse_body);
                } else {
                    sse_body.extend_from_slice(&first_body);
                }
            } else {
                continue;
            }
        } else if chunked {
            dechunker.feed(&read_buf[..n], &mut sse_body);
        } else {
            sse_body.extend_from_slice(&read_buf[..n]);
        }

        let emitted_delta = process_sse_buffer(
            &mut sse_body,
            &mut body_cursor,
            &mut splitter,
            on_delta,
            &mut tokens,
        )?;
        if emitted_delta {
            meaningful_stream_started = true;
        }
        if meaningful_stream_started {
            last_progress = read_at;
        }
    }
    splitter.finish(on_delta)?;
    Ok(tokens)
}

/// Incremental `Transfer-Encoding: chunked` decoder for the streaming path.
#[derive(Default)]
struct Dechunker {
    pending: Vec<u8>,
    /// Bytes still owed by the current chunk (0 = expecting a size line).
    remaining: usize,
    done: bool,
}

impl Dechunker {
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) {
        if self.done {
            return;
        }
        self.pending.extend_from_slice(input);
        loop {
            if self.remaining > 0 {
                let take = self.remaining.min(self.pending.len());
                out.extend_from_slice(&self.pending[..take]);
                self.pending.drain(..take);
                self.remaining -= take;
                if self.remaining > 0 {
                    return;
                }
            }
            // Strip the CRLF that trails each chunk (it may arrive in a
            // later read, in which case the next call strips it).
            while self.pending.starts_with(b"\r\n") {
                self.pending.drain(..2);
            }
            let Some(nl) = self.pending.iter().position(|&b| b == b'\n') else {
                return;
            };
            let size_line = std::str::from_utf8(&self.pending[..nl])
                .unwrap_or("")
                .trim()
                .to_string();
            let size_hex = size_line.split(';').next().unwrap_or("").trim();
            let Ok(size) = usize::from_str_radix(size_hex, 16) else {
                // Not a size line we understand; pass bytes through verbatim
                // rather than dropping a stream that may still be usable.
                out.extend_from_slice(&self.pending);
                self.pending.clear();
                return;
            };
            self.pending.drain(..nl + 1);
            if size == 0 {
                self.done = true;
                return;
            }
            self.remaining = size;
        }
    }
}

/// Probe `GET /v1/models` on an already-connected stream. Any 2xx status
/// line means the server is up and answering requests; everything else
/// (refused, 503, timeout, garbage) reads as "not yet".
pub fn probe_models_ready(stream: &mut dyn EngineStream, host: &str) -> bool {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let req = format!("GET /v1/models HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let _ = stream.flush();
    let mut buf = [0u8; 256];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return false,
    };
    let Ok(s) = std::str::from_utf8(&buf[..n]) else {
        return false;
    };
    s.starts_with("HTTP/1.1 2") || s.starts_with("HTTP/1.0 2")
}

/// Parse a buffered `chat.completions` response into the trait's result.
pub fn parse_once_response(resp_bytes: &[u8]) -> Result<GenerateResponse> {
    let resp: serde_json::Value = serde_json::from_slice(resp_bytes).with_context(|| {
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

// ---------------------------------------------------------------------------
// Startup canaries. Cocore intentionally does NOT maintain a model-family
// capability matrix: the engine proves what it can do at startup, and only
// what it proves is advertised (`tool_call_models`, `structured_output_models`
// on the Register frame).
// ---------------------------------------------------------------------------

/// Forced-function-call request. Passing requires an actual OpenAI-style
/// `message.tool_calls` reply naming `report_status` with `{"status":"ok"}`.
pub fn tool_canary_body(model: &str) -> serde_json::Value {
    serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a tool-calling canary. When a tool is forced, return exactly that tool call and no prose."
            },
            {
                "role": "user",
                "content": "Call report_status with status set to ok."
            }
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "report_status",
                    "description": "Report the tool-calling canary status.",
                    "strict": true,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "status": { "type": "string" }
                        },
                        "required": ["status"],
                        "additionalProperties": false
                    }
                }
            }
        ],
        "tool_choice": { "type": "function", "function": { "name": "report_status" } },
        "max_tokens": 96,
        "temperature": 0,
    })
}

pub fn tool_canary_passed(resp: &serde_json::Value) -> bool {
    resp.pointer("/choices/0/message/tool_calls")
        .and_then(|v| v.as_array())
        .is_some_and(|calls| {
            calls.iter().any(|call| {
                call.pointer("/function/name").and_then(|v| v.as_str()) == Some("report_status")
                    && call
                        .pointer("/function/arguments")
                        .and_then(|v| v.as_str())
                        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                        == Some(serde_json::json!({ "status": "ok" }))
            })
        })
}

/// Structured-output request: a `response_format: json_schema` with one
/// required field. The prompt deliberately begs for prose so a server that
/// silently ignores `response_format` (mei ≤ 0.5.0 drops unknown keys and
/// answers in free text, HTTP 200) fails the canary instead of passing by
/// luck. Constrained decoding, when honoured, cannot produce anything but
/// the schema.
pub fn structured_output_canary_body(model: &str) -> serde_json::Value {
    serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a friendly assistant who always answers in two or three warm, conversational sentences."
            },
            {
                "role": "user",
                "content": "Say hello and tell me how you are doing today."
            }
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "canary_status",
                "strict": true,
                "schema": {
                    "type": "object",
                    "properties": {
                        "status": { "type": "string", "enum": ["ok"] }
                    },
                    "required": ["status"],
                    "additionalProperties": false
                }
            }
        },
        "max_tokens": 64,
        "temperature": 0,
    })
}

/// Passing = the whole `message.content` parses as a JSON object whose
/// `status` is exactly `"ok"` and which has no other keys.
pub fn structured_output_canary_passed(resp: &serde_json::Value) -> bool {
    let Some(content) = resp
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
    else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(content.trim()) else {
        return false;
    };
    let Some(obj) = v.as_object() else {
        return false;
    };
    obj.len() == 1 && obj.get("status").and_then(|s| s.as_str()) == Some("ok")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_reassembles_a_complete_chunked_body() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(dechunk(body), b"hello world");
    }

    #[test]
    fn dechunker_handles_chunks_split_across_reads() {
        let mut d = Dechunker::default();
        let mut out = Vec::new();
        d.feed(b"c\r\ndata: {\"a", &mut out);
        d.feed(b"\"}\n\r\n4\r\n", &mut out);
        d.feed(b"more\r\n0\r\n\r\n", &mut out);
        assert_eq!(out, b"data: {\"a\"}\nmore");
        assert!(d.done);
    }

    #[test]
    fn dechunker_tolerates_chunk_extensions_and_uppercase_hex() {
        let mut d = Dechunker::default();
        let mut out = Vec::new();
        d.feed(b"A;ext=1\r\n0123456789\r\n0\r\n\r\n", &mut out);
        assert_eq!(out, b"0123456789");
    }

    #[test]
    fn chunked_header_detection_is_case_insensitive() {
        assert!(headers_declare_chunked(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\nContent-Type: text/event-stream"
        ));
        assert!(!headers_declare_chunked(
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: application/json"
        ));
    }

    #[test]
    fn build_chat_body_never_adds_stream_options_unless_asked() {
        let req = GenerateRequest {
            model: "m".into(),
            messages: vec![Message::text("user", "hi")],
            max_tokens: 8,
            temperature: None,
            top_p: None,
            guided_json: None,
            tools: None,
            tool_choice: None,
        };
        let mut streamed = build_chat_body(&req, true).unwrap();
        assert!(streamed.get("stream_options").is_none());
        request_stream_usage(&mut streamed);
        assert_eq!(
            streamed["stream_options"]["include_usage"],
            serde_json::json!(true)
        );
    }

    fn so_response(content: &str) -> serde_json::Value {
        serde_json::json!({ "choices": [{ "message": { "role": "assistant", "content": content } }] })
    }

    #[test]
    fn structured_output_canary_requires_exact_schema_shape() {
        assert!(structured_output_canary_passed(&so_response(
            r#"{"status":"ok"}"#
        )));
        assert!(structured_output_canary_passed(&so_response(
            "  {\"status\": \"ok\"}\n"
        )));
        // Free prose (server ignored response_format) fails.
        assert!(!structured_output_canary_passed(&so_response(
            "Hello! I'm doing great today, thanks for asking."
        )));
        // Right key, wrong value.
        assert!(!structured_output_canary_passed(&so_response(
            r#"{"status":"fine"}"#
        )));
        // Extra keys violate additionalProperties.
        assert!(!structured_output_canary_passed(&so_response(
            r#"{"status":"ok","mood":"good"}"#
        )));
        // JSON embedded in prose is not constrained decoding.
        assert!(!structured_output_canary_passed(&so_response(
            "Sure! {\"status\":\"ok\"}"
        )));
        // Missing content entirely.
        assert!(!structured_output_canary_passed(
            &serde_json::json!({ "choices": [] })
        ));
    }

    #[test]
    fn structured_output_canary_body_carries_json_schema_envelope() {
        let body = structured_output_canary_body("m");
        assert_eq!(body["response_format"]["type"], "json_schema");
        assert_eq!(
            body["response_format"]["json_schema"]["schema"]["required"][0],
            "status"
        );
        assert_eq!(body["model"], "m");
    }
}
