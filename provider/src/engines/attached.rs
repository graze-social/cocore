//! Attached engine: serve a model through an OpenAI-compatible HTTP server
//! the operator already runs on this machine.
//!
//! The subprocess engine owns its backend end to end (spawn the Python
//! child, download weights, watch the socket). An attached engine owns
//! nothing — it is handed a `http://host:port` and a model id, proves the
//! server is up and what it can do, and proxies jobs to it. That is the
//! shape a provider needs when the best engine for their hardware is not
//! the one we bundle: `mei` (native Swift/MLX, ~4× vllm-mlx's decode speed
//! on an M1), `mlx_lm.server`, `llama-server`, LM Studio's server, and so
//! on. Issue #204 asked for exactly this seam.
//!
//! Configuration is one map from model id to base URL (see [`EngineMap`]):
//!
//! ```text
//! COCORE_ENGINE_MAP="mlx-community/Qwen3.6-35B-A3B-4bit=http://127.0.0.1:8024"
//! ```
//!
//! or, for tray installs where env vars are awkward, the same entries one
//! per line in `~/.cocore/engine-map`. A model in the map is served by the
//! attached engine and is REMOVED from the vllm-mlx subprocess set even if
//! it is also listed in `COCORE_INFERENCE_MODELS`; a machine whose every
//! model is attached never needs the Python venv at all.
//!
//! What the agent still guarantees for an attached model:
//!
//!   * readiness is `GET /v1/models` answering 2xx, re-probed by the serve
//!     loop's health tick like any engine, so a server that goes away is
//!     de-advertised within a tick rather than sinking jobs;
//!   * tool calling is advertised only after the same forced-tool canary
//!     the subprocess engine runs;
//!   * structured output is advertised only after a `response_format`
//!     canary — a server that silently ignores the field (mei ≤ 0.5.0) would
//!     otherwise return free prose with HTTP 200 for a schema-constrained
//!     job; jobs that need it are refused with a typed rejection instead;
//!   * the confidential tier is unaffected: like the subprocess engine this
//!     is `in_process() == false`, so the machine stays best-effort.
//!
//! What it deliberately does not do: spawn or restart the server (that is
//! the operator's, or a later managed engine's, job), speak HTTPS (the
//! hand-rolled client is HTTP/1.1 only and the server is meant to be on
//! loopback — a non-loopback target is accepted with a loud warning, since
//! the decrypted prompt would then leave the machine in the clear).

use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeMap;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::engines::openai_http::{
    self, build_chat_body, http_post, http_post_stream, parse_once_response, probe_models_ready,
    request_stream_usage, structured_output_canary_body, structured_output_canary_passed,
    tool_canary_body, tool_canary_passed,
};
use crate::engines::{
    model_prefills_think, DeltaChannel, Engine, EngineRejection, GenerateRequest, GenerateResponse,
};

/// Dial timeout for every connection to the attached server.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `start()` waits for the server to answer `GET /v1/models`
/// before giving up on the model for this serve. A native server loading a
/// ~20 GB checkpoint from a cold page cache can take a couple of minutes;
/// this is generous but bounded so a misconfigured URL doesn't stall the
/// whole engine build. Override with `COCORE_ATTACHED_READY_TIMEOUT` (secs).
const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(300);

/// `ready()` is called from several places per health tick; cache a probe
/// result briefly so a burst of callers costs one TCP round trip.
const READY_CACHE: Duration = Duration::from_secs(2);

/// Where the tray-friendly map lives when the env var is not set.
pub const ENGINE_MAP_FILE: &str = ".cocore/engine-map";
pub const ENGINE_MAP_ENV: &str = "COCORE_ENGINE_MAP";

/// A parsed `http://host:port[/prefix]` base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedTarget {
    pub host: String,
    pub port: u16,
    /// Path mounted before `/v1/...`, without a trailing slash (`""` for none).
    pub path_prefix: String,
}

impl AttachedTarget {
    /// Parse a base URL. Accepts `http://host[:port][/prefix]` and a bare
    /// `host:port`; defaults the port to 80 only when a scheme was given.
    /// Rejects `https://` (no TLS in this client) and a trailing `/v1`
    /// (the client appends `/v1/...` itself).
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            bail!("empty engine URL");
        }
        let lower = raw.to_ascii_lowercase();
        if lower.starts_with("https://") {
            bail!(
                "attached engine URL {raw:?} uses https; the agent speaks plain HTTP/1.1 to a server on this machine — point it at http://127.0.0.1:<port>"
            );
        }
        let (had_scheme, rest) = match lower.strip_prefix("http://") {
            Some(_) => (true, &raw[7..]),
            None => {
                if raw.contains("://") {
                    bail!("attached engine URL {raw:?} has an unsupported scheme; use http://");
                }
                (false, raw)
            }
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        if authority.is_empty() {
            bail!("attached engine URL {raw:?} has no host");
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(']') || h.ends_with(']') => {
                let port: u16 = p
                    .parse()
                    .with_context(|| format!("attached engine URL {raw:?}: bad port {p:?}"))?;
                (h.trim_matches(|c| c == '[' || c == ']').to_string(), port)
            }
            _ => {
                if !had_scheme {
                    bail!("attached engine URL {raw:?} needs a port (e.g. http://127.0.0.1:8024)");
                }
                (
                    authority.trim_matches(|c| c == '[' || c == ']').to_string(),
                    80,
                )
            }
        };
        if host.is_empty() {
            bail!("attached engine URL {raw:?} has no host");
        }
        if path.eq_ignore_ascii_case("/v1") {
            bail!(
                "attached engine URL {raw:?} ends in /v1; give the server root instead (the agent appends /v1/chat/completions itself)"
            );
        }
        Ok(Self {
            host,
            port,
            path_prefix: path.to_string(),
        })
    }

    /// `Host:` header value.
    pub fn host_header(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Whether the server is on this machine.
    pub fn is_loopback(&self) -> bool {
        if self.host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        self.host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    }

    fn path(&self, route: &str) -> String {
        format!("{}{}", self.path_prefix, route)
    }
}

impl std::fmt::Display for AttachedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http://{}:{}{}", self.host, self.port, self.path_prefix)
    }
}

/// Model id → attached server. Parsed from `COCORE_ENGINE_MAP`
/// (`model=url,model=url`; `;` and newlines also separate entries) or from
/// `~/.cocore/engine-map` (one `model = url` per line, `#` comments).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineMap(BTreeMap<String, AttachedTarget>);

impl EngineMap {
    pub fn parse(raw: &str) -> Result<Self> {
        let mut map = BTreeMap::new();
        for entry in raw.split([',', ';', '\n']) {
            let entry = entry.trim();
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }
            let Some((model, url)) = entry.split_once('=') else {
                bail!("engine map entry {entry:?} is not `model=url`");
            };
            let model = model.trim();
            if model.is_empty() {
                bail!("engine map entry {entry:?} has an empty model id");
            }
            if model.eq_ignore_ascii_case("stub") {
                bail!("engine map may not remap the built-in `stub` model");
            }
            let target = AttachedTarget::parse(url)
                .with_context(|| format!("engine map entry for model {model:?}"))?;
            if map.insert(model.to_string(), target).is_some() {
                bail!("engine map lists model {model:?} twice");
            }
        }
        Ok(Self(map))
    }

    /// Env var first, then the file; an absent/empty source is an empty map.
    /// A malformed source is an error — a typo must not silently fall back
    /// to spawning vllm-mlx for a model the operator meant to attach.
    pub fn from_env_or_file() -> Result<Self> {
        if let Ok(raw) = std::env::var(ENGINE_MAP_ENV) {
            if !raw.trim().is_empty() {
                return Self::parse(&raw).context(ENGINE_MAP_ENV);
            }
        }
        let Some(path) = Self::file_path() else {
            return Ok(Self::default());
        };
        match std::fs::read_to_string(&path) {
            Ok(raw) => Self::parse(&raw).with_context(|| path.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow!(e).context(format!("reading {}", path.display()))),
        }
    }

    pub fn file_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(ENGINE_MAP_FILE))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, model: &str) -> bool {
        self.0.contains_key(model)
    }

    pub fn get(&self, model: &str) -> Option<&AttachedTarget> {
        self.0.get(model)
    }

    pub fn models(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &AttachedTarget)> {
        self.0.iter()
    }
}

pub struct AttachedEngine {
    model_id: String,
    target: AttachedTarget,
    verified_tool_calls: Mutex<bool>,
    verified_structured_output: Mutex<bool>,
    ready_cache: Mutex<Option<(Instant, bool)>>,
}

impl AttachedEngine {
    pub fn new(model_id: impl Into<String>, target: AttachedTarget) -> Self {
        let model_id = model_id.into();
        if !target.is_loopback() {
            tracing::warn!(
                model = %model_id,
                target = %target,
                "attached engine is NOT on loopback: decrypted prompts and replies will cross the network in plaintext to that host"
            );
        }
        Self {
            model_id,
            target,
            verified_tool_calls: Mutex::new(false),
            verified_structured_output: Mutex::new(false),
            ready_cache: Mutex::new(None),
        }
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn target(&self) -> &AttachedTarget {
        &self.target
    }

    fn connect(&self) -> Result<TcpStream> {
        let addrs: Vec<_> = (self.target.host.as_str(), self.target.port)
            .to_socket_addrs()
            .with_context(|| format!("resolving attached engine host {}", self.target))?
            .collect();
        let mut last = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(anyhow!(
            "connecting to attached engine {}: {}",
            self.target,
            last.map(|e| e.to_string())
                .unwrap_or_else(|| "no addresses".to_string())
        ))
    }

    fn probe(&self) -> bool {
        let Ok(mut stream) = self.connect() else {
            return false;
        };
        probe_models_ready(&mut stream, &self.target.host_header())
    }

    fn post(&self, route: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.connect()?;
        http_post(
            &mut stream,
            &self.target.host_header(),
            &self.target.path(route),
            body,
        )
    }

    fn ready_timeout() -> Duration {
        std::env::var("COCORE_ATTACHED_READY_TIMEOUT")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_READY_TIMEOUT)
    }

    /// Wait for the server to answer, then run the capability canaries.
    /// Idempotent; re-running re-verifies.
    pub fn start(&self) -> Result<()> {
        let timeout = Self::ready_timeout();
        let started = Instant::now();
        let mut last_log = Instant::now() - Duration::from_secs(60);
        loop {
            if self.probe() {
                break;
            }
            if started.elapsed() > timeout {
                bail!(
                    "attached engine {} did not answer GET /v1/models within {}s (is the server running and listening on that port?)",
                    self.target,
                    timeout.as_secs()
                );
            }
            if last_log.elapsed() >= Duration::from_secs(15) {
                tracing::info!(
                    model = %self.model_id,
                    target = %self.target,
                    waited_s = started.elapsed().as_secs(),
                    "waiting for attached engine to answer /v1/models"
                );
                last_log = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        tracing::info!(model = %self.model_id, target = %self.target, "attached engine is answering");
        self.set_ready_cache(true);

        let skip_canaries = std::env::var("COCORE_ATTACHED_SKIP_CANARIES")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let (tools, structured) = if skip_canaries {
            tracing::warn!(model = %self.model_id, "COCORE_ATTACHED_SKIP_CANARIES set; advertising neither tool calling nor structured output");
            (false, false)
        } else {
            (self.run_tool_canary(), self.run_structured_output_canary())
        };
        if let Ok(mut v) = self.verified_tool_calls.lock() {
            *v = tools;
        }
        if let Ok(mut v) = self.verified_structured_output.lock() {
            *v = structured;
        }
        Ok(())
    }

    fn run_tool_canary(&self) -> bool {
        let body = Zeroizing::new(
            match serde_json::to_vec(&tool_canary_body(&self.model_id)) {
                Ok(b) => b,
                Err(_) => return false,
            },
        );
        match self.post("/v1/chat/completions", &body).and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(Into::into)
        }) {
            Ok(resp) => {
                let ok = tool_canary_passed(&resp);
                tracing::info!(model = %self.model_id, passed = ok, "attached engine tool-calling canary");
                ok
            }
            Err(e) => {
                tracing::warn!(model = %self.model_id, error = %e, "attached engine tool-calling canary failed; not advertising tool support");
                false
            }
        }
    }

    fn run_structured_output_canary(&self) -> bool {
        let body = Zeroizing::new(
            match serde_json::to_vec(&structured_output_canary_body(&self.model_id)) {
                Ok(b) => b,
                Err(_) => return false,
            },
        );
        match self.post("/v1/chat/completions", &body).and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(Into::into)
        }) {
            Ok(resp) => {
                let ok = structured_output_canary_passed(&resp);
                if ok {
                    tracing::info!(model = %self.model_id, "attached engine structured-output canary passed");
                } else {
                    tracing::warn!(
                        model = %self.model_id,
                        "attached engine ignored or failed response_format json_schema; structured-output jobs will be refused for this model"
                    );
                }
                ok
            }
            Err(e) => {
                tracing::warn!(model = %self.model_id, error = %e, "attached engine structured-output canary errored; not advertising structured output");
                false
            }
        }
    }

    pub fn verified_tool_calls(&self) -> bool {
        self.verified_tool_calls.lock().map(|v| *v).unwrap_or(false)
    }

    pub fn verified_structured_output(&self) -> bool {
        self.verified_structured_output
            .lock()
            .map(|v| *v)
            .unwrap_or(false)
    }

    fn set_ready_cache(&self, ready: bool) {
        if let Ok(mut c) = self.ready_cache.lock() {
            *c = Some((Instant::now(), ready));
        }
    }

    fn check_structured_output(&self, request: &GenerateRequest) -> Result<()> {
        if request.guided_json.is_some() && !self.verified_structured_output() {
            return Err(EngineRejection::StructuredOutputUnsupported {
                model: self.model_id.clone(),
            }
            .into());
        }
        Ok(())
    }
}

impl Engine for AttachedEngine {
    fn name(&self) -> &'static str {
        "attached-openai"
    }

    fn ready(&self) -> bool {
        if let Ok(c) = self.ready_cache.lock() {
            if let Some((at, ready)) = *c {
                if at.elapsed() < READY_CACHE {
                    return ready;
                }
            }
        }
        let ready = self.probe();
        self.set_ready_cache(ready);
        ready
    }

    /// Nothing to respawn — the server is the operator's. Re-probe so the
    /// health loop's `ready()` re-check reflects the current state.
    fn restart(&self) -> Result<()> {
        let ready = self.probe();
        self.set_ready_cache(ready);
        if ready {
            tracing::info!(model = %self.model_id, target = %self.target, "attached engine is answering again");
        } else {
            tracing::warn!(
                model = %self.model_id,
                target = %self.target,
                "attached engine is not answering; the agent does not manage that server — restart it and the model will be re-advertised on the next health tick"
            );
        }
        Ok(())
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        self.check_structured_output(request)?;
        let body = build_chat_body(request, false)?;
        let body_bytes = Zeroizing::new(serde_json::to_vec(&body)?);
        let resp_bytes = self.post("/v1/chat/completions", &body_bytes)?;
        parse_once_response(&resp_bytes)
    }

    fn generate_stream(
        &self,
        request: &GenerateRequest,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        self.check_structured_output(request)?;
        let mut body = build_chat_body(request, true)?;
        request_stream_usage(&mut body);
        let body_bytes = Zeroizing::new(serde_json::to_vec(&body)?);
        let mut stream = self.connect()?;
        let (tokens_in, tokens_out) = http_post_stream(
            &mut stream,
            &self.target.host_header(),
            &self.target.path("/v1/chat/completions"),
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

// Re-exported so `main.rs` can size the gate from one place.
pub use openai_http::HTTP_TIMEOUT as ATTACHED_REQUEST_TIMEOUT;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::{rejection_of, Message};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // ---- URL / map parsing -------------------------------------------------

    #[test]
    fn parses_loopback_urls_with_and_without_scheme() {
        let t = AttachedTarget::parse("http://127.0.0.1:8024").unwrap();
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 8024);
        assert_eq!(t.path_prefix, "");
        assert!(t.is_loopback());
        assert_eq!(t.host_header(), "127.0.0.1:8024");

        let t = AttachedTarget::parse("localhost:8080/").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.path_prefix.as_str()),
            ("localhost", 8080, "")
        );
        assert!(t.is_loopback());

        let t = AttachedTarget::parse("http://[::1]:9000/llm").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.path_prefix.as_str()),
            ("::1", 9000, "/llm")
        );
        assert!(t.is_loopback());
        assert_eq!(t.path("/v1/models"), "/llm/v1/models");
    }

    #[test]
    fn rejects_https_bad_ports_missing_ports_and_v1_suffix() {
        assert!(AttachedTarget::parse("https://127.0.0.1:8024").is_err());
        assert!(AttachedTarget::parse("http://127.0.0.1:notaport").is_err());
        assert!(AttachedTarget::parse("127.0.0.1").is_err());
        assert!(AttachedTarget::parse("http://127.0.0.1:8024/v1").is_err());
        assert!(AttachedTarget::parse("ftp://127.0.0.1:1").is_err());
        assert!(AttachedTarget::parse("").is_err());
        // scheme without port defaults to 80
        assert_eq!(AttachedTarget::parse("http://127.0.0.1").unwrap().port, 80);
    }

    #[test]
    fn non_loopback_is_detected() {
        assert!(!AttachedTarget::parse("http://192.168.1.20:8024")
            .unwrap()
            .is_loopback());
        assert!(!AttachedTarget::parse("http://mei.lan:8024")
            .unwrap()
            .is_loopback());
    }

    #[test]
    fn engine_map_parses_env_and_file_forms() {
        let m = EngineMap::parse(
            "mlx-community/Qwen3.6-35B-A3B-4bit=http://127.0.0.1:8024, ornith-ai/Ornith-1.5-35B-A3B-MLX-4bit = http://127.0.0.1:8025",
        )
        .unwrap();
        assert_eq!(m.models().len(), 2);
        assert_eq!(
            m.get("mlx-community/Qwen3.6-35B-A3B-4bit").unwrap().port,
            8024
        );
        assert_eq!(
            m.get("ornith-ai/Ornith-1.5-35B-A3B-MLX-4bit").unwrap().port,
            8025
        );

        let file = "# Tijs's Mac Studio\nmlx-community/Qwen3.6-35B-A3B-4bit = http://127.0.0.1:8024\n\n# second server\nfoo/bar=localhost:9000\n";
        let m = EngineMap::parse(file).unwrap();
        assert_eq!(
            m.models(),
            vec![
                "foo/bar".to_string(),
                "mlx-community/Qwen3.6-35B-A3B-4bit".to_string()
            ]
        );
        assert!(m.contains("foo/bar"));
        assert!(EngineMap::parse("").unwrap().is_empty());
        assert!(EngineMap::parse("   \n# only a comment\n")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn engine_map_rejects_malformed_duplicate_and_stub_entries() {
        assert!(EngineMap::parse("no-equals-sign").is_err());
        assert!(EngineMap::parse("=http://127.0.0.1:1").is_err());
        assert!(EngineMap::parse("a=http://127.0.0.1:1,a=http://127.0.0.1:2").is_err());
        assert!(EngineMap::parse("stub=http://127.0.0.1:1").is_err());
        assert!(EngineMap::parse("a=https://127.0.0.1:1").is_err());
    }

    // ---- fake OpenAI-compatible server --------------------------------------

    #[derive(Clone, Copy)]
    enum SchemaMode {
        /// Honour response_format (constrained JSON).
        Honour,
        /// Ignore it and answer in prose, like mei ≤ 0.5.0.
        Ignore,
    }

    struct FakeServer {
        port: u16,
        requests: Arc<AtomicUsize>,
    }

    fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let head_end;
        loop {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                panic!("client closed before headers");
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                head_end = i + 4;
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let len = head
            .lines()
            .find_map(|l| {
                let lower = l.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut body = buf[head_end..].to_vec();
        while body.len() < len {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        (head, body)
    }

    fn write_json(stream: &mut TcpStream, status: u16, body: &str) {
        // Chunked, like a NIO server framing a buffered JSON reply.
        let resp = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).unwrap();
    }

    fn spawn_server(mode: SchemaMode, tools_ok: bool) -> FakeServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                let (head, body) = read_request(&mut stream);
                let first = head.lines().next().unwrap_or("").to_string();
                if first.starts_with("GET /v1/models") {
                    write_json(
                        &mut stream,
                        200,
                        r#"{"object":"list","data":[{"id":"m","object":"model"}]}"#,
                    );
                    continue;
                }
                if !first.starts_with("POST /v1/chat/completions") {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                }
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let streaming = req["stream"].as_bool().unwrap_or(false);
                if req.get("tool_choice").is_some() && !streaming {
                    let reply = if tools_ok {
                        r#"{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"report_status","arguments":"{\"status\":\"ok\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":20,"completion_tokens":5}}"#
                    } else {
                        r#"{"choices":[{"message":{"role":"assistant","content":"I would call report_status here."},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":8}}"#
                    };
                    write_json(&mut stream, 200, reply);
                    continue;
                }
                if req.get("response_format").is_some() && !streaming {
                    let reply = match mode {
                        SchemaMode::Honour => {
                            r#"{"choices":[{"message":{"role":"assistant","content":"{\"status\":\"ok\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":30,"completion_tokens":6}}"#
                        }
                        SchemaMode::Ignore => {
                            r#"{"choices":[{"message":{"role":"assistant","content":"Hello there! I'm doing wonderfully today, thank you for asking."},"finish_reason":"stop"}],"usage":{"prompt_tokens":30,"completion_tokens":14}}"#
                        }
                    };
                    write_json(&mut stream, 200, reply);
                    continue;
                }
                if streaming {
                    // Assert the usage chunk was requested, as the OpenAI
                    // contract requires for streams.
                    assert_eq!(
                        req["stream_options"]["include_usage"],
                        serde_json::json!(true)
                    );
                    let chunks = [
                        r#"data: {"choices":[{"delta":{"role":"assistant","content":""}}]}"#,
                        r#"data: {"choices":[{"delta":{"reasoning_content":"thinking…"}}]}"#,
                        r#"data: {"choices":[{"delta":{"content":"Hello"}}]}"#,
                        r#"data: {"choices":[{"delta":{"content":" world"}}]}"#,
                        r#"data: {"choices":[{"delta":{},"finish_reason":"stop"}]}"#,
                        r#"data: {"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":2}}"#,
                        "data: [DONE]",
                    ];
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                        .unwrap();
                    for c in chunks {
                        let frame = format!("{c}\n\n");
                        // Split one frame across two chunks to exercise the
                        // incremental dechunker.
                        let (a, b) = frame.split_at(frame.len() / 2);
                        for part in [a, b] {
                            stream
                                .write_all(format!("{:x}\r\n{}\r\n", part.len(), part).as_bytes())
                                .unwrap();
                        }
                    }
                    stream.write_all(b"0\r\n\r\n").unwrap();
                    continue;
                }
                write_json(
                    &mut stream,
                    200,
                    r#"{"choices":[{"message":{"role":"assistant","content":"buffered reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#,
                );
            }
        });
        FakeServer { port, requests }
    }

    fn engine_for(server: &FakeServer) -> AttachedEngine {
        AttachedEngine::new(
            "m",
            AttachedTarget::parse(&format!("http://127.0.0.1:{}", server.port)).unwrap(),
        )
    }

    fn req(guided: bool) -> GenerateRequest {
        GenerateRequest {
            model: "m".into(),
            messages: vec![Message::text("user", "hi")],
            max_tokens: 16,
            temperature: None,
            top_p: None,
            guided_json: guided
                .then(|| serde_json::json!({"name":"x","strict":true,"schema":{"type":"object"}})),
            tools: None,
            tool_choice: None,
        }
    }

    #[test]
    fn start_probes_ready_and_runs_both_canaries() {
        let server = spawn_server(SchemaMode::Honour, true);
        let engine = engine_for(&server);
        engine.start().unwrap();
        assert!(engine.ready());
        assert!(engine.verified_tool_calls());
        assert!(engine.verified_structured_output());
        // models probe + 2 canaries
        assert_eq!(server.requests.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn canaries_fail_honestly_when_the_server_ignores_them() {
        let server = spawn_server(SchemaMode::Ignore, false);
        let engine = engine_for(&server);
        engine.start().unwrap();
        assert!(!engine.verified_tool_calls());
        assert!(!engine.verified_structured_output());
    }

    #[test]
    fn streams_deltas_and_collects_usage_through_chunked_framing() {
        let server = spawn_server(SchemaMode::Honour, true);
        let engine = engine_for(&server);
        let mut got: Vec<(DeltaChannel, String)> = Vec::new();
        let resp = engine
            .generate_stream(&req(false), &mut |ch, s| {
                got.push((ch, s.to_string()));
                Ok(())
            })
            .unwrap();
        assert_eq!(resp.tokens_in, 11);
        assert_eq!(resp.tokens_out, 2);
        let content: String = got
            .iter()
            .filter(|(c, _)| *c == DeltaChannel::Content)
            .map(|(_, s)| s.as_str())
            .collect();
        assert_eq!(content, "Hello world");
        let reasoning: String = got
            .iter()
            .filter(|(c, _)| *c == DeltaChannel::Reasoning)
            .map(|(_, s)| s.as_str())
            .collect();
        assert_eq!(reasoning, "thinking…");
    }

    #[test]
    fn buffered_generate_parses_chunked_json() {
        let server = spawn_server(SchemaMode::Honour, true);
        let engine = engine_for(&server);
        let resp = engine.generate_once(&req(false)).unwrap();
        assert_eq!(resp.text, "buffered reply");
        assert_eq!((resp.tokens_in, resp.tokens_out), (7, 3));
    }

    #[test]
    fn structured_output_job_is_refused_typed_when_canary_failed() {
        let server = spawn_server(SchemaMode::Ignore, true);
        let engine = engine_for(&server);
        engine.start().unwrap();
        let before = server.requests.load(Ordering::SeqCst);
        let err = engine
            .generate_stream(&req(true), &mut |_, _| Ok(()))
            .expect_err("must refuse");
        match rejection_of(&err) {
            Some(EngineRejection::StructuredOutputUnsupported { model }) => assert_eq!(model, "m"),
            other => panic!("expected StructuredOutputUnsupported, got {other:?}"),
        }
        // Refused before any byte reached the server.
        assert_eq!(server.requests.load(Ordering::SeqCst), before);

        // Whereas a verified server takes the same job.
        let ok_server = spawn_server(SchemaMode::Honour, true);
        let ok_engine = engine_for(&ok_server);
        ok_engine.start().unwrap();
        assert!(ok_engine
            .generate_stream(&req(true), &mut |_, _| Ok(()))
            .is_ok());
    }

    #[test]
    fn ready_is_false_when_nothing_listens_and_start_times_out_fast_when_asked() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let engine = AttachedEngine::new(
            "m",
            AttachedTarget::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
        );
        assert!(!engine.ready());
        std::env::set_var("COCORE_ATTACHED_READY_TIMEOUT", "1");
        let started = Instant::now();
        let err = engine.start().expect_err("nothing listening → start fails");
        std::env::remove_var("COCORE_ATTACHED_READY_TIMEOUT");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(err.to_string().contains("did not answer"));
        // restart() is a no-op probe, never an error.
        assert!(engine.restart().is_ok());
    }
}
