//! Attached **decision** engine: serve a System-One decision model through a
//! `/v1/systemone` server the operator already runs on this machine.
//!
//! This is the sibling of [`attached`](super::attached), and it exists because
//! decision models are not chat models. Laya — the open reproduction of
//! TypeSafe's Jev — is a ModernBERT-large encoder (421M) plus a decision head:
//! it is **non-autoregressive**. Given a state and a map of typed questions it
//! scores every question in ONE encoder pass and returns calibrated
//! probabilities. There are no sampled tokens, no stream, and no
//! `/v1/chat/completions`. The published GGUFs are ggmlc-compiled and
//! explicitly refuse to load in llama.cpp, so the bundled vllm-mlx subprocess
//! engine cannot serve them either.
//!
//! What it *can* attach to is the same shape every attached engine uses — a
//! loopback HTTP server the operator runs:
//!
//! ```text
//! COCORE_DECISION_ENGINE_MAP="convaiinnovations/laya=http://127.0.0.1:11435"
//! ```
//!
//! or one `model = url` per line in `~/.cocore/decision-engine-map`. Known
//! servers that answer this wire format today: `ollaya serve` (port 11435),
//! `laya serve <model.gguf> --port 8080`, and Unsloth Desktop (port 8888).
//! All three speak `POST /v1/systemone` wire-identically to TypeSafe's hosted
//! API, and all three answer `GET /v1/models`, which is what the readiness
//! probe uses — the same probe the chat attached engine uses.
//!
//! ## How a decision rides the existing job pipeline
//!
//! The engine deliberately implements the ordinary [`Engine`] trait rather
//! than introducing a parallel dispatch path. The sealed prompt bytes ARE the
//! decision request (`{"state": ..., "questions": {...}}`) and the returned
//! text IS the answers envelope. That means a decision job reuses the whole
//! existing pipeline unchanged — job record, sealing, `inputCommitment`,
//! `outputCommitment`, receipt, settlement — with no lexicon change: the
//! commitment fields hash opaque bytes and do not care that those bytes are a
//! decision rather than prose.
//!
//! ## Why the output is re-serialized instead of proxied
//!
//! A decision is one deterministic encoder pass with no sampling, so two
//! providers running the same model over the same state produce the same
//! probabilities. That makes `outputCommitment` checkable **by replay**, which
//! it never is for autoregressive chat — the strongest verification property
//! in the system. It only holds if the bytes are canonical, so this engine
//! does not proxy the upstream JSON: it validates the answers and re-emits
//! them in a fixed field order with question ids and option keys sorted. Two
//! honest providers then agree byte for byte regardless of how their servers
//! happened to order JSON keys.
//!
//! ## What it deliberately does not do
//!
//! Spawn or manage the server (the operator's job, like every attached
//! engine), speak HTTPS (loopback plaintext only), stream (there is nothing to
//! stream), or advertise a distinct capability to the advisor. That last one
//! matters: until the Register frame carries a `decision_models` list, the
//! network can route an ordinary chat job to a decision model id, and this
//! engine answers it with a typed [`EngineRejection::DecisionRequestInvalid`]
//! — no receipt, no bill — exactly as the structured-output path refuses a
//! schema job on an engine that failed its canary.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::engines::attached::{AttachedTarget, EngineMap};
use crate::engines::{Engine, EngineRejection, GenerateRequest, GenerateResponse};

/// The one endpoint the System-One wire format defines.
const SYSTEMONE_ROUTE: &str = "/v1/systemone";

/// `ready()` is called from several places per health tick; cache a probe
/// result briefly so a burst of callers costs one TCP round trip.
const READY_CACHE: Duration = Duration::from_secs(2);

/// A decision server holds no multi-gigabyte checkpoint — Laya's largest
/// published weight file is ~807 MB — so readiness is quick or wrong.
const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(60);

pub const DECISION_ENGINE_MAP_ENV: &str = "COCORE_DECISION_ENGINE_MAP";
pub const DECISION_ENGINE_MAP_FILE: &str = ".cocore/decision-engine-map";

pub const MODEL_DIGESTS_ENV: &str = "COCORE_MODEL_DIGESTS";
pub const MODEL_DIGESTS_FILE: &str = ".cocore/model-digests";

/// Upper bound on `choice` options, from the System-One API reference.
const MAX_CHOICE_OPTIONS: usize = 255;
/// Ordered `score` levels, from the System-One API reference.
const MIN_SCORE_LEVELS: usize = 2;
const MAX_SCORE_LEVELS: usize = 10;

/// Model id → decision server. Same syntax and precedence as the chat engine
/// map; a separate source so a decision model is never confused for a chat
/// model by an operator editing one file.
pub fn decision_engine_map() -> Result<EngineMap> {
    EngineMap::from_sources(DECISION_ENGINE_MAP_ENV, DECISION_ENGINE_MAP_FILE)
}

/// Operator-declared model artifact digests, `model = <64 hex>` per line in
/// `COCORE_MODEL_DIGESTS` or `~/.cocore/model-digests`.
///
/// The operator is the one who pulled the weights, so they are the only party
/// on this machine that can compute `sha256sum` over them — an attached server
/// owns its own files and the agent never sees them. So this is a declaration
/// the agent relays, clearly, as a claim.
///
/// It is worth relaying despite being unverified because it is *falsifiable*:
/// a decision model is deterministic, so a requester who re-runs the named
/// artifact over the same input and gets different probabilities holds a
/// signed receipt that contradicts itself. A wrong digest is strictly worse
/// for the provider than no digest, which is why an honest one is the
/// equilibrium and why absence is allowed rather than defaulted.
///
/// Malformed entries are dropped with a warning rather than failing the serve:
/// a typo'd digest must not take a working machine offline, and the receipt
/// simply carries no claim.
pub fn model_digests() -> BTreeMap<String, String> {
    let raw = match std::env::var(MODEL_DIGESTS_ENV) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => match dirs::home_dir().map(|h| h.join(MODEL_DIGESTS_FILE)) {
            Some(path) => std::fs::read_to_string(path).unwrap_or_default(),
            None => String::new(),
        },
    };
    let mut out = BTreeMap::new();
    for entry in raw.split([',', ';', '\n']) {
        let entry = entry.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        let Some((model, digest)) = entry.split_once('=') else {
            tracing::warn!(entry = %entry, "model-digest entry is not `model=<sha256>`; ignoring");
            continue;
        };
        let model = model.trim();
        // Accept a `sha256:` prefix since that is how most tooling prints one.
        let digest = digest
            .trim()
            .trim_start_matches("sha256:")
            .to_ascii_lowercase();
        if model.is_empty() || !is_sha256_hex(&digest) {
            tracing::warn!(
                model = %model,
                "model-digest entry is not 64 lowercase hex characters; ignoring (the receipt will carry no digest claim for this model)"
            );
            continue;
        }
        out.insert(model.to_string(), digest);
    }
    out
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One typed question. `instructions` is `string | object | array` per the
/// API, so it stays a [`Value`]; what this type pins down is the shape of
/// `criteria`, which differs per question type and is what validation of the
/// ANSWER later depends on.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Question {
    /// Yes/no. Answered with a single probability that the statement is true.
    Noul {
        instructions: Value,
        #[serde(default)]
        criteria: Option<Value>,
    },
    /// Pick one of `criteria`'s keys. Answered with the pick + a distribution.
    Choice {
        instructions: Value,
        criteria: BTreeMap<String, Value>,
    },
    /// Rate against ordered levels. Answered with a number + a distribution.
    Score {
        instructions: Value,
        criteria: Vec<Value>,
    },
}

impl Question {
    fn kind(&self) -> &'static str {
        match self {
            Question::Noul { .. } => "noul",
            Question::Choice { .. } => "choice",
            Question::Score { .. } => "score",
        }
    }

    fn validate(&self, id: &str) -> Result<()> {
        let instructions = match self {
            Question::Noul { instructions, .. }
            | Question::Choice { instructions, .. }
            | Question::Score { instructions, .. } => instructions,
        };
        if instructions.is_null() {
            bail!("question {id:?} has no instructions");
        }
        if let Some(s) = instructions.as_str() {
            if s.trim().is_empty() {
                bail!("question {id:?} has empty instructions");
            }
        }
        match self {
            Question::Noul { .. } => {}
            Question::Choice { criteria, .. } => {
                if criteria.is_empty() {
                    bail!("choice question {id:?} has no options in criteria");
                }
                if criteria.len() > MAX_CHOICE_OPTIONS {
                    bail!(
                        "choice question {id:?} has {} options; the limit is {MAX_CHOICE_OPTIONS}",
                        criteria.len()
                    );
                }
            }
            Question::Score { criteria, .. } => {
                if criteria.len() < MIN_SCORE_LEVELS || criteria.len() > MAX_SCORE_LEVELS {
                    bail!(
                        "score question {id:?} has {} levels; the range is {MIN_SCORE_LEVELS}–{MAX_SCORE_LEVELS}",
                        criteria.len()
                    );
                }
            }
        }
        Ok(())
    }
}

/// A parsed decision request — the sealed prompt bytes of a decision job.
#[derive(Debug, Clone)]
pub struct DecisionRequest {
    /// What the caller asked for (`jev-latest`, `laya`, a repo id). Advisory:
    /// the engine serves the model the operator attached and says so in the
    /// response, so the receipt names the model that actually ran.
    pub requested_model: Option<String>,
    pub questions: BTreeMap<String, Question>,
    /// The original object, forwarded upstream with `model` overridden so a
    /// server that understands fields we don't still receives them.
    raw: Value,
}

impl DecisionRequest {
    /// Parse the sealed prompt as a decision request.
    ///
    /// A chat prompt reaching a decision engine lands here and fails with a
    /// message that says what the engine wanted, because that is the likeliest
    /// way this is misconfigured: a decision model id listed in
    /// `COCORE_INFERENCE_MODELS`, or the network routing chat at a decision
    /// model because no capability separates them yet.
    pub fn parse(prompt: &str) -> Result<Self> {
        let trimmed = prompt.trim();
        if trimmed.is_empty() {
            bail!("empty prompt; a decision request is a JSON object with `state` and `questions`");
        }
        let v: Value = serde_json::from_str(trimmed).map_err(|e| {
            anyhow!(
                "prompt is not a decision request (expected a JSON object with `state` and \
                 `questions`; this model serves /v1/systemone, not chat): {e}"
            )
        })?;
        let obj = v
            .as_object()
            .ok_or_else(|| anyhow!("decision request must be a JSON object"))?;
        if !obj.contains_key("state") {
            bail!("decision request is missing `state`");
        }
        let raw_questions = obj
            .get("questions")
            .ok_or_else(|| anyhow!("decision request is missing `questions`"))?
            .as_object()
            .ok_or_else(|| anyhow!("decision request `questions` must be an object"))?;
        if raw_questions.is_empty() {
            bail!("decision request has no questions");
        }
        let mut questions = BTreeMap::new();
        for (id, q) in raw_questions {
            let parsed: Question =
                serde_json::from_value(q.clone()).with_context(|| format!("question {id:?}"))?;
            parsed.validate(id)?;
            questions.insert(id.clone(), parsed);
        }
        Ok(Self {
            requested_model: obj
                .get("model")
                .and_then(|m| m.as_str())
                .map(str::to_string),
            questions,
            raw: v,
        })
    }

    /// The body to send upstream: the caller's object with `model` pinned to
    /// the model this provider actually attached.
    fn upstream_body(&self, model: &str) -> Value {
        let mut v = self.raw.clone();
        if let Some(obj) = v.as_object_mut() {
            obj.insert("model".into(), Value::String(model.to_string()));
        }
        v
    }
}

/// One validated answer. Field order here is the canonical output order.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    Noul {
        noul: f64,
    },
    Choice {
        choice: String,
        probabilities: BTreeMap<String, f64>,
        confidence: Option<f64>,
    },
    Score {
        score: f64,
        /// Level descriptions, always as strings. A raw JSON value here would
        /// be uncanonicalizable: JavaScript cannot tell `1` from `1.0`, so a
        /// numeric legend entry would hash differently in the verifier than in
        /// the provider. Non-string values are coerced to their JSON text.
        legend: BTreeMap<String, String>,
        probabilities: BTreeMap<String, f64>,
        confidence: Option<f64>,
    },
}

impl Answer {
    fn kind(&self) -> &'static str {
        match self {
            Answer::Noul { .. } => "noul",
            Answer::Choice { .. } => "choice",
            Answer::Score { .. } => "score",
        }
    }

    fn to_canonical(&self) -> Value {
        let mut o = Map::new();
        o.insert("type".into(), Value::String(self.kind().into()));
        match self {
            Answer::Noul { noul } => {
                o.insert("noul".into(), number(*noul));
            }
            Answer::Choice {
                choice,
                probabilities,
                confidence,
            } => {
                o.insert("choice".into(), Value::String(choice.clone()));
                o.insert(
                    "probabilities".into(),
                    canonical_probabilities(probabilities),
                );
                if let Some(c) = confidence {
                    o.insert("confidence".into(), number(*c));
                }
            }
            Answer::Score {
                score,
                legend,
                probabilities,
                confidence,
            } => {
                o.insert("score".into(), number(*score));
                if !legend.is_empty() {
                    let mut l = Map::new();
                    for (k, v) in legend {
                        l.insert(k.clone(), Value::String(v.clone()));
                    }
                    o.insert("legend".into(), Value::Object(l));
                }
                o.insert(
                    "probabilities".into(),
                    canonical_probabilities(probabilities),
                );
                if let Some(c) = confidence {
                    o.insert("confidence".into(), number(*c));
                }
            }
        }
        Value::Object(o)
    }
}

/// `BTreeMap` iteration is sorted, and `preserve_order` keeps the insertion
/// order we build here — so option keys come out sorted, not in whatever order
/// the upstream server emitted them.
fn canonical_probabilities(p: &BTreeMap<String, f64>) -> Value {
    let mut m = Map::new();
    for (k, v) in p {
        m.insert(k.clone(), number(*v));
    }
    Value::Object(m)
}

fn number(f: f64) -> Value {
    serde_json::Number::from_f64(f)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// A validated decision result, ready to hash and return.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionResult {
    pub model: String,
    pub answers: BTreeMap<String, Answer>,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl DecisionResult {
    /// The bytes the receipt commits to. Deterministic for a given model +
    /// state + questions, which is what makes replay verification possible.
    pub fn to_canonical_json(&self) -> String {
        let mut answers = Map::new();
        for (id, a) in &self.answers {
            answers.insert(id.clone(), a.to_canonical());
        }
        let out = json!({
            "model": self.model,
            "answers": Value::Object(answers),
            "usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
            },
        });
        serde_json::to_string(&out).unwrap_or_default()
    }
}

/// Parse and validate an upstream `/v1/systemone` reply against the questions
/// that were asked.
///
/// This is the engine's honest-checkpoint: a server that drops a question,
/// invents one, picks an option that was never offered, or returns a
/// probability outside `[0, 1]` fails here rather than producing a signed
/// receipt for a malformed decision.
pub fn parse_decision_response(
    bytes: &[u8],
    questions: &BTreeMap<String, Question>,
    model: &str,
) -> Result<DecisionResult> {
    let v: Value = serde_json::from_slice(bytes)
        .map_err(|e| anyhow!("decision server reply is not JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| anyhow!("decision server reply is not an object"))?;

    // The hosted API documents `{ model, answers, usage }`; some clients and
    // at least one published example show the answers at the top level. Accept
    // both — the question ids tell us which we got.
    let answers_obj = match obj.get("answers").and_then(|a| a.as_object()) {
        Some(a) => a.clone(),
        None => {
            let mut m = obj.clone();
            for k in ["model", "usage", "id", "object", "created"] {
                m.remove(k);
            }
            m
        }
    };

    let mut answers = BTreeMap::new();
    for (id, question) in questions {
        let raw = answers_obj
            .get(id)
            .ok_or_else(|| anyhow!("decision server did not answer question {id:?}"))?;
        answers.insert(id.clone(), parse_answer(raw, question, id)?);
    }
    for id in answers_obj.keys() {
        if !questions.contains_key(id) {
            bail!("decision server answered unasked question {id:?}");
        }
    }

    let usage = obj.get("usage");
    let input_tokens = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    // A non-autoregressive model generates nothing. Carried through honestly
    // rather than defaulted, so a server that does report it is believed.
    let output_tokens = usage
        .and_then(|u| u.get("output_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0);

    Ok(DecisionResult {
        model: model.to_string(),
        answers,
        input_tokens,
        output_tokens,
    })
}

fn parse_answer(raw: &Value, question: &Question, id: &str) -> Result<Answer> {
    let obj = raw
        .as_object()
        .ok_or_else(|| anyhow!("answer to {id:?} is not an object"))?;
    if let Some(t) = obj.get("type").and_then(|t| t.as_str()) {
        if t != question.kind() {
            bail!(
                "answer to {id:?} is a {t:?} but the question was a {:?}",
                question.kind()
            );
        }
    }
    match question {
        Question::Noul { .. } => Ok(Answer::Noul {
            noul: probability(obj.get("noul"), id, "noul")?,
        }),
        Question::Choice { criteria, .. } => {
            let choice = obj
                .get("choice")
                .and_then(|c| c.as_str())
                .ok_or_else(|| anyhow!("answer to {id:?} has no `choice`"))?
                .to_string();
            if !criteria.contains_key(&choice) {
                bail!("answer to {id:?} chose {choice:?}, which was not one of the options");
            }
            let probabilities = probability_map(obj.get("probabilities"), id, Some(criteria))?;
            Ok(Answer::Choice {
                choice,
                probabilities,
                confidence: optional_probability(obj.get("confidence"), id, "confidence")?,
            })
        }
        Question::Score { .. } => {
            let score = obj
                .get("score")
                .and_then(|s| s.as_f64())
                .ok_or_else(|| anyhow!("answer to {id:?} has no numeric `score`"))?;
            let legend = obj
                .get("legend")
                .and_then(|l| l.as_object())
                .map(|l| {
                    l.iter()
                        .map(|(k, v)| {
                            let text = match v.as_str() {
                                Some(s) => s.to_string(),
                                None => v.to_string(),
                            };
                            (k.clone(), text)
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(Answer::Score {
                score,
                legend,
                probabilities: probability_map(obj.get("probabilities"), id, None)?,
                confidence: optional_probability(obj.get("confidence"), id, "confidence")?,
            })
        }
    }
}

fn probability(v: Option<&Value>, id: &str, field: &str) -> Result<f64> {
    let n = v
        .and_then(|x| x.as_f64())
        .ok_or_else(|| anyhow!("answer to {id:?} has no numeric `{field}`"))?;
    if !(0.0..=1.0).contains(&n) {
        bail!("answer to {id:?} has `{field}` = {n}, outside [0, 1]");
    }
    Ok(n)
}

fn optional_probability(v: Option<&Value>, id: &str, field: &str) -> Result<Option<f64>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(_) => Ok(Some(probability(v, id, field)?)),
    }
}

/// `allowed` is the question's option set for a `choice` (a distribution may
/// only name options that were offered) and `None` for a `score`, whose
/// distribution is over its ordered levels rather than named keys.
fn probability_map(
    v: Option<&Value>,
    id: &str,
    allowed: Option<&BTreeMap<String, Value>>,
) -> Result<BTreeMap<String, f64>> {
    let Some(obj) = v.and_then(|x| x.as_object()) else {
        return Ok(BTreeMap::new());
    };
    let mut out = BTreeMap::new();
    for (k, val) in obj {
        if let Some(allowed) = allowed {
            if !allowed.contains_key(k) {
                bail!("answer to {id:?} has a probability for {k:?}, which was not an option");
            }
        }
        out.insert(k.clone(), probability(Some(val), id, k)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Canary
// ---------------------------------------------------------------------------

/// Two opposed nouls over an unambiguous state.
///
/// Passing requires the server to answer BOTH ids with in-range probabilities
/// AND to rank them correctly. A server that echoes, that answers a constant
/// 0.5, or that ignores `questions` and replies with a fixed object fails.
/// Deliberately no absolute threshold: calibration differs across Laya
/// variants and quantizations, and a canary that encodes a threshold would
/// de-advertise honest servers on a q4 checkpoint.
pub fn decision_canary_body(model: &str) -> Value {
    json!({
        "model": model,
        "state": "The server room is on fire, the building alarm is sounding, and staff are evacuating right now.",
        "questions": {
            "cocore_canary_urgent": {
                "type": "noul",
                "instructions": "The situation described is an emergency that needs action immediately."
            },
            "cocore_canary_routine": {
                "type": "noul",
                "instructions": "The situation described is routine and can safely wait until next quarter."
            }
        }
    })
}

/// Passing = both canary questions answered, in range, and urgent > routine.
pub fn decision_canary_passed(bytes: &[u8]) -> bool {
    let questions = match DecisionRequest::parse(&decision_canary_body("canary").to_string()) {
        Ok(r) => r.questions,
        Err(_) => return false,
    };
    let Ok(result) = parse_decision_response(bytes, &questions, "canary") else {
        return false;
    };
    let (Some(Answer::Noul { noul: urgent }), Some(Answer::Noul { noul: routine })) = (
        result.answers.get("cocore_canary_urgent"),
        result.answers.get("cocore_canary_routine"),
    ) else {
        return false;
    };
    urgent > routine
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub struct AttachedDecisionEngine {
    model_id: String,
    model_digest: Option<String>,
    target: AttachedTarget,
    verified_decisions: Mutex<bool>,
    ready_cache: Mutex<Option<(Instant, bool)>>,
    /// Overrides the env-var timeout. Set by tests so they don't race each
    /// other through a shared process-wide env var.
    ready_timeout: Option<Duration>,
}

impl AttachedDecisionEngine {
    pub fn new(model_id: impl Into<String>, target: AttachedTarget) -> Self {
        let model_id = model_id.into();
        if !target.is_loopback() {
            tracing::warn!(
                model = %model_id,
                target = %target,
                "attached decision engine is NOT on loopback: decrypted state will cross the network in plaintext to that host"
            );
        }
        Self {
            model_id,
            model_digest: None,
            target,
            verified_decisions: Mutex::new(false),
            ready_cache: Mutex::new(None),
            ready_timeout: None,
        }
    }

    /// Declare which artifact this engine runs (see [`model_digests`]). The
    /// agent relays it as a claim on the receipt; it never verifies it.
    pub fn with_model_digest(mut self, digest: Option<String>) -> Self {
        self.model_digest = digest;
        self
    }

    /// Bound how long [`start`](Self::start) waits for the server, instead of
    /// reading `COCORE_ATTACHED_READY_TIMEOUT`.
    pub fn with_ready_timeout(mut self, timeout: Duration) -> Self {
        self.ready_timeout = Some(timeout);
        self
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn target(&self) -> &AttachedTarget {
        &self.target
    }

    fn ready_timeout(&self) -> Duration {
        if let Some(t) = self.ready_timeout {
            return t;
        }
        std::env::var("COCORE_ATTACHED_READY_TIMEOUT")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_READY_TIMEOUT)
    }

    fn set_ready_cache(&self, ready: bool) {
        if let Ok(mut c) = self.ready_cache.lock() {
            *c = Some((Instant::now(), ready));
        }
    }

    /// Wait for the server to answer, then run the decision canary.
    /// Idempotent; re-running re-verifies.
    pub fn start(&self) -> Result<()> {
        let timeout = self.ready_timeout();
        let started = Instant::now();
        let mut last_log = Instant::now() - Duration::from_secs(60);
        loop {
            if self.target.probe_ready() {
                break;
            }
            if started.elapsed() > timeout {
                bail!(
                    "attached decision engine {} did not answer GET /v1/models within {}s (is the decision server running on that port? e.g. `ollaya serve`)",
                    self.target,
                    timeout.as_secs()
                );
            }
            if last_log.elapsed() >= Duration::from_secs(15) {
                tracing::info!(
                    model = %self.model_id,
                    target = %self.target,
                    waited_s = started.elapsed().as_secs(),
                    "waiting for attached decision engine to answer /v1/models"
                );
                last_log = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        self.set_ready_cache(true);

        let skip = std::env::var("COCORE_ATTACHED_SKIP_CANARIES")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let verified = if skip {
            tracing::warn!(model = %self.model_id, "COCORE_ATTACHED_SKIP_CANARIES set; serving decisions without proving the server speaks /v1/systemone");
            true
        } else {
            self.run_decision_canary()
        };
        if let Ok(mut v) = self.verified_decisions.lock() {
            *v = verified;
        }
        if !verified {
            bail!(
                "attached decision engine {} answers /v1/models but failed the /v1/systemone canary; it is not serving decisions for {}",
                self.target,
                self.model_id
            );
        }
        tracing::info!(model = %self.model_id, target = %self.target, "attached decision engine ready");
        Ok(())
    }

    fn run_decision_canary(&self) -> bool {
        let body = match serde_json::to_vec(&decision_canary_body(&self.model_id)) {
            Ok(b) => b,
            Err(_) => return false,
        };
        match self.target.post_json(SYSTEMONE_ROUTE, &body) {
            Ok(bytes) => {
                let ok = decision_canary_passed(&bytes);
                if ok {
                    tracing::info!(model = %self.model_id, "attached decision engine canary passed");
                } else {
                    tracing::warn!(
                        model = %self.model_id,
                        "attached decision engine failed the /v1/systemone canary (its answers did not track the questions); not serving this model"
                    );
                }
                ok
            }
            Err(e) => {
                tracing::warn!(model = %self.model_id, error = %e, "attached decision engine canary errored; not serving this model");
                false
            }
        }
    }

    pub fn verified_decisions(&self) -> bool {
        self.verified_decisions.lock().map(|v| *v).unwrap_or(false)
    }

    /// Run one decision. Split out from [`Engine::generate_once`] so the
    /// wire path can be tested without building a [`GenerateRequest`].
    pub fn decide(&self, prompt: &str) -> Result<DecisionResult> {
        let request = DecisionRequest::parse(prompt).map_err(|e| {
            anyhow::Error::new(EngineRejection::DecisionRequestInvalid {
                model: self.model_id.clone(),
                reason: e.to_string(),
            })
        })?;
        let body = Zeroizing::new(serde_json::to_vec(&request.upstream_body(&self.model_id))?);
        let bytes = self.target.post_json(SYSTEMONE_ROUTE, &body)?;
        parse_decision_response(&bytes, &request.questions, &self.model_id)
    }
}

impl Engine for AttachedDecisionEngine {
    fn name(&self) -> &'static str {
        "attached-decision"
    }

    fn model_digest(&self) -> Option<String> {
        self.model_digest.clone()
    }

    fn ready(&self) -> bool {
        if let Ok(c) = self.ready_cache.lock() {
            if let Some((at, ready)) = *c {
                if at.elapsed() < READY_CACHE {
                    return ready;
                }
            }
        }
        let ready = self.target.probe_ready();
        self.set_ready_cache(ready);
        ready
    }

    /// Nothing to respawn — the server is the operator's. Re-probe, and
    /// re-run the canary if it comes back, so a server that was restarted
    /// with a different model doesn't keep the old advertisement.
    fn restart(&self) -> Result<()> {
        let ready = self.target.probe_ready();
        self.set_ready_cache(ready);
        if ready {
            let verified = self.run_decision_canary();
            if let Ok(mut v) = self.verified_decisions.lock() {
                *v = verified;
            }
            tracing::info!(model = %self.model_id, target = %self.target, canary = verified, "attached decision engine is answering again");
        } else {
            tracing::warn!(
                model = %self.model_id,
                target = %self.target,
                "attached decision engine is not answering; the agent does not manage that server — restart it and the model will be re-advertised on the next health tick"
            );
        }
        Ok(())
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        // Guided decoding and tools are chat-engine concepts; a decision
        // server has no sampler to constrain. Refuse rather than silently
        // ignoring a constraint the requester paid for.
        if request.guided_json.is_some() {
            return Err(EngineRejection::StructuredOutputUnsupported {
                model: self.model_id.clone(),
            }
            .into());
        }
        if request.tools.is_some() {
            return Err(EngineRejection::DecisionRequestInvalid {
                model: self.model_id.clone(),
                reason: "tools are not available on a decision model".to_string(),
            }
            .into());
        }

        let prompt = Zeroizing::new(
            request
                .messages
                .iter()
                .map(|m| m.content_text())
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let result = self.decide(&prompt)?;
        Ok(GenerateResponse {
            text: result.to_canonical_json(),
            tokens_in: result.input_tokens,
            tokens_out: result.output_tokens,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::{rejection_of, Message};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // ---- request parsing ---------------------------------------------------

    fn noul_request() -> String {
        json!({
            "model": "jev-latest",
            "state": "Third time this year you've double-charged me.",
            "questions": {
                "is_urgent": { "type": "noul", "instructions": "The message conveys urgency." }
            }
        })
        .to_string()
    }

    #[test]
    fn parses_a_noul_request() {
        let r = DecisionRequest::parse(&noul_request()).unwrap();
        assert_eq!(r.requested_model.as_deref(), Some("jev-latest"));
        assert_eq!(r.questions.len(), 1);
        assert_eq!(r.questions["is_urgent"].kind(), "noul");
    }

    #[test]
    fn a_chat_prompt_is_not_a_decision_request() {
        let err = DecisionRequest::parse("Write me a haiku about otters.").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not a decision request"), "{msg}");
        assert!(msg.contains("/v1/systemone"), "{msg}");
    }

    #[test]
    fn rejects_requests_missing_state_or_questions() {
        assert!(DecisionRequest::parse(r#"{"questions":{}}"#)
            .unwrap_err()
            .to_string()
            .contains("missing `state`"));
        assert!(DecisionRequest::parse(r#"{"state":"x"}"#)
            .unwrap_err()
            .to_string()
            .contains("missing `questions`"));
        assert!(DecisionRequest::parse(r#"{"state":"x","questions":{}}"#)
            .unwrap_err()
            .to_string()
            .contains("no questions"));
    }

    #[test]
    fn enforces_the_documented_criteria_limits() {
        let one_level = json!({
            "state": "x",
            "questions": { "q": { "type": "score", "instructions": "Rate it", "criteria": ["low"] } }
        })
        .to_string();
        assert!(DecisionRequest::parse(&one_level)
            .unwrap_err()
            .to_string()
            .contains("2–10"));

        let no_options = json!({
            "state": "x",
            "questions": { "q": { "type": "choice", "instructions": "Pick", "criteria": {} } }
        })
        .to_string();
        assert!(DecisionRequest::parse(&no_options)
            .unwrap_err()
            .to_string()
            .contains("no options"));
    }

    #[test]
    fn upstream_body_pins_the_model_the_operator_attached() {
        let r = DecisionRequest::parse(&noul_request()).unwrap();
        let body = r.upstream_body("convaiinnovations/laya");
        assert_eq!(body["model"], json!("convaiinnovations/laya"));
        // Everything else is forwarded untouched.
        assert_eq!(
            body["state"],
            json!("Third time this year you've double-charged me.")
        );
    }

    // ---- response validation ----------------------------------------------

    fn questions_of(req: &str) -> BTreeMap<String, Question> {
        DecisionRequest::parse(req).unwrap().questions
    }

    #[test]
    fn accepts_both_the_enveloped_and_bare_answer_shapes() {
        let qs = questions_of(&noul_request());
        let enveloped = br#"{"model":"laya","answers":{"is_urgent":{"type":"noul","noul":0.94}},"usage":{"input_tokens":31,"output_tokens":0}}"#;
        let bare = br#"{"is_urgent":{"type":"noul","noul":0.94}}"#;
        let a = parse_decision_response(enveloped, &qs, "laya").unwrap();
        let b = parse_decision_response(bare, &qs, "laya").unwrap();
        assert_eq!(a.answers, b.answers);
        assert_eq!(a.input_tokens, 31);
        assert_eq!(b.input_tokens, 0);
    }

    #[test]
    fn rejects_a_server_that_drops_or_invents_questions() {
        let qs = questions_of(&noul_request());
        let missing = br#"{"answers":{}}"#;
        assert!(parse_decision_response(missing, &qs, "laya")
            .unwrap_err()
            .to_string()
            .contains("did not answer question"));

        let extra = br#"{"answers":{"is_urgent":{"type":"noul","noul":0.9},"is_angry":{"type":"noul","noul":0.9}}}"#;
        assert!(parse_decision_response(extra, &qs, "laya")
            .unwrap_err()
            .to_string()
            .contains("unasked question"));
    }

    #[test]
    fn rejects_out_of_range_and_mistyped_answers() {
        let qs = questions_of(&noul_request());
        let over = br#"{"answers":{"is_urgent":{"type":"noul","noul":1.4}}}"#;
        assert!(parse_decision_response(over, &qs, "laya")
            .unwrap_err()
            .to_string()
            .contains("outside [0, 1]"));

        let wrong_type = br#"{"answers":{"is_urgent":{"type":"choice","choice":"yes"}}}"#;
        assert!(parse_decision_response(wrong_type, &qs, "laya")
            .unwrap_err()
            .to_string()
            .contains("but the question was"));
    }

    #[test]
    fn rejects_a_choice_that_was_never_offered() {
        let req = json!({
            "state": "x",
            "questions": { "next": { "type": "choice", "instructions": "Pick one",
                "criteria": { "refund": "issue a refund", "escalate": "send to a human" } } }
        })
        .to_string();
        let qs = questions_of(&req);
        let bogus =
            br#"{"answers":{"next":{"type":"choice","choice":"ignore","probabilities":{}}}}"#;
        assert!(parse_decision_response(bogus, &qs, "laya")
            .unwrap_err()
            .to_string()
            .contains("not one of the options"));

        let bogus_prob = br#"{"answers":{"next":{"type":"choice","choice":"refund","probabilities":{"ignore":0.5}}}}"#;
        assert!(parse_decision_response(bogus_prob, &qs, "laya")
            .unwrap_err()
            .to_string()
            .contains("not an option"));
    }

    // ---- canonical output --------------------------------------------------

    #[test]
    fn output_is_canonical_regardless_of_upstream_key_order() {
        let req = json!({
            "state": "x",
            "questions": {
                "zeta": { "type": "noul", "instructions": "z" },
                "alpha": { "type": "choice", "instructions": "a",
                           "criteria": { "b": "bee", "a": "ay" } }
            }
        })
        .to_string();
        let qs = questions_of(&req);
        let one = br#"{"answers":{"zeta":{"type":"noul","noul":0.25},"alpha":{"probabilities":{"b":0.3,"a":0.7},"type":"choice","choice":"a","confidence":0.7}}}"#;
        let two = br#"{"answers":{"alpha":{"choice":"a","confidence":0.7,"type":"choice","probabilities":{"a":0.7,"b":0.3}},"zeta":{"noul":0.25,"type":"noul"}}}"#;
        let a = parse_decision_response(one, &qs, "laya").unwrap();
        let b = parse_decision_response(two, &qs, "laya").unwrap();
        assert_eq!(a.to_canonical_json(), b.to_canonical_json());
        assert_eq!(
            a.to_canonical_json(),
            r#"{"model":"laya","answers":{"alpha":{"type":"choice","choice":"a","probabilities":{"a":0.7,"b":0.3},"confidence":0.7},"zeta":{"type":"noul","noul":0.25}},"usage":{"input_tokens":0,"output_tokens":0}}"#
        );
    }

    // ---- canary ------------------------------------------------------------

    #[test]
    fn canary_needs_the_answers_to_track_the_questions() {
        let good = br#"{"answers":{"cocore_canary_urgent":{"type":"noul","noul":0.98},"cocore_canary_routine":{"type":"noul","noul":0.02}}}"#;
        assert!(decision_canary_passed(good));

        // A server that answers a constant — the failure mode a liveness
        // probe alone would not catch.
        let constant = br#"{"answers":{"cocore_canary_urgent":{"type":"noul","noul":0.5},"cocore_canary_routine":{"type":"noul","noul":0.5}}}"#;
        assert!(!decision_canary_passed(constant));

        // Ranked backwards.
        let inverted = br#"{"answers":{"cocore_canary_urgent":{"type":"noul","noul":0.1},"cocore_canary_routine":{"type":"noul","noul":0.9}}}"#;
        assert!(!decision_canary_passed(inverted));

        // A chat server answering prose with HTTP 200.
        assert!(!decision_canary_passed(
            br#"{"choices":[{"message":{"content":"Sure! That sounds urgent."}}]}"#
        ));
    }

    // ---- wire path ---------------------------------------------------------

    struct FakeServer {
        port: u16,
        requests: Arc<AtomicUsize>,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Good,
        /// Answers, but always the same numbers — fails the canary.
        Constant,
    }

    fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = find_headers_end(&buf) {
                let head = String::from_utf8_lossy(&buf[..i]).to_string();
                let len = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if buf.len() >= i + 4 + len {
                    return (head, buf[i + 4..i + 4 + len].to_vec());
                }
            }
        }
        (String::from_utf8_lossy(&buf).to_string(), Vec::new())
    }

    fn find_headers_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn write_json(stream: &mut TcpStream, status: u16, body: &str) {
        let resp = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).unwrap();
    }

    /// A stand-in for `ollaya serve`: answers `/v1/models` and scores every
    /// question it is asked, keying off the instructions the way a real
    /// decision model keys off the state.
    fn spawn_server(mode: Mode) -> FakeServer {
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
                        r#"{"object":"list","data":[{"id":"laya","object":"model"}]}"#,
                    );
                    continue;
                }
                if !first.starts_with("POST /v1/systemone") {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                }
                let req: Value = serde_json::from_slice(&body).unwrap();
                let mut answers = Map::new();
                for (id, q) in req["questions"].as_object().unwrap() {
                    let instructions = q["instructions"].as_str().unwrap_or("");
                    let p = if mode == Mode::Constant {
                        0.5
                    } else if instructions.contains("routine") {
                        0.02
                    } else {
                        0.97
                    };
                    answers.insert(id.clone(), json!({ "type": "noul", "noul": p }));
                }
                let reply = json!({
                    "model": req["model"],
                    "answers": answers,
                    "usage": { "input_tokens": 42, "output_tokens": 0 },
                });
                write_json(&mut stream, 200, &reply.to_string());
            }
        });
        FakeServer { port, requests }
    }

    fn engine_for(server: &FakeServer, model: &str) -> AttachedDecisionEngine {
        AttachedDecisionEngine::new(
            model,
            AttachedTarget::parse(&format!("http://127.0.0.1:{}", server.port)).unwrap(),
        )
    }

    #[test]
    fn starts_serves_and_reports_input_only_tokens() {
        let server = spawn_server(Mode::Good);
        let engine = engine_for(&server, "convaiinnovations/laya");
        engine.start().unwrap();
        assert!(engine.verified_decisions());
        assert!(engine.ready());

        let request = GenerateRequest {
            model: "jev-latest".into(),
            messages: vec![Message::text("user", noul_request())],
            max_tokens: 1024,
            temperature: None,
            top_p: None,
            guided_json: None,
            tools: None,
            tool_choice: None,
        };
        let resp = engine.generate_once(&request).unwrap();
        let out: Value = serde_json::from_str(&resp.text).unwrap();
        // The receipt names the model that actually ran, not the alias asked for.
        assert_eq!(out["model"], json!("convaiinnovations/laya"));
        assert_eq!(out["answers"]["is_urgent"]["type"], json!("noul"));
        assert!(out["answers"]["is_urgent"]["noul"].as_f64().unwrap() > 0.5);
        assert_eq!(resp.tokens_in, 42);
        // Non-autoregressive: nothing was generated.
        assert_eq!(resp.tokens_out, 0);
        assert!(server.requests.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn a_server_that_fails_the_canary_is_not_served() {
        let server = spawn_server(Mode::Constant);
        let engine = engine_for(&server, "convaiinnovations/laya");
        let err = engine.start().unwrap_err();
        assert!(err.to_string().contains("canary"), "{err}");
        assert!(!engine.verified_decisions());
    }

    #[test]
    fn a_chat_job_routed_here_is_refused_typed_not_answered() {
        let server = spawn_server(Mode::Good);
        let engine = engine_for(&server, "convaiinnovations/laya");
        engine.start().unwrap();

        let request = GenerateRequest {
            model: "convaiinnovations/laya".into(),
            messages: vec![Message::text("user", "Write me a haiku about otters.")],
            max_tokens: 64,
            temperature: None,
            top_p: None,
            guided_json: None,
            tools: None,
            tool_choice: None,
        };
        let err = engine.generate_once(&request).unwrap_err();
        let rejection = rejection_of(&err).expect("typed rejection so no receipt is published");
        assert_eq!(rejection.code(), "decision-request-invalid");
    }

    #[test]
    fn guided_json_is_refused_rather_than_silently_dropped() {
        let server = spawn_server(Mode::Good);
        let engine = engine_for(&server, "convaiinnovations/laya");
        engine.start().unwrap();

        let request = GenerateRequest {
            model: "convaiinnovations/laya".into(),
            messages: vec![Message::text("user", noul_request())],
            max_tokens: 64,
            temperature: None,
            top_p: None,
            guided_json: Some(json!({ "name": "x", "schema": {} })),
            tools: None,
            tool_choice: None,
        };
        let err = engine.generate_once(&request).unwrap_err();
        assert_eq!(
            rejection_of(&err).unwrap().code(),
            "structured-output-unsupported"
        );
    }

    #[test]
    fn unreachable_server_is_not_ready_and_start_fails_bounded() {
        let engine = AttachedDecisionEngine::new(
            "convaiinnovations/laya",
            // Port 1 on loopback: nothing listens, connect fails fast.
            AttachedTarget::parse("http://127.0.0.1:1").unwrap(),
        )
        .with_ready_timeout(Duration::from_secs(1));
        assert!(!engine.ready());
        let err = engine.start().unwrap_err();
        assert!(err.to_string().contains("did not answer"), "{err}");
    }

    #[test]
    fn decision_map_reads_its_own_env_var() {
        std::env::set_var(
            DECISION_ENGINE_MAP_ENV,
            "convaiinnovations/laya=http://127.0.0.1:11435",
        );
        let map = decision_engine_map().unwrap();
        std::env::remove_var(DECISION_ENGINE_MAP_ENV);
        assert_eq!(map.models(), vec!["convaiinnovations/laya".to_string()]);
        assert_eq!(map.get("convaiinnovations/laya").unwrap().port, 11435);
    }
}
