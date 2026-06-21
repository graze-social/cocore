//! PDS write surface for the provider.
//!
//! The provider publishes three record types:
//!
//!   * `dev.cocore.compute.provider`        — once per `serve` start
//!   * `dev.cocore.compute.attestation`     — once per `serve` start
//!   * `dev.cocore.compute.receipt`         — once per completed job
//!
//! v0.3.0 swapped the architecture: the agent **does not** call bsky
//! directly. It POSTs each record to the cocore console's proxy
//! (`POST /api/pds/createRecord`) using the API
//! key from its paired session. The console resolves the key to a
//! DID, restores the user's DPoP-aware OAuth session, and forwards
//! the create to bsky on the agent's behalf.
//!
//! Why: real bsky PDSes require DPoP-bound tokens (ES256-signed
//! per-request proofs). The agent doesn't sign DPoP today; the
//! console's JS OAuth client does. Routing every write through the
//! console keeps DPoP in one place and lets us iterate on signing
//! semantics without re-shipping a Rust binary.
//!
//! Token lifecycle: API keys are stable until revoked. There is no
//! refresh path here — if the key is rejected, the agent fails the
//! publish and surfaces the error. The user revokes/re-mints in the
//! console at /api-keys.

use crate::error::{ProviderError, Result};
use crate::oauth::Session;
use serde::{Deserialize, Serialize};

/// Inputs needed to publish a `dev.cocore.compute.provider` record.
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Clone)]
pub struct ProviderRecord {
    pub machineLabel: String,
    pub chip: String,
    pub ramGB: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpuCores: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memoryBandwidthGBs: Option<u32>,
    /// New in v0.3.1 — total CPU cores.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuCores: Option<u32>,
    /// New in v0.3.1 — Apple Silicon performance-core split.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pCores: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eCores: Option<u32>,
    /// New in v0.3.1 — Apple model code (e.g. "Macmini9,1").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modelIdentifier: Option<String>,
    /// New in v0.3.1 — operating system + version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub supportedModels: Vec<String>,
    pub priceList: Vec<ModelPrice>,
    pub encryptionPubKey: String,
    pub attestationPubKey: String,
    pub trustLevel: TrustLevel,
    /// Agent-published ACHIEVED confidentiality tier (`attested-confidential` |
    /// `best-effort`), derived from the signed attestation's evidence — NEVER
    /// self-declared. Absent ≡ best-effort. The agent only publishes
    /// `attested-confidential` once the measured native engine is serving under
    /// a hardware-attested posture. See `desiredTier` for the owner's intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acceptedExchanges: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contactEndpoint: Option<String>,
    /// Version of the agent binary that wrote this record (e.g.
    /// `0.3.4`). Stamped on every `cocore agent serve` startup so
    /// dashboards can tell at a glance which machines need an
    /// update. Optional in the lexicon (additive); always set in
    /// records this binary writes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binaryVersion: Option<String>,
    /// Whether this DID has a payout method on file. The agent
    /// itself doesn't know — it's set by the console's reconcile
    /// flow after Stripe Connect onboarding. We carry the field
    /// here so the agent's startup `put_provider` can PRESERVE the
    /// value when it re-publishes the record (otherwise every
    /// serve restart would clobber the field back to absent). The
    /// agent never writes `true` on its own; it only echoes back
    /// whatever it found on the existing record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payoutsEnabled: Option<bool>,
    /// Owner-controlled serve switch. `Some(false)` means the owner has
    /// stopped this machine from the console (it should be routed no jobs);
    /// `Some(true)` / `None` means it serves. The agent NEVER sets this
    /// itself — the console writes it to the owner's PDS — so the agent
    /// must PRESERVE whatever it finds on the existing record when it
    /// re-publishes (exactly like `payoutsEnabled`), and it reports the
    /// value to the advisor so routing can skip a stopped machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// Model identifiers the OWNER wants this machine to load, written from
    /// a management UI (the console's per-machine model picker). The agent
    /// reconciles toward it (loads it at serve start; restarts to reload
    /// when it changes) but never AUTHORS it — like `active`/`payoutsEnabled`
    /// it's console-written and the agent must PRESERVE it on every
    /// re-publish, or each serve would clobber the owner's choice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desiredModels: Option<Vec<String>>,
    /// The confidentiality tier the OWNER opted this machine into (the console /
    /// tray "Upgrade security" action), `attested-confidential` | `best-effort`.
    /// Owner-written INTENT, like `desiredModels`/`active`: the agent reconciles
    /// toward it (switches to the measured native engine, earns the posture) but
    /// NEVER authors it, so it must PRESERVE whatever it finds on every
    /// re-publish. Setting it never fakes the achieved `tier`/`trustLevel` —
    /// those only rise once actually earned; a machine that can't (e.g. a
    /// non-native build) stays best-effort. Absent / `best-effort` = not opted
    /// in, serves exactly as before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desiredTier: Option<String>,
    /// True while the agent is still loading its inference engine. Set on
    /// the early "provisioning" publish at serve start so the machine
    /// appears on the console immediately; cleared (set false) on the
    /// re-publish once the engine is ready. See `cmd_serve`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<bool>,
    /// Liveness flag. `Some(true)` while the serve loop is up; the agent
    /// publishes `Some(false)` on graceful shutdown (SIGTERM) so the
    /// console can show the machine offline the moment it stops serving.
    /// `None` on records from binaries that predate the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serving: Option<bool>,
    /// Set when `serve` could not bring the configured inference engine
    /// online after exhausting its startup recovery attempts. The agent
    /// clears this (writes `None`) on every healthy serve, so its
    /// presence always reflects the *current* serve lifetime, not a
    /// stale failure. See `build_engines`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engineFault: Option<EngineFault>,
    pub createdAt: chrono::DateTime<chrono::Utc>,
}

/// A content-safe description of why the inference engine failed to
/// load. Published on the provider record so the console can show the
/// operator a fault + remediation instead of a silently-stubbed machine
/// that looks healthy but never gets routed real jobs. Recorded only
/// after `serve`'s bounded retry loop gives up; populated strictly from
/// startup diagnostics (no prompt/completion bytes ever reach it).
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EngineFault {
    /// Machine-readable fault class: `model-load-failed`, `venv-missing`,
    /// or `no-home`.
    pub code: String,
    /// Human-readable summary with remediation guidance.
    pub message: String,
    /// The configured model ids that failed to load.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// When the agent gave up and recorded the fault.
    pub at: chrono::DateTime<chrono::Utc>,
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Clone)]
pub struct ModelPrice {
    pub modelId: String,
    pub inputPricePerMTok: u64,
    pub outputPricePerMTok: u64,
    pub currency: String,
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    SelfAttested,
    HardwareAttested,
}

/// A published record's location, plus the signed repo commit it landed
/// in. `commit.rev` is an inclusion pointer into the provider's MST: the
/// repo revision at which this record became part of the signed tree.
#[derive(Debug, Clone, Deserialize)]
pub struct PublishedRecord {
    pub uri: String,
    pub cid: String,
    #[serde(default)]
    pub commit: Option<RepoCommit>,
}

/// The `commit` half of a `com.atproto.repo.createRecord` response.
#[derive(Debug, Clone, Deserialize)]
pub struct RepoCommit {
    pub cid: String,
    pub rev: String,
}

/// One row of `com.atproto.repo.listRecords` output, narrowed to what
/// the dedup path needs (everything else is ignored). The PDS exposes
/// listRecords without auth so we can hit it directly without going
/// through the console proxy.
#[derive(Debug, Clone, Deserialize)]
pub struct ListedRecord {
    pub uri: String,
    pub cid: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ListRecordsResponse {
    records: Vec<ListedRecord>,
    #[serde(default)]
    cursor: Option<String>,
}

/// HTTP client over the console's `/api/pds/createRecord`
/// endpoint. One instance per agent lifetime; the API key is
/// captured at construction and never rotated.
pub struct PdsClient {
    did: String,
    api_base: String,
    api_key: String,
    http: reqwest::Client,
}

impl PdsClient {
    pub fn new(session: Session) -> Self {
        let http = reqwest::Client::builder()
            .build()
            .expect("reqwest client construction is infallible");
        Self {
            did: session.did,
            api_base: session.api_base,
            api_key: session.api_key,
            http,
        }
    }

    pub fn provider_did(&self) -> &str {
        &self.did
    }

    pub async fn publish_provider(&self, record: &ProviderRecord) -> Result<PublishedRecord> {
        self.publish("dev.cocore.compute.provider", record).await
    }

    /// Idempotent upsert via the console's `proxy.putRecord` endpoint.
    /// Used by the dedup-and-republish path on every `serve` startup
    /// so this machine has exactly one provider record on PDS,
    /// stably-keyed by the rkey we computed at first publish.
    pub async fn put_provider(
        &self,
        rkey: &str,
        record: &ProviderRecord,
        swap_record: Option<&str>,
    ) -> Result<PublishedRecord> {
        self.put_record("dev.cocore.compute.provider", rkey, record, swap_record)
            .await
    }

    /// Generic putRecord proxy. Same auth + allowlist as
    /// `publish` (which is createRecord); the difference is the rkey
    /// is required and the operation is upsert-with-swap-guard.
    pub async fn put_record<R: Serialize>(
        &self,
        collection: &str,
        rkey: &str,
        record: &R,
        swap_record: Option<&str>,
    ) -> Result<PublishedRecord> {
        let url = format!("{}/api/pds/putRecord", self.api_base.trim_end_matches('/'));
        let body = match swap_record {
            Some(swap) => serde_json::json!({
                "collection": collection,
                "rkey": rkey,
                "record": record,
                "swapRecord": swap,
            }),
            None => serde_json::json!({
                "collection": collection,
                "rkey": rkey,
                "record": record,
            }),
        };
        tracing::debug!(collection, rkey, did = %self.did, "putRecord via console proxy");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Pds(format!("transport: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Pds(format!("read body: {e}")))?;
        if !status.is_success() {
            return Err(ProviderError::Pds(format!(
                "console proxy putRecord {collection} returned {status}: {text}"
            )));
        }
        serde_json::from_str(&text).map_err(|e| {
            ProviderError::Pds(format!("decode {collection} response: {e} body={text}"))
        })
    }

    /// Delete a record on the user's PDS via the console proxy.
    /// Used to trim duplicate provider records on every `serve`
    /// startup. Treats 404 / "InvalidSwap" / "could not locate" as
    /// success — the goal is "the record is gone", and the proxy
    /// already mirrors the AppView clear regardless of PDS outcome.
    pub async fn delete_record(
        &self,
        collection: &str,
        rkey: &str,
        swap_record: Option<&str>,
    ) -> Result<()> {
        let url = format!(
            "{}/api/pds/deleteRecord",
            self.api_base.trim_end_matches('/')
        );
        let body = match swap_record {
            Some(swap) => serde_json::json!({
                "collection": collection,
                "rkey": rkey,
                "swapRecord": swap,
            }),
            None => serde_json::json!({
                "collection": collection,
                "rkey": rkey,
            }),
        };
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Pds(format!("transport: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Pds(format!("read body: {e}")))?;
        if !status.is_success() {
            return Err(ProviderError::Pds(format!(
                "console proxy deleteRecord {collection} returned {status}: {text}"
            )));
        }
        Ok(())
    }

    /// List all of this provider's own records under `collection` on
    /// its PDS. Reads through bsky's public read endpoint (no auth);
    /// the agent uses this to find duplicates by `attestationPubKey`
    /// before republishing. Pagination caps at 100 pages × 100 records
    /// per page (10000 total) — well above any realistic duplicate
    /// count.
    pub async fn list_my_records(&self, collection: &str) -> Result<Vec<ListedRecord>> {
        let pds_endpoint = self.resolve_pds_endpoint().await?;
        let mut out: Vec<ListedRecord> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..100 {
            let mut url = format!(
                "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection={}&limit=100",
                pds_endpoint.trim_end_matches('/'),
                self.did,
                collection,
            );
            if let Some(c) = &cursor {
                url.push_str(&format!("&cursor={c}"));
            }
            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| ProviderError::Pds(format!("listRecords transport: {e}")))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ProviderError::Pds(format!(
                    "listRecords {collection} returned {status}: {text}"
                )));
            }
            let body: ListRecordsResponse = resp
                .json()
                .await
                .map_err(|e| ProviderError::Pds(format!("listRecords decode: {e}")))?;
            let got = body.records.len();
            out.extend(body.records);
            match body.cursor {
                Some(c) if got > 0 => cursor = Some(c),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Read the owner-set `active` start/stop switch from this DID's
    /// provider record at `rkey`. Returns `Some(bool)` when the field is
    /// present, `None` when it's absent (the lexicon default — serving) or
    /// on any read error. Reuses `list_my_records` (the proxy exposes no
    /// getRecord); a DID typically owns one provider record, so this is a
    /// single cheap list. The agent polls this to honour a remote stop.
    pub async fn get_provider_active(&self, rkey: &str) -> Option<bool> {
        let listed = self
            .list_my_records("dev.cocore.compute.provider")
            .await
            .ok()?;
        let rec = listed
            .iter()
            .find(|r| r.uri.rsplit('/').next() == Some(rkey))?;
        rec.value.get("active").and_then(|v| v.as_bool())
    }

    /// Read the owner-set controls — the `active` start/stop switch, the
    /// `desiredModels` list, and the `desiredTier` intent — from this DID's
    /// provider record at `rkey` in one list. Defaults: `active` true
    /// (serving) when absent, `desired` empty when absent, `desiredTier` None
    /// when absent. On any read error returns the serving default with an
    /// empty list and no tier so a transient blip never looks like a stop, a
    /// model change, or a tier change. The agent polls this to honour remote
    /// pause + model changes; the serve loop also restarts on a `desiredTier`
    /// change so the supervisor can re-select the confidential worker binary.
    pub async fn get_provider_control(&self, rkey: &str) -> (bool, Vec<String>, Option<String>) {
        let Ok(listed) = self.list_my_records("dev.cocore.compute.provider").await else {
            return (true, Vec::new(), None);
        };
        let Some(rec) = listed
            .iter()
            .find(|r| r.uri.rsplit('/').next() == Some(rkey))
        else {
            return (true, Vec::new(), None);
        };
        let active = rec
            .value
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let desired = rec
            .value
            .get("desiredModels")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let desired_tier = rec
            .value
            .get("desiredTier")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        (active, desired, desired_tier)
    }

    /// Walk the DID PLC directory to find this DID's PDS host. The
    /// agent only does this when it needs to read records directly
    /// (e.g. dedup); writes still go through the console proxy.
    async fn resolve_pds_endpoint(&self) -> Result<String> {
        if self.did.starts_with("did:plc:") {
            let url = format!("https://plc.directory/{}", self.did);
            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| ProviderError::Pds(format!("plc resolve transport: {e}")))?;
            if !resp.status().is_success() {
                return Err(ProviderError::Pds(format!(
                    "plc resolve {} returned {}",
                    self.did,
                    resp.status()
                )));
            }
            let doc: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ProviderError::Pds(format!("plc resolve decode: {e}")))?;
            let services = doc.get("service").and_then(|s| s.as_array());
            if let Some(arr) = services {
                for svc in arr {
                    if svc.get("id").and_then(|v| v.as_str()) == Some("#atproto_pds") {
                        if let Some(ep) = svc.get("serviceEndpoint").and_then(|v| v.as_str()) {
                            return Ok(ep.to_string());
                        }
                    }
                }
            }
            return Err(ProviderError::Pds(format!(
                "no atproto_pds service in PLC doc for {}",
                self.did
            )));
        }
        // did:web — the doc lives at https://<host>/.well-known/did.json.
        // Honored for completeness; the agent's primary identity is
        // did:plc.
        if let Some(host) = self.did.strip_prefix("did:web:") {
            return Ok(format!("https://{host}"));
        }
        Err(ProviderError::Pds(format!(
            "unsupported DID method: {}",
            self.did
        )))
    }

    pub async fn publish_attestation<R: Serialize>(&self, record: &R) -> Result<PublishedRecord> {
        self.publish("dev.cocore.compute.attestation", record).await
    }

    pub async fn publish_receipt<R: Serialize>(&self, record: &R) -> Result<PublishedRecord> {
        self.publish("dev.cocore.compute.receipt", record).await
    }

    /// Generic publish for any cocore collection. The console proxy
    /// validates that `collection` starts with `dev.cocore.compute.`.
    pub async fn publish<R: Serialize>(
        &self,
        collection: &str,
        record: &R,
    ) -> Result<PublishedRecord> {
        let url = format!(
            "{}/api/pds/createRecord",
            self.api_base.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "collection": collection,
            "record": record,
        });
        tracing::debug!(collection, did = %self.did, "publish via console proxy");

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Pds(format!("transport: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Pds(format!("read body: {e}")))?;
        if !status.is_success() {
            return Err(ProviderError::Pds(format!(
                "console proxy createRecord {collection} returned {status}: {text}"
            )));
        }
        serde_json::from_str(&text).map_err(|e| {
            ProviderError::Pds(format!("decode {collection} response: {e} body={text}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_session(api_base: &str) -> Session {
        Session {
            did: "did:plc:test".into(),
            handle: "test.example".into(),
            api_key: "cocore-fake-key".into(),
            api_base: api_base.into(),
        }
    }

    /// One-shot HTTP stub: handler returns Some((status, body)) for
    /// each accepted connection. Returns the bound port.
    async fn run_stub<F>(handler: F) -> u16
    where
        F: Fn(String) -> Option<(u16, String)> + Send + Sync + 'static,
    {
        use std::convert::Infallible;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(handler);
        let _server: tokio::task::JoinHandle<Infallible> = tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let h = handler.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (status, body) = h(req).unwrap_or((404, "{}".into()));
                    let line = match status {
                        200 => "200 OK",
                        201 => "201 Created",
                        400 => "400 Bad Request",
                        401 => "401 Unauthorized",
                        _ => "500 Internal Server Error",
                    };
                    let resp = format!(
                        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        line,
                        body.len(),
                        body,
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn publish_returns_uri_and_cid_on_success() {
        let port = run_stub(move |req: String| {
            let path = req.lines().next().unwrap_or("");
            if !path.contains("/api/pds/createRecord") {
                return Some((404, "{}".into()));
            }
            // Bearer auth header should carry the API key.
            assert!(
                req.lines()
                    .any(|l| l.to_lowercase().contains("authorization: bearer cocore-")),
                "expected Bearer auth header in request: {req}"
            );
            Some((
                200,
                serde_json::json!({
                    "uri": "at://did:plc:test/dev.cocore.compute.receipt/abc",
                    "cid": "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq",
                })
                .to_string(),
            ))
        })
        .await;

        let session = fake_session(&format!("http://127.0.0.1:{port}"));
        let client = PdsClient::new(session);
        let published = client
            .publish(
                "dev.cocore.compute.receipt",
                &serde_json::json!({"foo": "bar"}),
            )
            .await
            .expect("publish should succeed");
        assert_eq!(
            published.uri,
            "at://did:plc:test/dev.cocore.compute.receipt/abc"
        );
        assert!(published.cid.starts_with("bafy"));
    }

    #[tokio::test]
    async fn publish_propagates_4xx_errors() {
        let port = run_stub(move |_| {
            Some((
                400,
                r#"{"error":"pds createRecord dev.cocore.compute.receipt: bad rkey"}"#.into(),
            ))
        })
        .await;
        let session = fake_session(&format!("http://127.0.0.1:{port}"));
        let client = PdsClient::new(session);
        let err = client
            .publish("dev.cocore.compute.receipt", &serde_json::json!({}))
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("400"), "expected 400 in error, got {msg}");
        assert!(msg.contains("bad rkey"));
    }

    #[tokio::test]
    async fn publish_propagates_401_unauthorized() {
        // If the API key was revoked or never existed, the console
        // returns 401. The agent should surface that to the operator
        // — there's no useful retry.
        let port = run_stub(move |_| Some((401, r#"{"error":"invalid API key"}"#.into()))).await;
        let session = fake_session(&format!("http://127.0.0.1:{port}"));
        let client = PdsClient::new(session);
        let err = client
            .publish("dev.cocore.compute.receipt", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("401"));
    }
}
