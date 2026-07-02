//! Device-pair code flow.
//!
//! The Rust agent is headless. To bind a machine to an ATProto identity
//! we use a "pair code" similar to `gh auth login`:
//!
//!   1. Agent calls `POST /xrpc/dev.cocore.devicePair.start` on the
//!      console. Console returns an 8-character user-visible code and an
//!      opaque `device_id`.
//!   2. Agent prints the code, opens the user's browser to
//!      `https://<console>/devices/new?code=XXXXXXXX`.
//!   3. User signs in with ATProto OAuth (DPoP/PAR/PKCE) in the browser
//!      and confirms the pairing.
//!   4. Console mints an API key bound to the user's DID. The agent
//!      uses that key to call the console's PDS proxy
//!      (`POST /api/pds/createRecord`) for every
//!      record it wants to publish; the console signs each call with
//!      its DPoP-aware OAuth session.
//!   5. Agent polls `dev.cocore.devicePair.poll(device_id)` until it
//!      receives the session blob (DID + handle + apiKey + apiBase).
//!   6. Agent persists the session to `~/.cocore/session.json`.

use serde::{Deserialize, Serialize};

/// Connect + total request timeouts for the device-pair HTTP calls. A slow or
/// hostile console must not be able to wedge the pairing flow indefinitely;
/// each call here is a small JSON request/response with no streaming body.
const PAIR_CONNECT_TIMEOUT_SECS: u64 = 10;
const PAIR_REQUEST_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairStartResponse {
    pub device_id: String,
    pub user_code: String,
    pub verification_uri: String,
    pub poll_interval_secs: u64,
    pub expires_in_secs: u64,
}

/// What we get back at the end of a successful pair flow.
///
/// Fields:
/// - `did`, `handle` — the paired ATProto identity. The agent's
///   record publishes are credited to this DID.
/// - `api_key` — `cocore-...` Bearer token the agent presents to the
///   console proxy. Bound to `did` server-side.
/// - `api_base` — console URL the agent appends
///   `/api/pds/createRecord` to. e.g.,
///   `https://cocore.dev`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub did: String,
    pub handle: String,
    pub api_key: String,
    pub api_base: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OauthError {
    #[error("pair code expired before user completed sign-in")]
    Expired,
    #[error("user denied the pairing request")]
    Denied,
    #[error("transport: {0}")]
    Transport(String),
}

/// Begin a device-pair flow. Returns the user code to print; caller is
/// responsible for showing it and opening the browser.
pub async fn start_pair(console_url: &str) -> Result<PairStartResponse, OauthError> {
    let url = format!(
        "{}/api/xrpc/dev.cocore.devicePair.start",
        console_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(PAIR_CONNECT_TIMEOUT_SECS))
        .timeout(std::time::Duration::from_secs(PAIR_REQUEST_TIMEOUT_SECS))
        .build()
        .map_err(|e| OauthError::Transport(e.to_string()))?;
    let resp = client
        .post(&url)
        .send()
        .await
        .map_err(|e| OauthError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(OauthError::Transport(format!(
            "console returned {} from devicePair.start",
            resp.status()
        )));
    }
    resp.json::<PairStartResponse>()
        .await
        .map_err(|e| OauthError::Transport(e.to_string()))
}

/// Poll for completion. Returns a [`Session`] once the user has
/// approved, or an error if denied / expired / unknown.
pub async fn poll_pair(console_url: &str, device_id: &str) -> Result<Session, OauthError> {
    let base = console_url.trim_end_matches('/').to_string();
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(PAIR_CONNECT_TIMEOUT_SECS))
        .timeout(std::time::Duration::from_secs(PAIR_REQUEST_TIMEOUT_SECS))
        .build()
        .map_err(|e| OauthError::Transport(e.to_string()))?;

    let interval = std::time::Duration::from_secs(2);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);

    loop {
        if std::time::Instant::now() > deadline {
            return Err(OauthError::Expired);
        }
        let resp = client
            .get(format!(
                "{}/api/xrpc/dev.cocore.devicePair.poll?deviceId={}",
                base, device_id
            ))
            .send()
            .await
            .map_err(|e| OauthError::Transport(e.to_string()))?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| serde_json::json!({}));
        let kind = body.get("status").and_then(|v| v.as_str()).unwrap_or("");
        match kind {
            "session" => {
                let s: Session = serde_json::from_value(body["session"].clone())
                    .map_err(|e| OauthError::Transport(e.to_string()))?;
                return Ok(s);
            }
            "pending" => tokio::time::sleep(interval).await,
            "denied" => return Err(OauthError::Denied),
            "expired" | "consumed" => return Err(OauthError::Expired),
            _ => {
                return Err(OauthError::Transport(format!(
                    "unexpected pair status {kind:?} (HTTP {status})"
                )))
            }
        }
    }
}

/// Persist a session to the macOS keychain. On non-macOS, falls back to
/// `~/.cocore/session.json` with mode 0600.
pub fn store_session(session: &Session) -> anyhow::Result<()> {
    let dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("no home directory"))?
        .join(".cocore");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("session.json");
    let json = serde_json::to_string(session)?;
    std::fs::write(&path, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(())
}

/// Load a previously-stored session. Returns `None` if nothing is stored.
pub fn load_session() -> anyhow::Result<Option<Session>> {
    let Some(home) = dirs::home_dir() else {
        return Ok(None);
    };
    let path = home.join(".cocore/session.json");
    if !path.exists() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&json)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_session_through_disk() {
        // Use a temp dir as $HOME to avoid stomping on a real session.
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", tmp.path());
        let s = Session {
            did: "did:plc:test".into(),
            handle: "alice.example".into(),
            api_key: "cocore-test-key".into(),
            api_base: "https://console.example".into(),
        };
        store_session(&s).unwrap();
        let loaded = load_session().unwrap().unwrap();
        assert_eq!(loaded.did, s.did);
    }
}
