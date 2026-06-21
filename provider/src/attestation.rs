//! Builds and signs `dev.cocore.compute.attestation` records.
//!
//! An attestation snapshots the host's hardware/software state and
//! signs the snapshot with the Secure-Enclave-bound P-256 key. Receipts
//! that strong-ref this attestation inherit its trust level: if the
//! attestation is hardware-attested via Apple MDA, the receipt is too.
//!
//! Refresh schedule (managed by the publisher loop): a fresh
//! attestation is published every 23 hours, one hour before the prior
//! one expires. Receipts produced inside that window strong-ref the
//! current attestation; receipts produced after expiry are invalid.

use crate::canonical::to_canonical_bytes;
use crate::secure_enclave::SigningIdentity;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct AttestationInputs {
    pub provider_did: String,
    pub encryption_pub_key_b64: String,
    pub chip_name: String,
    pub hardware_model: String,
    pub serial_number: String,
    pub os_version: String,
    pub binary_path: std::path::PathBuf,
    pub sip_enabled: bool,
    pub secure_boot_enabled: bool,
    pub secure_enclave_available: bool,
    pub authenticated_root_enabled: bool,
    pub rdma_disabled: bool,
    pub mda_cert_chain: Vec<Vec<u8>>,
    // --- WS-CDHASH: OS-enforced measured identity + hardened-runtime posture
    // (read live via `codesign::read_self`). ---
    pub cd_hash: Option<String>,
    pub team_id: Option<String>,
    pub hardened_runtime: bool,
    pub library_validation: bool,
    pub get_task_allow: bool,
    /// SHA-256 hex of the precompiled Metal shader library the in-process
    /// engine loads. `None` for the subprocess/best-effort backend.
    pub metallib_hash: Option<String>,
    /// SHA-256 hex of the dynamic engine library (libCoCoreMLX.dylib). `None`
    /// for the subprocess/best-effort backend.
    pub engine_lib_hash: Option<String>,
    /// True iff inference runs inside THIS measured binary (native engine),
    /// not an owner-controlled subprocess. The load-bearing confidential bit.
    pub in_process_backend: bool,
    // --- WS-HARDENING: darkbloom-parity startup hardening capability flags. ---
    pub anti_debug: bool,
    pub core_dumps_disabled: bool,
    pub env_scrubbed: bool,
}

// Field names match the lexicon's camelCase wire shape so serde produces
// the right JSON without a renames table.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize)]
pub struct AttestationRecord {
    pub publicKey: String,
    pub encryptionPubKey: String,
    pub chipName: String,
    pub hardwareModel: String,
    pub serialNumberHash: String,
    pub osVersion: String,
    pub binaryHash: String,
    pub sipEnabled: bool,
    pub secureBootEnabled: bool,
    pub secureEnclaveAvailable: bool,
    pub authenticatedRootEnabled: bool,
    pub rdmaDisabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mdaCertChain: Vec<String>, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdHash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teamId: Option<String>,
    pub hardenedRuntime: bool,
    pub libraryValidation: bool,
    pub getTaskAllow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metallibHash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engineLibHash: Option<String>,
    pub inProcessBackend: bool,
    pub antiDebug: bool,
    pub coreDumpsDisabled: bool,
    pub envScrubbed: bool,
    /// Provider's self-asserted confidentiality tier. ADVISORY — verifiers
    /// recompute from evidence; never trusted.
    pub tier: String,
    /// Bytes — Secure Enclave P-256 signature over canonical JSON of
    /// every other field in this struct.
    pub selfSignature: String, // base64
    pub attestedAt: DateTime<Utc>,
    pub expiresAt: DateTime<Utc>,
}

/// Sensible defaults for a self-attested provider — what cocore
/// publishes when no Apple MDA chain is available (i.e. the stock
/// build, no Swift FFI). Values are HONEST about not being hardware
/// claims: secureBoot / secureEnclave / authenticatedRoot all
/// `false`, no MDA cert chain. The signature is still a real P-256
/// over the canonicalised body, so verifiers can confirm "this DID
/// holds the matching private key" — they just can't elevate the
/// attestation's trust level above self-attested.
///
/// Used by `cmd_serve` to publish a fresh attestation on each boot
/// so receipts have something to strong-ref.
pub fn build_stub_inputs(provider_did: &str, encryption_pub_key_b64: &str) -> AttestationInputs {
    let binary_path =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("cocore-provider"));
    let chip_name = sysctl_string("machdep.cpu.brand_string").unwrap_or_else(|| "stub".into());
    let hardware_model = sysctl_string("hw.model").unwrap_or_else(|| "stub".into());
    let os_version = sysctl_string("kern.osproductversion").unwrap_or_else(|| "stub".into());
    // Read the OS-enforced code-signing identity + posture of the running
    // process (live, not a file digest), and the startup hardening posture.
    let cs = crate::codesign::read_self();
    let hp = crate::security::posture();
    AttestationInputs {
        provider_did: provider_did.into(),
        encryption_pub_key_b64: encryption_pub_key_b64.into(),
        chip_name,
        hardware_model,
        // Hashed before storage; the stub value is fine.
        serial_number: "stub-serial".into(),
        os_version,
        binary_path,
        // sysctl exposes `kern.bootargs` etc but reading them
        // reliably across macOS versions is fiddly; we report the
        // honest "we did not verify" state for the stub build.
        sip_enabled: true,
        secure_boot_enabled: false,
        secure_enclave_available: false,
        authenticated_root_enabled: false,
        rdma_disabled: true,
        mda_cert_chain: Vec::new(),
        cd_hash: cs.cd_hash,
        team_id: cs.team_id,
        hardened_runtime: cs.hardened_runtime,
        library_validation: cs.library_validation,
        get_task_allow: cs.get_task_allow,
        // No native engine yet → no measured metallib and the prompt is still
        // handled by the subprocess backend. Honest: not in-process.
        metallib_hash: None,
        engine_lib_hash: None,
        in_process_backend: false,
        anti_debug: hp.anti_debug,
        core_dumps_disabled: hp.core_dumps_disabled,
        env_scrubbed: hp.env_scrubbed,
    }
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &str) -> Option<String> {
    use std::process::Command;
    let out = Command::new("sysctl").arg("-n").arg(name).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(not(target_os = "macos"))]
fn sysctl_string(_name: &str) -> Option<String> {
    None
}

pub fn build(
    inputs: AttestationInputs,
    signer: &dyn SigningIdentity,
) -> anyhow::Result<AttestationRecord> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let attested_at = Utc::now();
    let expires_at = attested_at + Duration::hours(24);

    let public_key_b64 = signer.public_key_b64();
    let binary_hash = hash_file(&inputs.binary_path)?;

    // Only embed an MDA chain that VERIFIES (Apple-rooted, every link,
    // CA constraints) AND is BOUND to this signer — its leaf must certify
    // our signing key. An unverified or stapled chain (a valid Apple chain
    // for someone else's device/key) must NOT ride in the record claiming
    // hardware attestation: drop it and stay self-attested. When bound, the
    // serialNumberHash is taken from the verified leaf's device serial so
    // it reflects the real device, not the local stub.
    let mut serial_hash = hash_serial(&inputs.serial_number, &inputs.provider_did);
    let empty: Vec<Vec<u8>> = Vec::new();
    let mda_chain: &[Vec<u8>] = if inputs.mda_cert_chain.is_empty() {
        &inputs.mda_cert_chain
    } else {
        match crate::mda::verify_chain(&inputs.mda_cert_chain) {
            // Bind to our signing key by EITHER rule (leaf==key, or the
            // freshness-code commitment sha256(signing pubkey)). See
            // mda::MdaResult::binds_key + the BINDING CONTRACT in mda_loader.rs.
            Ok(res) if res.valid && res.binds_key(&signer.public_key_bytes()) => {
                if let Some(serial) = res.device_serial.as_deref() {
                    serial_hash = hash_serial(serial, &inputs.provider_did);
                }
                &inputs.mda_cert_chain
            }
            Ok(res) if res.valid => {
                tracing::warn!(
                    "MDA chain verifies but is not bound to our signing key \
                     (neither leaf-key nor freshness-code); dropping it and staying self-attested"
                );
                &empty
            }
            other => {
                let why = match other {
                    Ok(res) => format!("{:?}", res.error),
                    Err(e) => format!("{e}"),
                };
                tracing::warn!(reason = %why, "MDA chain failed verification; dropping it and staying self-attested");
                &empty
            }
        }
    };
    let mda_chain_b64: Vec<String> = mda_chain.iter().map(|c| B64.encode(c)).collect();

    // Producer's HONEST self-asserted tier. `attested-confidential` requires
    // the full confidential posture AND a bound MDA chain that survived
    // verification above; everything else is best-effort. Verifiers recompute
    // this from evidence (and the requester's known-good set + session key) and
    // never trust the field — but the producer must not over-claim.
    let confidential_capable = inputs.in_process_backend
        && !inputs.get_task_allow
        && inputs.hardened_runtime
        && inputs.library_validation
        && inputs.anti_debug
        && inputs.core_dumps_disabled
        && inputs.env_scrubbed
        && inputs.sip_enabled
        && inputs.secure_boot_enabled
        && inputs.cd_hash.is_some()
        && !mda_chain_b64.is_empty();
    let tier = if confidential_capable {
        "attested-confidential"
    } else {
        "best-effort"
    }
    .to_string();

    // Build the unsigned record as an ordered object, canonicalize, sign, and
    // then produce the typed record with the signature attached. Optional
    // measured fields are inserted only when present so the canonical bytes of
    // a best-effort attestation stay minimal.
    let mut unsigned = json!({
        "publicKey": public_key_b64,
        "encryptionPubKey": inputs.encryption_pub_key_b64,
        "chipName": inputs.chip_name,
        "hardwareModel": inputs.hardware_model,
        "serialNumberHash": serial_hash,
        "osVersion": inputs.os_version,
        "binaryHash": binary_hash,
        "sipEnabled": inputs.sip_enabled,
        "secureBootEnabled": inputs.secure_boot_enabled,
        "secureEnclaveAvailable": inputs.secure_enclave_available,
        "authenticatedRootEnabled": inputs.authenticated_root_enabled,
        "rdmaDisabled": inputs.rdma_disabled,
        "mdaCertChain": mda_chain_b64,
        "hardenedRuntime": inputs.hardened_runtime,
        "libraryValidation": inputs.library_validation,
        "getTaskAllow": inputs.get_task_allow,
        "inProcessBackend": inputs.in_process_backend,
        "antiDebug": inputs.anti_debug,
        "coreDumpsDisabled": inputs.core_dumps_disabled,
        "envScrubbed": inputs.env_scrubbed,
        "tier": tier,
        "attestedAt": rfc3339(attested_at),
        "expiresAt": rfc3339(expires_at),
    });
    if let Value::Object(map) = &mut unsigned {
        if let Some(cd) = &inputs.cd_hash {
            map.insert("cdHash".into(), Value::String(cd.clone()));
        }
        if let Some(tid) = &inputs.team_id {
            map.insert("teamId".into(), Value::String(tid.clone()));
        }
        if let Some(mh) = &inputs.metallib_hash {
            map.insert("metallibHash".into(), Value::String(mh.clone()));
        }
        if let Some(eh) = &inputs.engine_lib_hash {
            map.insert("engineLibHash".into(), Value::String(eh.clone()));
        }
    }
    let canonical = to_canonical_bytes(&unsigned)?;
    let sig = signer
        .sign(&canonical)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(AttestationRecord {
        publicKey: public_key_b64,
        encryptionPubKey: inputs.encryption_pub_key_b64,
        chipName: inputs.chip_name,
        hardwareModel: inputs.hardware_model,
        serialNumberHash: serial_hash,
        osVersion: inputs.os_version,
        binaryHash: binary_hash,
        sipEnabled: inputs.sip_enabled,
        secureBootEnabled: inputs.secure_boot_enabled,
        secureEnclaveAvailable: inputs.secure_enclave_available,
        authenticatedRootEnabled: inputs.authenticated_root_enabled,
        rdmaDisabled: inputs.rdma_disabled,
        mdaCertChain: mda_chain_b64,
        cdHash: inputs.cd_hash,
        teamId: inputs.team_id,
        hardenedRuntime: inputs.hardened_runtime,
        libraryValidation: inputs.library_validation,
        getTaskAllow: inputs.get_task_allow,
        metallibHash: inputs.metallib_hash,
        engineLibHash: inputs.engine_lib_hash,
        inProcessBackend: inputs.in_process_backend,
        antiDebug: inputs.anti_debug,
        coreDumpsDisabled: inputs.core_dumps_disabled,
        envScrubbed: inputs.env_scrubbed,
        tier,
        selfSignature: B64.encode(&sig),
        attestedAt: attested_at,
        expiresAt: expires_at,
    })
}

fn rfc3339(t: DateTime<Utc>) -> Value {
    Value::String(t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn hash_serial(serial: &str, did: &str) -> String {
    let mut h = Sha256::new();
    h.update(serial.as_bytes());
    h.update(b"|");
    h.update(did.as_bytes());
    hex::encode(h.finalize())
}

fn hash_file(path: &std::path::Path) -> anyhow::Result<String> {
    if !path.exists() {
        // In dev/CI we hash the path string itself so the field is
        // never empty. Real builds run from a code-signed binary.
        let mut h = Sha256::new();
        h.update(path.to_string_lossy().as_bytes());
        return Ok(hex::encode(h.finalize()));
    }
    let mut h = Sha256::new();
    let mut f = std::fs::File::open(path)?;
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_enclave::{identity_lock, load_or_create_identity};

    #[test]
    fn attestation_round_trips() {
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        let inputs = AttestationInputs {
            provider_did: "did:plc:test".into(),
            encryption_pub_key_b64: "abc".into(),
            chip_name: "Apple M3 Max".into(),
            hardware_model: "Mac15,8".into(),
            serial_number: "ABC123".into(),
            os_version: "15.0".into(),
            binary_path: std::path::PathBuf::from("/nonexistent"),
            sip_enabled: true,
            secure_boot_enabled: true,
            secure_enclave_available: true,
            authenticated_root_enabled: true,
            rdma_disabled: true,
            mda_cert_chain: vec![],
            cd_hash: Some("ab".repeat(20)),
            team_id: Some("TEAM123456".into()),
            hardened_runtime: true,
            library_validation: true,
            get_task_allow: false,
            metallib_hash: None,
            engine_lib_hash: None,
            in_process_backend: false,
            anti_debug: true,
            core_dumps_disabled: true,
            env_scrubbed: true,
        };
        let rec = build(inputs, &*signer).unwrap();
        assert!(!rec.selfSignature.is_empty());
        assert_eq!(rec.serialNumberHash.len(), 64);
        assert!(rec.expiresAt > rec.attestedAt);
        // No MDA chain + no native engine → must self-assert best-effort,
        // never attested-confidential.
        assert_eq!(rec.tier, "best-effort");
        assert!(!rec.inProcessBackend);
    }

    #[test]
    fn unverifiable_mda_chain_is_dropped_not_embedded() {
        // The provider must NOT embed a chain it can't verify against the
        // Apple root AND bind to its signing key — publishing one would be
        // a "hardware" claim taken on faith. Synthetic DER (not a real
        // Apple-rooted, signer-bound chain) is dropped; the record stays
        // self-attested with an empty mdaCertChain.
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        let inputs = AttestationInputs {
            provider_did: "did:plc:test".into(),
            encryption_pub_key_b64: "abc".into(),
            chip_name: "Apple M4".into(),
            hardware_model: "Mac15,12".into(),
            serial_number: "MDA-TEST".into(),
            os_version: "26.0".into(),
            binary_path: std::path::PathBuf::from("/nonexistent"),
            sip_enabled: true,
            secure_boot_enabled: true,
            secure_enclave_available: true,
            authenticated_root_enabled: true,
            rdma_disabled: true,
            mda_cert_chain: vec![b"leaf-cert-der".to_vec(), b"intermediate-cert-der".to_vec()],
            cd_hash: Some("cd".repeat(20)),
            team_id: None,
            hardened_runtime: true,
            library_validation: true,
            get_task_allow: false,
            metallib_hash: None,
            engine_lib_hash: None,
            in_process_backend: true,
            anti_debug: true,
            core_dumps_disabled: true,
            env_scrubbed: true,
        };
        let rec = build(inputs, &*signer).unwrap();
        assert!(
            rec.mdaCertChain.is_empty(),
            "an unverifiable / unbound chain must be dropped, not embedded"
        );
        // Even with a full in-process confidential posture, a DROPPED MDA chain
        // means the producer must NOT self-assert attested-confidential.
        assert_eq!(
            rec.tier, "best-effort",
            "without a bound MDA chain the tier caps at best-effort"
        );
    }
}
