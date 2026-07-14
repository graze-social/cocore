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

/// Apple App Attest evidence as it rides in the record. Field names match the
/// lexicon's `appAttest` object (`{ object, keyId }`), both base64.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize)]
pub struct AppAttestEvidence {
    pub object: String,
    pub keyId: String,
}

#[derive(Debug, Clone)]
pub struct AttestationInputs {
    pub provider_did: String,
    pub encryption_pub_key_b64: String,
    /// Short `encScheme` tag for `encryption_pub_key_b64`: `"x25519"` (software,
    /// extractable) or `"p256-ecies-se"` (Secure-Enclave-resident). Emitted only
    /// when not `"x25519"` so best-effort canonical bytes stay minimal.
    pub enc_scheme: String,
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
    /// Optional Apple App Attest evidence (base64 CBOR `object` + `keyId`),
    /// acquired via [`crate::mda_loader::load_appattest`]. Embedded only if it
    /// verifies Apple-App-Attest-rooted AND binds to this signer; the
    /// MDM-free path to hardware-attested.
    pub app_attest: Option<AppAttestEvidence>,
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
    /// Scheme for `encryptionPubKey`: absent/`"x25519"` (software, extractable)
    /// or `"p256-ecies-se"` (Secure-Enclave-resident, non-extractable — required
    /// for the confidential tier). Skipped when x25519 to keep best-effort bytes
    /// minimal (an absent value reads as `"x25519"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encScheme: Option<String>,
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
    pub appAttest: Option<AppAttestEvidence>,
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
    // Seconds-precision RFC3339 strings, NOT `DateTime<Utc>`. The signed
    // canonical body uses `rfc3339()` (SecondsFormat::Secs); storing a
    // `DateTime` here would re-serialize at chrono's default sub-second
    // precision, so the stored record would no longer match the bytes that
    // were signed and every selfSignature check would fail. Storing the exact
    // signed string keeps stored-bytes == signed-bytes. (This mirrors
    // `receipt.rs`, whose `startedAt`/`completedAt` are `String` for the same
    // reason — the divergence here is what stalled settlement in 2026-06.)
    pub attestedAt: String,
    pub expiresAt: String,
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
/// Apple Silicon Secure Boot status. There's no cheap syscall for the boot
/// policy (`bputil` needs sudo), but `system_profiler SPiBridgeDataType`
/// reports it as `Secure Boot: Full Security` — the ONLY level that counts as
/// fully enabled (Reduced / Permissive do not). Returns false on any
/// uncertainty so the confidential posture is never over-claimed. ~1–2s; run
/// once per attestation build (boot + the 23h refresh).
#[cfg(target_os = "macos")]
fn detect_secure_boot() -> bool {
    use std::process::Command;
    let out = match Command::new("/usr/sbin/system_profiler")
        .arg("SPiBridgeDataType")
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return false,
    };
    String::from_utf8_lossy(&out).lines().any(|l| {
        let l = l.trim();
        l.starts_with("Secure Boot:") && l.contains("Full Security")
    })
}

#[cfg(not(target_os = "macos"))]
fn detect_secure_boot() -> bool {
    false
}

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
        // Default to the software scheme; `build_and_publish_attestation`
        // overrides this from the actual encryption key's `enc_scheme()` (and
        // `secure_enclave_available` from the signer's `is_hardware_bound()`).
        enc_scheme: "x25519".into(),
        chip_name,
        hardware_model,
        // Hashed before storage; the stub value is fine.
        serial_number: "stub-serial".into(),
        os_version,
        binary_path,
        // SIP is verified ON before we ever get here: `security::apply_all`
        // runs `csrutil status` at startup and refuses to serve if it's off.
        sip_enabled: true,
        // Apple Silicon Secure Boot policy, measured live (Full Security only).
        // Reduced/Permissive and any read failure report false (the honest
        // floor) so we never over-claim the confidential posture.
        secure_boot_enabled: detect_secure_boot(),
        secure_enclave_available: false,
        authenticated_root_enabled: false,
        rdma_disabled: true,
        mda_cert_chain: Vec::new(),
        app_attest: None,
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

    // App Attest evidence — the MDM-free path to hardware-attested. Same
    // discipline as the MDA chain: embed it ONLY if it verifies
    // Apple-App-Attest-rooted AND binds to this signing key (its credCert nonce
    // commits to sha256(signing pubkey)). An object that doesn't bind is a
    // hardware claim for the wrong key, so drop it and stay self-attested.
    let app_attest: Option<AppAttestEvidence> = match &inputs.app_attest {
        None => None,
        Some(ev) => {
            if crate::appattest::verify_b64(
                &ev.object,
                &ev.keyId,
                &public_key_b64,
                crate::appattest::APP_ATTEST_APP_ID,
            ) {
                Some(ev.clone())
            } else {
                tracing::warn!(
                    "App Attest evidence failed verification or is not bound to our signing key; \
                     dropping it and staying self-attested on the App Attest path"
                );
                None
            }
        }
    };

    // Producer's HONEST self-asserted tier. `attested-confidential` is the
    // CONFIDENTIALITY axis — "the prompt is handled only inside this measured,
    // signed binary, and the operator can't read it." It is ORTHOGONAL to
    // `trustLevel` (the hardware-attestation axis): the bound Apple MDA chain
    // gates `trustLevel: hardware-attested` (computed by the caller from
    // `mda_cert_chain`), NOT the tier. A machine can therefore be
    // self-attested (software) AND attested-confidential — its confidentiality
    // is backed by the in-process native engine + the hardened posture +
    // (off-record) the advisor's APNs code-identity challenge + cdHash
    // known-good gate, while its hardware is not independently Apple-attested.
    // The tier requires the FULL confidential posture; everything else is
    // best-effort. Verifiers recompute this from evidence (known-good set +
    // session key + code-attestation) and never trust the field — but the
    // producer must not over-claim.
    let confidential_capable = inputs.in_process_backend
        && !inputs.get_task_allow
        && inputs.hardened_runtime
        && inputs.library_validation
        && inputs.anti_debug
        && inputs.core_dumps_disabled
        && inputs.env_scrubbed
        && inputs.sip_enabled
        && inputs.secure_boot_enabled
        && inputs.cd_hash.is_some();
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
        // Sign `mdaCertChain` only when non-empty, mirroring the stored
        // record's `#[serde(skip_serializing_if = "Vec::is_empty")]`. An empty
        // chain (the self-attested common case) is absent from BOTH the signed
        // bytes and the stored record, so they stay byte-identical. Signing an
        // empty `[]` that storage then dropped is exactly what made every
        // self-attested attestation unverifiable in 2026-06.
        if !mda_chain_b64.is_empty() {
            map.insert("mdaCertChain".into(), json!(mda_chain_b64));
        }
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
        // Emit encScheme only when not the x25519 default, mirroring the stored
        // record's skip-when-None, so best-effort attestations stay byte-minimal
        // and old verifiers (which read absent as x25519) are unaffected.
        if inputs.enc_scheme != "x25519" {
            map.insert("encScheme".into(), Value::String(inputs.enc_scheme.clone()));
        }
        if let Some(ev) = &app_attest {
            map.insert(
                "appAttest".into(),
                json!({ "object": ev.object, "keyId": ev.keyId }),
            );
        }
    }
    let canonical = to_canonical_bytes(&unsigned)?;
    let sig = signer
        .sign(&canonical)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(AttestationRecord {
        publicKey: public_key_b64,
        encryptionPubKey: inputs.encryption_pub_key_b64,
        encScheme: if inputs.enc_scheme == "x25519" {
            None
        } else {
            Some(inputs.enc_scheme.clone())
        },
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
        appAttest: app_attest,
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
        // Store the exact seconds-precision strings that were signed (NOT the
        // `DateTime`s), so stored-bytes == signed-bytes.
        attestedAt: rfc3339(attested_at),
        expiresAt: rfc3339(expires_at),
    })
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
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
            enc_scheme: "x25519".into(),
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
            app_attest: None,
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
        // No native in-process engine (inProcessBackend=false) → must
        // self-assert best-effort, never attested-confidential. (The MDA chain
        // is irrelevant to the tier; it gates trustLevel only.)
        assert_eq!(rec.tier, "best-effort");
        assert!(!rec.inProcessBackend);
    }

    #[test]
    fn stored_record_canonicalizes_to_the_signed_bytes() {
        // Regression guard for the 2026-06 settlement stall. The record we
        // WRITE to the PDS (serde of `AttestationRecord`) must canonicalize to
        // the EXACT bytes we SIGNED. The stall had two causes, both reproduced
        // here as a single invariant:
        //   * a field signed but dropped on store (`mdaCertChain: []`), and
        //   * timestamps signed at seconds precision but stored as `DateTime`
        //     at sub-second precision.
        // Either makes the stored record's canonical bytes differ from the
        // signed bytes, so the enclave selfSignature no longer verifies against
        // what a consumer reads back — and settlement silently rejects every
        // receipt. Verify the STORED form cryptographically, the way the
        // AppView/exchange does.
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::EncodedPoint;

        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        // Self-attested common case: empty MDA chain, so `mdaCertChain` is
        // absent from BOTH signed and stored forms.
        let inputs = AttestationInputs {
            provider_did: "did:plc:test".into(),
            encryption_pub_key_b64: "abc".into(),
            enc_scheme: "x25519".into(),
            chip_name: "Apple M5 Max".into(),
            hardware_model: "Mac17,6".into(),
            serial_number: "STORE-EQ".into(),
            os_version: "26.5.2".into(),
            binary_path: std::path::PathBuf::from("/nonexistent"),
            sip_enabled: true,
            secure_boot_enabled: true,
            secure_enclave_available: false,
            authenticated_root_enabled: false,
            rdma_disabled: true,
            mda_cert_chain: vec![],
            app_attest: None,
            cd_hash: Some("ab".repeat(20)),
            team_id: Some("4L45P7CP9M".into()),
            hardened_runtime: true,
            library_validation: false,
            get_task_allow: false,
            metallib_hash: None,
            engine_lib_hash: None,
            in_process_backend: false,
            anti_debug: true,
            core_dumps_disabled: true,
            env_scrubbed: true,
        };
        let rec = build(inputs, &*signer).unwrap();

        // Serialize exactly as written to the PDS, strip the signature, and
        // canonicalize — this is precisely what a verifier reconstructs.
        let mut stored: Value = serde_json::to_value(&rec).unwrap();
        let map = stored.as_object_mut().unwrap();
        let sig_der = B64
            .decode(map.remove("selfSignature").unwrap().as_str().unwrap())
            .unwrap();
        // The empty self-attested chain must NOT be present in the stored form
        // (and so must not be in the signed form either).
        assert!(
            !map.contains_key("mdaCertChain"),
            "an empty mdaCertChain must be absent from the stored record"
        );
        let canonical = to_canonical_bytes(&stored).unwrap();

        let pub_bytes = B64.decode(rec.publicKey.as_bytes()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_bytes);
        let vk = VerifyingKey::from_encoded_point(&EncodedPoint::from_bytes(uncompressed).unwrap())
            .unwrap();
        let sig = Signature::from_der(&sig_der).unwrap();
        vk.verify(&canonical, &sig)
            .expect("stored record must verify against the signed canonical bytes");
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
            enc_scheme: "x25519".into(),
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
            app_attest: None,
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
        // tier ⊥ trustLevel: a dropped/absent MDA chain caps the HARDWARE axis
        // (the caller computes trustLevel: self-attested), but does NOT cap the
        // CONFIDENTIALITY tier — a full in-process confidential posture still
        // earns attested-confidential. The chain being dropped only means this
        // machine isn't ALSO hardware-attested.
        assert_eq!(
            rec.tier, "attested-confidential",
            "a full confidential posture earns the tier regardless of the MDA chain"
        );
    }

    #[test]
    fn unverifiable_app_attest_is_dropped_not_embedded() {
        // Same discipline as the MDA chain: bogus App Attest evidence (not an
        // Apple-App-Attest-rooted, signer-bound object) must be dropped, leaving
        // the record self-attested with no `appAttest`. The positive embed path
        // needs a real Apple-rooted object (real device / cross-lang fixture).
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        let mut inputs = AttestationInputs {
            provider_did: "did:plc:test".into(),
            encryption_pub_key_b64: "abc".into(),
            enc_scheme: "x25519".into(),
            chip_name: "Apple M4".into(),
            hardware_model: "Mac15,12".into(),
            serial_number: "AA-TEST".into(),
            os_version: "26.0".into(),
            binary_path: std::path::PathBuf::from("/nonexistent"),
            sip_enabled: true,
            secure_boot_enabled: true,
            secure_enclave_available: true,
            authenticated_root_enabled: true,
            rdma_disabled: true,
            mda_cert_chain: vec![],
            app_attest: None,
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
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        inputs.app_attest = Some(AppAttestEvidence {
            object: B64.encode(b"not-a-real-cbor-attestation-object"),
            keyId: B64.encode([0u8; 32]),
        });
        let rec = build(inputs, &*signer).unwrap();
        assert!(
            rec.appAttest.is_none(),
            "unverifiable App Attest evidence must be dropped, not embedded"
        );
    }
}
