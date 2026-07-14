//! Apple App Attest attestation verification.
//!
//! The MDM-free path to `trustLevel: hardware-attested`. Parallel to
//! [`crate::mda`] (which verifies an MDA x509 chain), this module verifies an
//! Apple App Attest *attestation object* — a CBOR/WebAuthn-shaped blob produced
//! by `DCAppAttestService` — and confirms it is **bound to the provider's
//! receipt-signing key** via the credential certificate's nonce extension.
//!
//! ## Why a separate verifier
//!
//! App Attest is a different beast from MDA: a different Apple root (the App
//! Attest Root CA, not the Enterprise Attestation Root), a CBOR container
//! instead of a bare cert chain, and the key binding lives in a nonce that
//! commits to a caller-chosen `clientDataHash` rather than in a freshness OID.
//! The helper (`provider/spikes/app-attest`) sets
//! `clientDataHash = sha256(signingPubKey)`, so the binding check here is:
//!
//! ```text
//! nonce == sha256( authData ‖ sha256(signingPubKey) )   ==  credCert ext 1.2.840.113635.100.8.2
//! ```
//!
//! ## Verification steps (Apple "Validating Apps That Connect to Your Server")
//!
//!   1. CBOR-decode the object; require `fmt == "apple-appattest"`.
//!   2. Verify the `attStmt.x5c` chain (leaf = credCert, then the App Attest
//!      intermediate) up to the embedded Apple App Attest Root CA: every
//!      adjacent signature, validity windows, and BasicConstraints (leaf is an
//!      end-entity, the issuer is a CA).
//!   3. Recompute `nonce = sha256(authData ‖ clientDataHash)` where
//!      `clientDataHash = sha256(signingPubKey)`, and require it to equal the
//!      OCTET STRING inside the credCert's `1.2.840.113635.100.8.2` extension.
//!      THIS is the binding to the signing key.
//!   4. `credentialId` in authData == `sha256(credCert uncompressed pubkey)`,
//!      and that also equals the claimed `keyId`.
//!   5. authData's `rpIdHash == sha256(appId)`, the AAGUID is the genuine
//!      App-Attest value (production by default), and the AT flag is set.
//!
//! What we deliberately do NOT do (matching the MDA module's posture): CRL/OCSP
//! revocation (App Attest leaf certs are short-lived), and the App Attest
//! *receipt* fraud-metric exchange with Apple (a v2 freshness concern — see the
//! handoff). The object is self-verifying offline against the embedded root,
//! honoring invariant #2.

use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Apple App Attest Root CA, P-384, valid 2020 → 2045.
/// Source: <https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>
/// (SHA-256 fingerprint 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32).
/// Distinct from the Enterprise Attestation Root the MDA path embeds — we ship both.
pub const APPLE_APP_ATTEST_ROOT_CA_PEM: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw\n",
    "JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK\n",
    "QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa\n",
    "Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv\n",
    "biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y\n",
    "bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh\n",
    "NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au\n",
    "Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/\n",
    "MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw\n",
    "CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn\n",
    "53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV\n",
    "oyFraWVIyd/dganmrduC1bmTBGwD\n",
    "-----END CERTIFICATE-----\n"
);

/// Apple's nonce extension OID 1.2.840.113635.100.8.2, as the pre-computed DER
/// component suffix (same encoding scheme `mda.rs` uses for its OID constants).
const OID_APP_ATTEST_NONCE: &[u8] = &[42, 134, 72, 134, 247, 99, 100, 8, 2];

/// AAGUID stamped into authData for genuine production App Attest:
/// ASCII "appattest" padded to 16 bytes with zeros.
pub const AAGUID_PRODUCTION: &[u8; 16] = &[
    0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0, 0, 0, 0, 0, 0, 0,
];
/// AAGUID for the development environment: ASCII "appattestdevelop" (16 bytes).
pub const AAGUID_DEVELOPMENT: &[u8; 16] = b"appattestdevelop";

/// WebAuthn authenticator-data "attested credential data included" flag.
const FLAG_AT: u8 = 0x40;

/// The cocore provider App ID — "TEAMID.bundleID". App Attest's rpIdHash is
/// `sha256` of this; an attestation for any other App ID is rejected. Matches
/// the entitlements in `provider/spikes/app-attest/helper/entitlements.plist`
/// and `provider/cocore-provider.entitlements`.
pub const APP_ATTEST_APP_ID: &str = "4L45P7CP9M.dev.cocore.provider";

#[derive(Debug, Clone, Default)]
pub struct AppAttestResult {
    pub valid: bool,
    /// The attested App Attest public key as the uncompressed EC point
    /// (0x04‖X‖Y, 65 bytes). NB: this is the App Attest key, NOT the signing
    /// key — the binding to the signing key is the nonce check, not this field.
    pub attested_pubkey_uncompressed: Vec<u8>,
    /// `sha256(attested_pubkey_uncompressed)` — equals the authData credentialId
    /// and the claimed keyId.
    pub key_id: Vec<u8>,
    pub aaguid: Vec<u8>,
    pub rp_id_hash: Vec<u8>,
    /// True iff the nonce extension commits to `sha256(authData ‖ sha256(signingPubKey))`.
    pub binds_signing_key: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AppAttestError {
    #[error("CBOR decode: {0}")]
    Cbor(String),
    #[error("attestation object missing or malformed field: {0}")]
    Shape(String),
    #[error("unexpected fmt {0:?}, want \"apple-appattest\"")]
    BadFmt(String),
    #[error("parse trust anchor: {0}")]
    BadTrustAnchor(String),
    #[error("parse cert {index}: {message}")]
    Parse { index: usize, message: String },
    #[error("signature verification failed for cert {index}: {message}")]
    BadSignature { index: usize, message: String },
    #[error("cert {index} is not valid at {at}")]
    NotValid { index: usize, at: String },
    #[error("CA constraint violation for cert {index}: {message}")]
    CaConstraint { index: usize, message: String },
    #[error("credCert has no nonce extension (OID 1.2.840.113635.100.8.2)")]
    NoNonceExtension,
    #[error("malformed nonce extension")]
    BadNonceExtension,
    #[error("nonce mismatch: attestation is not bound to the signing key")]
    NonceMismatch,
    #[error("authData too short ({0} bytes)")]
    ShortAuthData(usize),
    #[error("attested-credential-data flag (AT) not set in authData")]
    NoAttestedCredentialData,
    #[error("unrecognized AAGUID {0} (not genuine App Attest hardware)")]
    BadAaguid(String),
    #[error("credentialId != sha256(attested pubkey)")]
    CredIdMismatch,
    #[error("keyId != credentialId")]
    KeyIdMismatch,
}

/// Verify an App Attest object against the embedded Apple App Attest Root CA,
/// at the current time, requiring the production AAGUID.
///
/// * `object_der` — the CBOR attestation object bytes.
/// * `key_id` — the claimed App Attest key id (32 bytes, = sha256(attested pubkey)).
/// * `signing_pubkey_raw` — the decoded `attestation.publicKey` (64-byte raw X‖Y).
/// * `app_id` — "TEAMID.bundleID", e.g. "4L45P7CP9M.dev.cocore.provider".
pub fn verify(
    object_der: &[u8],
    key_id: &[u8],
    signing_pubkey_raw: &[u8],
    app_id: &str,
) -> Result<AppAttestResult, AppAttestError> {
    let root_der =
        pem_to_der(APPLE_APP_ATTEST_ROOT_CA_PEM).map_err(AppAttestError::BadTrustAnchor)?;
    verify_against(
        object_der,
        key_id,
        signing_pubkey_raw,
        app_id,
        &root_der,
        &chrono::Utc::now(),
        false,
    )
}

/// As [`verify`], but against a caller-supplied trust anchor / clock, and with
/// the development AAGUID optionally allowed. The test path uses this with a
/// synthetic root; the production path uses [`verify`].
pub fn verify_against(
    object_der: &[u8],
    key_id: &[u8],
    signing_pubkey_raw: &[u8],
    app_id: &str,
    root_ca_der: &[u8],
    now: &chrono::DateTime<chrono::Utc>,
    allow_development: bool,
) -> Result<AppAttestResult, AppAttestError> {
    // --- 1. CBOR-decode the attestation object. ---
    let value: ciborium::value::Value =
        ciborium::de::from_reader(object_der).map_err(|e| AppAttestError::Cbor(format!("{e}")))?;
    let obj = AttestationObject::from_cbor(&value)?;
    if obj.fmt != "apple-appattest" {
        return Err(AppAttestError::BadFmt(obj.fmt));
    }
    if obj.x5c.is_empty() {
        return Err(AppAttestError::Shape("attStmt.x5c is empty".into()));
    }

    // --- 2. Verify the x5c chain to the App Attest root. ---
    let mut parsed: Vec<X509Certificate> = Vec::with_capacity(obj.x5c.len());
    for (i, der) in obj.x5c.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der).map_err(|e| AppAttestError::Parse {
            index: i,
            message: format!("{e}"),
        })?;
        parsed.push(cert);
    }
    let (_, root) = X509Certificate::from_der(root_ca_der)
        .map_err(|e| AppAttestError::BadTrustAnchor(format!("{e}")))?;

    let now_unix = now.timestamp();
    let valid_at = |cert: &X509Certificate, idx: usize| -> Result<(), AppAttestError> {
        let nb = cert.validity().not_before.timestamp();
        let na = cert.validity().not_after.timestamp();
        if now_unix < nb || now_unix > na {
            return Err(AppAttestError::NotValid {
                index: idx,
                at: now.to_rfc3339(),
            });
        }
        Ok(())
    };
    for (i, cert) in parsed.iter().enumerate() {
        valid_at(cert, i)?;
    }
    valid_at(&root, usize::MAX)?;

    // certs[i] signed by certs[i+1]; top of chain signed by the root.
    for i in 0..(parsed.len().saturating_sub(1)) {
        parsed[i]
            .verify_signature(Some(parsed[i + 1].public_key()))
            .map_err(|e| AppAttestError::BadSignature {
                index: i,
                message: format!("{e:?}"),
            })?;
    }
    let top = &parsed[parsed.len() - 1];
    top.verify_signature(Some(root.public_key()))
        .map_err(|e| AppAttestError::BadSignature {
            index: parsed.len() - 1,
            message: format!("{e:?}"),
        })?;

    // BasicConstraints: leaf is an end-entity, every issuer in the chain is a CA.
    // Blocks the same leaf-as-issuer forgery the MDA verifier guards against.
    use x509_parser::extensions::ParsedExtension;
    for (i, cert) in parsed.iter().enumerate() {
        let is_ca = cert.extensions().iter().any(
            |ext| matches!(ext.parsed_extension(), ParsedExtension::BasicConstraints(bc) if bc.ca),
        );
        if i == 0 && is_ca {
            return Err(AppAttestError::CaConstraint {
                index: 0,
                message: "leaf (credCert) must be an end-entity, not a CA".into(),
            });
        }
        if i > 0 && !is_ca {
            return Err(AppAttestError::CaConstraint {
                index: i,
                message: format!("chain cert {i} is not a CA but signs cert {}", i - 1),
            });
        }
    }

    let cred_cert = &parsed[0];

    // --- 3. Recompute the nonce and check the credCert nonce extension. ---
    // clientDataHash = sha256(signing pubkey) — the binding the helper chose.
    let client_data_hash = Sha256::digest(signing_pubkey_raw);
    let mut nonce_in = Vec::with_capacity(obj.auth_data.len() + 32);
    nonce_in.extend_from_slice(&obj.auth_data);
    nonce_in.extend_from_slice(&client_data_hash);
    let expected_nonce = Sha256::digest(&nonce_in);

    let nonce_ext = cred_cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.as_bytes() == OID_APP_ATTEST_NONCE)
        .ok_or(AppAttestError::NoNonceExtension)?;
    let got_nonce =
        parse_nonce_extension(nonce_ext.value).ok_or(AppAttestError::BadNonceExtension)?;
    if !ct_eq(&got_nonce, expected_nonce.as_slice()) {
        return Err(AppAttestError::NonceMismatch);
    }

    // --- 4. credCert pubkey → credentialId, cross-check authData + keyId. ---
    let attested_pubkey = {
        let raw = cred_cert.public_key().subject_public_key.data.as_ref();
        if raw.len() != 65 || raw[0] != 0x04 {
            return Err(AppAttestError::Shape(format!(
                "credCert public key is not an uncompressed P-256 point ({} bytes)",
                raw.len()
            )));
        }
        raw.to_vec()
    };
    let pubkey_hash = Sha256::digest(&attested_pubkey);

    // --- 5. Parse authData and validate rpIdHash / AAGUID / credentialId. ---
    let ad = parse_auth_data(&obj.auth_data)?;
    let rp_id_expected = Sha256::digest(app_id.as_bytes());
    // rpIdHash mismatch is fatal — the attestation is for a different App ID.
    if !ct_eq(&ad.rp_id_hash, rp_id_expected.as_slice()) {
        return Err(AppAttestError::Shape("rpIdHash != sha256(appId)".into()));
    }
    let aaguid_ok = ad.aaguid == AAGUID_PRODUCTION
        || (allow_development && ad.aaguid.as_slice() == AAGUID_DEVELOPMENT.as_slice());
    if !aaguid_ok {
        return Err(AppAttestError::BadAaguid(hex::encode(&ad.aaguid)));
    }
    if !ct_eq(&ad.credential_id, pubkey_hash.as_slice()) {
        return Err(AppAttestError::CredIdMismatch);
    }
    if !ct_eq(key_id, pubkey_hash.as_slice()) {
        return Err(AppAttestError::KeyIdMismatch);
    }

    Ok(AppAttestResult {
        valid: true,
        attested_pubkey_uncompressed: attested_pubkey,
        key_id: pubkey_hash.to_vec(),
        aaguid: ad.aaguid,
        rp_id_hash: ad.rp_id_hash,
        binds_signing_key: true,
    })
}

/// Convenience: decode base64 `object` + `keyId` + `publicKey` and verify.
/// Returns `true` iff the App Attest evidence is valid AND bound to `public_key_b64`.
pub fn verify_b64(object_b64: &str, key_id_b64: &str, public_key_b64: &str, app_id: &str) -> bool {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let (Ok(object), Ok(key_id), Ok(pubkey)) = (
        B64.decode(object_b64),
        B64.decode(key_id_b64),
        B64.decode(public_key_b64),
    ) else {
        return false;
    };
    matches!(
        verify(&object, &key_id, &pubkey, app_id),
        Ok(res) if res.valid && res.binds_signing_key
    )
}

// ---- App Attest ASSERTIONS (ADR-0003) ----
//
// An attestation OBJECT (above) is a one-time proof a key was generated in the
// Secure Enclave. An ASSERTION is the ongoing signature: `generateAssertion`
// signs `authenticatorData ‖ clientDataHash` with the SE key, which can't be
// exported or produced off-device. When the confidential identity IS the App
// Attest key (`keyId == sha256(uncompressed publicKey)`), every record signature
// becomes an assertion over `clientDataHash = sha256(canonical message)`.

/// Verify an App Attest assertion over `message`, against the SE key that IS the
/// signing identity (`public_key_raw` = raw 64-byte X‖Y). Checks the ES256
/// signature over `authenticatorData ‖ sha256(message)` and that the assertion's
/// rpIdHash == sha256(app_id). Mirror of `verifyAppAttestAssertion` (appattest.ts).
pub fn verify_assertion(
    public_key_raw: &[u8],
    assertion_cbor: &[u8],
    message: &[u8],
    app_id: &str,
) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;

    // CBOR: { "signature": bstr, "authenticatorData": bstr }.
    let Ok(val): Result<ciborium::value::Value, _> = ciborium::from_reader(assertion_cbor) else {
        return false;
    };
    let Some(map) = val.as_map() else {
        return false;
    };
    let get = |key: &str| {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    };
    let (Some(signature), Some(auth_data)) = (
        get("signature").and_then(|v| v.as_bytes()),
        get("authenticatorData").and_then(|v| v.as_bytes()),
    ) else {
        return false;
    };
    // authenticatorData = rpIdHash(32) ‖ flags(1) ‖ signCount(4); assertions omit
    // attested-credential-data, so 37 bytes is the minimum.
    if auth_data.len() < 37 {
        return false;
    }
    if auth_data[..32] != Sha256::digest(app_id.as_bytes())[..] {
        return false;
    }
    if public_key_raw.len() != 64 {
        return false;
    }
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(public_key_raw);
    let Ok(point) = EncodedPoint::from_bytes(&uncompressed) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_encoded_point(&point) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(signature) else {
        return false;
    };
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(auth_data);
    signed.extend_from_slice(&Sha256::digest(message));
    vk.verify(&signed, &sig).is_ok()
}

/// Base64 wrapper over [`verify_assertion`] (mirrors `verify_b64`).
pub fn verify_assertion_b64(
    public_key_b64: &str,
    assertion_b64: &str,
    message: &[u8],
    app_id: &str,
) -> bool {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let (Ok(pk), Ok(a)) = (B64.decode(public_key_b64), B64.decode(assertion_b64)) else {
        return false;
    };
    verify_assertion(&pk, &a, message, app_id)
}

/// Residency predicate (ADR-0003): does the App-Attest-attested key EQUAL the
/// signing key? A bound attestation object proves a genuine SE key was attested,
/// but binds to the signing key only via clientData — so a genuine SE key can
/// attest a pointer to a SEPARATE (software) signing key, still portable. Only
/// equality proves the signing private key itself is non-exportable.
/// `attested_uncompressed` is 65 bytes (0x04‖X‖Y); `signing_pubkey_raw` is 64.
/// Mirror of `attestedKeyMatchesSigningKey` (appattest.ts).
pub fn attested_key_matches_signing_key(
    attested_uncompressed: &[u8],
    signing_pubkey_raw: &[u8],
) -> bool {
    attested_uncompressed.len() == 65
        && signing_pubkey_raw.len() == 64
        && attested_uncompressed[0] == 0x04
        && attested_uncompressed[1..] == *signing_pubkey_raw
}

// ---- internals ----

struct AttestationObject {
    fmt: String,
    x5c: Vec<Vec<u8>>,
    auth_data: Vec<u8>,
}

impl AttestationObject {
    fn from_cbor(v: &ciborium::value::Value) -> Result<Self, AppAttestError> {
        let map = v
            .as_map()
            .ok_or_else(|| AppAttestError::Shape("top-level is not a CBOR map".into()))?;
        let get = |key: &str| {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, val)| val)
        };

        let fmt = get("fmt")
            .and_then(|x| x.as_text())
            .ok_or_else(|| AppAttestError::Shape("fmt".into()))?
            .to_string();
        let att_stmt = get("attStmt")
            .and_then(|x| x.as_map())
            .ok_or_else(|| AppAttestError::Shape("attStmt".into()))?;
        let x5c_val = att_stmt
            .iter()
            .find(|(k, _)| k.as_text() == Some("x5c"))
            .map(|(_, val)| val)
            .and_then(|x| x.as_array())
            .ok_or_else(|| AppAttestError::Shape("attStmt.x5c".into()))?;
        let mut x5c = Vec::with_capacity(x5c_val.len());
        for c in x5c_val {
            x5c.push(
                c.as_bytes()
                    .ok_or_else(|| AppAttestError::Shape("attStmt.x5c[] not bytes".into()))?
                    .clone(),
            );
        }
        let auth_data = get("authData")
            .and_then(|x| x.as_bytes())
            .ok_or_else(|| AppAttestError::Shape("authData".into()))?
            .clone();
        Ok(AttestationObject {
            fmt,
            x5c,
            auth_data,
        })
    }
}

struct AuthData {
    rp_id_hash: Vec<u8>,
    aaguid: Vec<u8>,
    credential_id: Vec<u8>,
}

fn parse_auth_data(ad: &[u8]) -> Result<AuthData, AppAttestError> {
    // rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) | credIdLen(2) | credId(L) | cose...
    if ad.len() < 37 {
        return Err(AppAttestError::ShortAuthData(ad.len()));
    }
    let rp_id_hash = ad[0..32].to_vec();
    let flags = ad[32];
    if flags & FLAG_AT == 0 {
        return Err(AppAttestError::NoAttestedCredentialData);
    }
    if ad.len() < 55 {
        return Err(AppAttestError::ShortAuthData(ad.len()));
    }
    let aaguid = ad[37..53].to_vec();
    let cred_id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let end = 55usize
        .checked_add(cred_id_len)
        .filter(|&e| e <= ad.len())
        .ok_or(AppAttestError::ShortAuthData(ad.len()))?;
    let credential_id = ad[55..end].to_vec();
    Ok(AuthData {
        rp_id_hash,
        aaguid,
        credential_id,
    })
}

/// The credCert nonce extension's extnValue is DER:
/// `SEQUENCE { [1] EXPLICIT OCTET STRING <nonce> }`. Walk it strictly.
fn parse_nonce_extension(ext_value: &[u8]) -> Option<Vec<u8>> {
    let (tag, seq_body, _) = read_tlv(ext_value)?;
    if tag != 0x30 {
        return None; // SEQUENCE
    }
    let (tag, ctx_body, _) = read_tlv(seq_body)?;
    if tag != 0xA1 {
        return None; // [1] constructed (context-specific)
    }
    let (tag, octets, _) = read_tlv(ctx_body)?;
    if tag != 0x04 {
        return None; // OCTET STRING
    }
    if octets.len() != 32 {
        return None; // App Attest nonce is sha256 → 32 bytes
    }
    Some(octets.to_vec())
}

/// Minimal strict DER TLV reader. Returns `(tag, value, rest)`. Handles
/// short-form and long-form definite lengths; rejects indefinite length.
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let first_len = data[1];
    let (len, header) = if first_len & 0x80 == 0 {
        (first_len as usize, 2usize)
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return None; // indefinite (0) or implausibly large
        }
        let mut l = 0usize;
        for &b in &data[2..2 + n] {
            l = (l << 8) | b as usize;
        }
        (l, 2 + n)
    };
    let end = header.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((tag, &data[header..end], &data[end..]))
}

/// Constant-time byte-slice equality (length-checked).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let mut acc = String::new();
    let mut in_block = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            acc.push_str(line.trim());
        }
    }
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    B64.decode(acc).map_err(|e| format!("base64: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa,
        KeyPair, PKCS_ECDSA_P256_SHA256,
    };
    use x509_parser::prelude::SubjectPublicKeyInfo;

    const TEST_APP_ID: &str = "4L45P7CP9M.dev.cocore.provider";

    /// DER-encode `SEQUENCE { [1] EXPLICIT OCTET STRING <nonce> }`, the shape of
    /// Apple's credCert nonce extension extnValue.
    fn nonce_extension_der(nonce: &[u8]) -> Vec<u8> {
        // OCTET STRING
        let mut os = vec![0x04, nonce.len() as u8];
        os.extend_from_slice(nonce);
        // [1] EXPLICIT wrapping the OCTET STRING
        let mut ctx = vec![0xA1, os.len() as u8];
        ctx.extend_from_slice(&os);
        // SEQUENCE wrapping that
        let mut seq = vec![0x30, ctx.len() as u8];
        seq.extend_from_slice(&ctx);
        seq
    }

    fn uncompressed_point(key: &KeyPair) -> Vec<u8> {
        let spki = key.public_key_der();
        let (_, info) = SubjectPublicKeyInfo::from_der(&spki).unwrap();
        info.subject_public_key.data.to_vec()
    }

    /// Build a full synthetic App Attest attestation object bound to
    /// `signing_pubkey`, returning `(object_cbor, key_id, root_der)`.
    fn synth_object(signing_pubkey: &[u8], aaguid: &[u8; 16]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let now = time::OffsetDateTime::now_utc();
        let nb = now - time::Duration::HOUR;
        let na = now + time::Duration::days(365);

        // Root (CA).
        let mut root_params = CertificateParams::new(vec!["Test AppAttest Root".into()]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.not_before = nb;
        root_params.not_after = na;
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();

        // Intermediate (CA, signed by root).
        let mut int_params = CertificateParams::new(vec!["Test AppAttest CA".into()]).unwrap();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        int_params.not_before = nb;
        int_params.not_after = na;
        let int_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let int_cert = int_params
            .signed_by(&int_key, &root_cert, &root_key)
            .unwrap();

        // Leaf (credCert): generate its key first so we can derive credentialId
        // and the authData the nonce commits to.
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_point = uncompressed_point(&leaf_key);
        let cred_id = Sha256::digest(&leaf_point).to_vec();

        // authData = rpIdHash | flags(AT) | signCount=0 | aaguid | credIdLen | credId
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(Sha256::digest(TEST_APP_ID.as_bytes()).as_slice());
        auth_data.push(FLAG_AT);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(aaguid);
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&cred_id);

        // nonce = sha256(authData || sha256(signing pubkey))
        let client_data_hash = Sha256::digest(signing_pubkey);
        let mut nonce_in = auth_data.clone();
        nonce_in.extend_from_slice(&client_data_hash);
        let nonce = Sha256::digest(&nonce_in).to_vec();

        // Leaf cert with the nonce extension.
        let mut leaf_params = CertificateParams::new(vec!["credCert".into()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "credCert");
        leaf_params.distinguished_name = dn;
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.not_before = nb;
        leaf_params.not_after = na;
        const NONCE_OID: &[u64] = &[1, 2, 840, 113635, 100, 8, 2];
        let mut ext = CustomExtension::from_oid_content(NONCE_OID, nonce_extension_der(&nonce));
        ext.set_criticality(false);
        leaf_params.custom_extensions.push(ext);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &int_cert, &int_key)
            .unwrap();

        // CBOR object.
        use ciborium::value::Value;
        let obj = Value::Map(vec![
            (
                Value::Text("fmt".into()),
                Value::Text("apple-appattest".into()),
            ),
            (
                Value::Text("attStmt".into()),
                Value::Map(vec![
                    (
                        Value::Text("x5c".into()),
                        Value::Array(vec![
                            Value::Bytes(leaf_cert.der().to_vec()),
                            Value::Bytes(int_cert.der().to_vec()),
                        ]),
                    ),
                    (Value::Text("receipt".into()), Value::Bytes(vec![])),
                ]),
            ),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&obj, &mut buf).unwrap();
        (buf, cred_id, root_cert.der().to_vec())
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    #[test]
    fn embedded_app_attest_root_parses() {
        let der = pem_to_der(APPLE_APP_ATTEST_ROOT_CA_PEM).unwrap();
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let cn: Vec<&str> = cert
            .subject()
            .iter_common_name()
            .filter_map(|c| c.attr_value().as_str().ok())
            .collect();
        assert!(cn.iter().any(|s| s.contains("Apple App Attestation")));
    }

    #[test]
    fn happy_path_binds_and_verifies() {
        let signing = vec![7u8; 64];
        let (object, key_id, root) = synth_object(&signing, AAGUID_PRODUCTION);
        let res = verify_against(
            &object,
            &key_id,
            &signing,
            TEST_APP_ID,
            &root,
            &now(),
            false,
        )
        .expect("should verify");
        assert!(res.valid);
        assert!(res.binds_signing_key);
        assert_eq!(res.key_id, key_id);
        assert_eq!(res.aaguid, AAGUID_PRODUCTION.to_vec());
    }

    #[test]
    fn wrong_signing_key_breaks_binding() {
        // Object bound to `signing`; verify with a DIFFERENT key → nonce mismatch.
        let signing = vec![7u8; 64];
        let (object, key_id, root) = synth_object(&signing, AAGUID_PRODUCTION);
        let other = vec![9u8; 64];
        let err = verify_against(&object, &key_id, &other, TEST_APP_ID, &root, &now(), false)
            .unwrap_err();
        assert!(matches!(err, AppAttestError::NonceMismatch), "got {err:?}");
    }

    #[test]
    fn wrong_root_rejects() {
        let signing = vec![7u8; 64];
        let (object, key_id, _root) = synth_object(&signing, AAGUID_PRODUCTION);
        // Verify against Apple's real root, which did not sign the synthetic chain.
        let apple = pem_to_der(APPLE_APP_ATTEST_ROOT_CA_PEM).unwrap();
        let err = verify_against(
            &object,
            &key_id,
            &signing,
            TEST_APP_ID,
            &apple,
            &now(),
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, AppAttestError::BadSignature { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn wrong_app_id_rejected() {
        let signing = vec![7u8; 64];
        let (object, key_id, root) = synth_object(&signing, AAGUID_PRODUCTION);
        let err = verify_against(
            &object,
            &key_id,
            &signing,
            "4L45P7CP9M.com.evil.fork",
            &root,
            &now(),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, AppAttestError::Shape(_)), "got {err:?}");
    }

    #[test]
    fn development_aaguid_rejected_unless_allowed() {
        let signing = vec![7u8; 64];
        let (object, key_id, root) = synth_object(&signing, AAGUID_DEVELOPMENT);
        // Default (production-only) rejects the development AAGUID.
        let err = verify_against(
            &object,
            &key_id,
            &signing,
            TEST_APP_ID,
            &root,
            &now(),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, AppAttestError::BadAaguid(_)), "got {err:?}");
        // With allow_development it passes.
        let res = verify_against(&object, &key_id, &signing, TEST_APP_ID, &root, &now(), true)
            .expect("dev aaguid allowed");
        assert!(res.valid);
    }

    #[test]
    fn wrong_key_id_rejected() {
        let signing = vec![7u8; 64];
        let (object, _key_id, root) = synth_object(&signing, AAGUID_PRODUCTION);
        let bogus = vec![0u8; 32];
        let err = verify_against(&object, &bogus, &signing, TEST_APP_ID, &root, &now(), false)
            .unwrap_err();
        assert!(matches!(err, AppAttestError::KeyIdMismatch), "got {err:?}");
    }

    #[test]
    fn parse_nonce_extension_walks_der() {
        let nonce = vec![0xABu8; 32];
        let der = nonce_extension_der(&nonce);
        assert_eq!(parse_nonce_extension(&der), Some(nonce));
        // A 31-byte "nonce" (wrong length) is rejected.
        let bad = nonce_extension_der(&[0u8; 31]);
        assert_eq!(parse_nonce_extension(&bad), None);
    }

    // ---- App Attest ASSERTIONS (ADR-0003) ----
    // Self-contained: synthesize an assertion the way DCAppAttestService would (a
    // P-256 SE key signs `authenticatorData || sha256(clientData)`). Parity with
    // the TS/Py appattest assertion tests.

    fn assertion_identity() -> (p256::ecdsa::SigningKey, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        let ep = vk.to_encoded_point(false); // 0x04||X||Y
        let raw = ep.as_bytes()[1..].to_vec(); // 64-byte X||Y
        (sk, raw)
    }

    fn make_assertion(sk: &p256::ecdsa::SigningKey, message: &[u8], app_id: &str) -> Vec<u8> {
        use ciborium::value::Value;
        use p256::ecdsa::{signature::Signer, Signature};
        let mut auth_data = Sha256::digest(app_id.as_bytes()).to_vec();
        auth_data.extend_from_slice(&[0x00, 0, 0, 0, 1]); // flags + signCount → 37 bytes
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(message));
        let sig: Signature = sk.sign(&signed);
        let der = sig.to_der().as_bytes().to_vec();
        let val = Value::Map(vec![
            (Value::Text("signature".into()), Value::Bytes(der)),
            (
                Value::Text("authenticatorData".into()),
                Value::Bytes(auth_data),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        buf
    }

    #[test]
    fn verify_assertion_accepts_valid_and_rejects_tamper() {
        let (sk, pub_raw) = assertion_identity();
        let msg = b"canonical record bytes";
        let a = make_assertion(&sk, msg, TEST_APP_ID);
        assert!(verify_assertion(&pub_raw, &a, msg, TEST_APP_ID));
        // Tampered message.
        assert!(!verify_assertion(&pub_raw, &a, b"tampered", TEST_APP_ID));
        // Wrong verifying key.
        let (_, other) = assertion_identity();
        assert!(!verify_assertion(&other, &a, msg, TEST_APP_ID));
        // Wrong appId (rpIdHash mismatch).
        assert!(!verify_assertion(
            &pub_raw,
            &a,
            msg,
            "9Z9Z9Z9Z9Z.dev.cocore.provider"
        ));
    }

    #[test]
    fn attested_key_matches_signing_key_only_on_equality() {
        let (_, pub_raw) = assertion_identity();
        let mut uncompressed = vec![0x04u8];
        uncompressed.extend_from_slice(&pub_raw);
        assert!(attested_key_matches_signing_key(&uncompressed, &pub_raw));
        // Different key.
        let (_, other) = assertion_identity();
        let mut other_unc = vec![0x04u8];
        other_unc.extend_from_slice(&other);
        assert!(!attested_key_matches_signing_key(&other_unc, &pub_raw));
        // Raw 64 (missing 0x04 prefix) doesn't match.
        assert!(!attested_key_matches_signing_key(&pub_raw, &pub_raw));
    }
}
