//! Cross-language signature parity fixture generator.
//!
//! Produces a JSON file under `target/cross-lang-fixture.json` that
//! the TypeScript test in `packages/sdk/src/p256.test.ts` reads to
//! verify Rust-produced ECDSA-P256 DER signatures with WebCrypto.
//!
//! ECDSA with the default RustCrypto signer is **non-deterministic**
//! (uses a random nonce). That's fine for the parity test — TS only
//! cares that the signature verifies for the published public key,
//! not that the bytes are pinned. We still emit the canonical bytes
//! that were signed so the TS side can re-canonicalise the receipt
//! and prove byte-equality at the same time.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cocore_provider::canonical::to_canonical_bytes;
use cocore_provider::mda::{verify_chain_against, APPLE_ENTERPRISE_ATTESTATION_ROOT_CA_PEM};
use cocore_provider::receipt::{build, Money, ReceiptInputs, StrongRef};
use cocore_provider::secure_enclave::load_or_create_identity;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::json;

#[test]
fn writes_cross_lang_fixture() {
    let signer = load_or_create_identity().unwrap();

    // A pinned input — same bytes the TS test expects to canonicalise.
    let inputs = ReceiptInputs {
        job: StrongRef {
            uri: "at://did:plc:requester/dev.cocore.compute.job/x".into(),
            cid: "bafyjob".into(),
        },
        requester: "did:plc:requester".into(),
        model: "llama-3.1-70b".into(),
        input_commitment: "a".repeat(64),
        output_commitment: "b".repeat(64),
        // New optional fields stay None here so the pinned canonical bytes
        // (and the cross-language golden fixture) are unchanged — both are
        // skip-serialized when absent.
        output_cipher_commitment: None,
        reasoning_commitment: None,
        params: None,
        output_cipher_url: None,
        tokens_in: 32,
        tokens_out: 128,
        started_at: chrono::DateTime::parse_from_rfc3339("2026-05-07T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        completed_at: chrono::DateTime::parse_from_rfc3339("2026-05-07T12:00:03Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        price: Money {
            amount: 12,
            currency: "USD".into(),
        },
        attestation: StrongRef {
            uri: "at://did:plc:provider/dev.cocore.compute.attestation/x".into(),
            cid: "bafyatt".into(),
        },
    };
    let (record, canonical) = build(inputs, &*signer).unwrap();

    // Self-test: round-trip the typed record through serde, strip the
    // signature, and prove the canonical bytes match what we signed.
    let mut body_value = serde_json::to_value(&record).unwrap();
    body_value
        .as_object_mut()
        .unwrap()
        .remove("enclaveSignature");
    let recanon = to_canonical_bytes(&body_value).unwrap();
    assert_eq!(
        recanon, canonical,
        "round-tripping the typed record must reproduce the signed bytes",
    );

    let fixture = json!({
        "publicKeyB64": signer.public_key_b64(),
        "isHardwareBound": signer.is_hardware_bound(),
        "canonicalB64": B64.encode(&canonical),
        "receipt": record,
    });

    let target = workspace_target_dir().join("cross-lang-fixture.json");
    std::fs::write(&target, serde_json::to_vec_pretty(&fixture).unwrap())
        .unwrap_or_else(|e| panic!("write {}: {e}", target.display()));
    eprintln!("wrote {}", target.display());
}

/// Generate an MDA cert chain fixture: a synthetic root + a single
/// leaf signed by it, with the Apple-defined OIDs encoded as
/// extensions. The TS test verifies this exactly the same way
/// `verify_chain_against` does in Rust — same root bytes, same chain
/// bytes — proving cross-language parity on the cert path too.
#[test]
fn writes_mda_cross_lang_fixture() {
    let now = time::OffsetDateTime::now_utc();
    let nb = now - time::Duration::HOUR;
    let na = now + time::Duration::days(365 * 2);

    // Root.
    let mut root_params = CertificateParams::new(vec!["cocore MDA Test Root".into()]).unwrap();
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CommonName, "cocore MDA Test Root");
    root_params.distinguished_name = root_dn;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root_params.not_before = nb;
    root_params.not_after = na;
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let root_cert = root_params.self_signed(&root_key).unwrap();

    // Leaf.
    let mut leaf_params = CertificateParams::new(vec!["mda-cross-lang-device".into()]).unwrap();
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, "mda-cross-lang-device");
    leaf_dn.push(
        DnType::CustomDnType(vec![2, 5, 4, 5]), // X.500 serialNumber
        "C02CROSSLANG",
    );
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.not_before = nb;
    leaf_params.not_after = na;
    let mut sip = CustomExtension::from_oid_content(
        &[1, 2, 840, 113635, 100, 8, 13, 1],
        vec![0x01, 0x01, 0xff],
    );
    sip.set_criticality(false);
    leaf_params.custom_extensions.push(sip);
    let mut udid = CustomExtension::from_oid_content(&[1, 2, 840, 113635, 100, 8, 9, 2], {
        let s = "UDID-CROSSLANG";
        let mut o = vec![0x0c, s.len() as u8];
        o.extend_from_slice(s.as_bytes());
        o
    });
    udid.set_criticality(false);
    leaf_params.custom_extensions.push(udid);
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &root_cert, &root_key)
        .unwrap();

    let root_der = root_cert.der().to_vec();
    let chain_der = vec![leaf_cert.der().to_vec()];

    // Self-test: prove the Rust verifier accepts what we just built
    // before we ask the TS verifier to do the same.
    let now_chrono = chrono::Utc::now();
    let result = verify_chain_against(&chain_der, &root_der, &now_chrono).unwrap();
    assert!(result.valid, "Rust must verify its own fixture");
    assert_eq!(result.device_serial.as_deref(), Some("C02CROSSLANG"));

    // Also include the Apple Root PEM so the TS test can prove the
    // wrong-root path works (synthetic chain MUST NOT verify against
    // the real Apple root).
    let fixture = json!({
        "rootDerB64": B64.encode(&root_der),
        "chainDerB64": chain_der.iter().map(|d| B64.encode(d)).collect::<Vec<_>>(),
        "appleRootPem": APPLE_ENTERPRISE_ATTESTATION_ROOT_CA_PEM,
        "expected": {
            "valid": true,
            "deviceSerial": "C02CROSSLANG",
            "deviceUdid": "UDID-CROSSLANG",
            "sipEnabled": true,
        },
    });
    let path = workspace_target_dir().join("mda-cross-lang-fixture.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&fixture).unwrap())
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    eprintln!("wrote {}", path.display());
}

/// Emit a COMPLETE confidential-tier attestation fixture for the TS
/// `verifyProviderForSeal` test. A single P-256 key (imported from the rcgen
/// leaf key, so the MDA leaf certifies it) is used as the attestation
/// `publicKey`, the `selfSignature` signer, AND the session-key signer — so
/// the TS verifier exercises every gate end-to-end and returns
/// `attested-confidential`. This is the definitive cross-language proof that
/// the Rust producer's signed bytes + the SDK's verifier agree.
#[test]
fn writes_confidential_attestation_fixture() {
    use base64::engine::general_purpose::STANDARD as B64e;
    use cocore_provider::canonical::to_canonical_bytes;
    use cocore_provider::crypto::ProviderKeypair;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePrivateKey;

    let now = time::OffsetDateTime::now_utc();
    let nb = now - time::Duration::HOUR;
    let na = now + time::Duration::days(365 * 2);

    // Synthetic root.
    let mut root_params = CertificateParams::new(vec!["cocore Conf Test Root".into()]).unwrap();
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CommonName, "cocore Conf Test Root");
    root_params.distinguished_name = root_dn;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root_params.not_before = nb;
    root_params.not_after = na;
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let root_cert = root_params.self_signed(&root_key).unwrap();

    // Leaf — its key becomes the attestation/signing key. Import the rcgen
    // private key into p256 so the SAME key signs the attestation + session.
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf_priv_pem = leaf_key.serialize_pem();
    let secret = p256::SecretKey::from_pkcs8_pem(&leaf_priv_pem).unwrap();
    let signing_key = SigningKey::from(&secret);
    let pub_point = secret.public_key().to_encoded_point(false);
    let public_key_b64 = B64e.encode(&pub_point.as_bytes()[1..]); // drop 0x04 → 64 bytes

    let mut leaf_params = CertificateParams::new(vec!["conf-device".into()]).unwrap();
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, "conf-device");
    leaf_dn.push(DnType::CustomDnType(vec![2, 5, 4, 5]), "C02CONFID");
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.not_before = nb;
    leaf_params.not_after = na;
    let mut sip = CustomExtension::from_oid_content(
        &[1, 2, 840, 113635, 100, 8, 13, 1],
        vec![0x01, 0x01, 0xff],
    );
    sip.set_criticality(false);
    leaf_params.custom_extensions.push(sip);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &root_cert, &root_key)
        .unwrap();
    let root_der = root_cert.der().to_vec();
    let leaf_der = leaf_cert.der().to_vec();

    // Encryption key the requester seals to (best-effort/no-session path).
    let enc = ProviderKeypair::generate();
    let cd_hash = "ab".repeat(20); // 40 hex
    let metallib_hash = "cd".repeat(32); // 64 hex
    let attested_at = chrono::Utc::now();
    let expires_at = attested_at + chrono::Duration::hours(24);

    // Build the attestation body (sorted/canonical-independent) — every field a
    // confidential verifier checks, set to the strong posture.
    let mut body = json!({
        "publicKey": public_key_b64,
        "encryptionPubKey": enc.public_key_b64(),
        "chipName": "Apple M4 Max",
        "hardwareModel": "Mac16,1",
        "serialNumberHash": "0".repeat(64),
        "osVersion": "macOS 26.0",
        "binaryHash": "1".repeat(64),
        "cdHash": cd_hash,
        "teamId": "4L45P7CP9M",
        "hardenedRuntime": true,
        "libraryValidation": true,
        "getTaskAllow": false,
        "metallibHash": metallib_hash,
        "engineLibHash": "ef".repeat(32),
        "inProcessBackend": true,
        "antiDebug": true,
        "coreDumpsDisabled": true,
        "envScrubbed": true,
        "sipEnabled": true,
        "secureBootEnabled": true,
        "secureEnclaveAvailable": true,
        "authenticatedRootEnabled": true,
        "rdmaDisabled": true,
        "mdaCertChain": [B64e.encode(&leaf_der)],
        "tier": "attested-confidential",
        "attestedAt": attested_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "expiresAt": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    let canonical = to_canonical_bytes(&body).unwrap();
    let self_sig: Signature = signing_key.sign(&canonical);
    body.as_object_mut().unwrap().insert(
        "selfSignature".into(),
        json!(B64e.encode(self_sig.to_der().as_bytes())),
    );

    // Session key (advisor-trustless freshness mode): SE-sign canonical
    // {attestationCid, ephemeralPubKey, nonce} with the SAME key.
    let ephemeral = ProviderKeypair::generate();
    let nonce = "f".repeat(32);
    let attestation_cid = "bafyconfattestationcid";
    let sk_msg = to_canonical_bytes(&json!({
        "attestationCid": attestation_cid,
        "ephemeralPubKey": ephemeral.public_key_b64(),
        "nonce": nonce,
    }))
    .unwrap();
    let sk_sig: Signature = signing_key.sign(&sk_msg);

    let fixture = json!({
        "attestation": body,
        "rootDerB64": B64e.encode(&root_der),
        "knownGoodCdHash": "ab".repeat(20),
        "knownGoodMetallibHash": "cd".repeat(32),
        "knownGoodEngineLibHash": "ef".repeat(32),
        "osFloor": "14.0.0",
        "attestationCid": attestation_cid,
        "nonce": nonce,
        "sessionKey": {
            "ephemeralPubKey": ephemeral.public_key_b64(),
            "nonce": nonce,
            "attestationCid": attestation_cid,
            "signature": B64e.encode(sk_sig.to_der().as_bytes()),
        },
    });
    let path = workspace_target_dir().join("confidential-attestation-fixture.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&fixture).unwrap())
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    eprintln!("wrote {}", path.display());
}

fn workspace_target_dir() -> std::path::PathBuf {
    // CARGO_TARGET_DIR or <workspace>/target. We want a stable path
    // under the workspace root so the TS test can find the fixture
    // regardless of which crate's target dir cargo was using.
    let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf();
    let dir = workspace.join("target");
    std::fs::create_dir_all(&dir).ok();
    dir
}
