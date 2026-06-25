//! Builds and signs `dev.cocore.compute.receipt` records.
//!
//! Mirrors the shape of [`crate::attestation::build`]: the unsigned
//! body is constructed as a `serde_json::Value`, canonicalised via
//! [`crate::canonical::to_canonical_bytes`], signed by the
//! Secure-Enclave-bound P-256 key, and the DER signature is
//! base64-encoded into the `enclaveSignature` field.
//!
//! The resulting record is what flows into the firehose. Anyone with
//! the attestation public key (referenced by the receipt) and these
//! same canonicalisation rules can verify offline — without asking
//! any service for permission. The TS verifier in
//! `packages/sdk/src/p256.ts` does exactly that.

use crate::canonical::to_canonical_bytes;
use crate::secure_enclave::SigningIdentity;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct StrongRef {
    pub uri: String,
    pub cid: String,
}

#[derive(Debug, Clone)]
pub struct Money {
    pub amount: u64,
    pub currency: String,
}

#[derive(Debug, Clone)]
pub struct ReceiptInputs {
    pub job: StrongRef,
    pub requester: String,
    pub model: String,
    pub input_commitment: String,
    pub output_commitment: String,
    /// SHA-256 hex over the exact sealed bytes delivered to the
    /// requester. Lets a requester confirm the ciphertext they received
    /// is the one this receipt's signature commits to.
    pub output_cipher_commitment: Option<String>,
    /// SHA-256 hex over the plaintext reasoning ('thinking') output the
    /// provider produced, separate from `output_commitment`. `None` when
    /// the model emitted no reasoning channel.
    pub reasoning_commitment: Option<String>,
    /// Sampling parameters the provider committed to for this job.
    pub params: Option<GenerationParams>,
    pub output_cipher_url: Option<String>,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub price: Money,
    pub attestation: StrongRef,
    /// True when this job was served pro bono under the provider's
    /// `proBono` election — free, unmetered, no exchange cut. When set,
    /// the caller MUST pass `price.amount == 0` and `tokens_in ==
    /// tokens_out == 0`; the work is explicitly not counted. Emitted as
    /// `proBono: true` and covered by the enclave signature so the
    /// carve-out is part of the signed record. `false` omits the field
    /// entirely (a normal metered receipt).
    pub pro_bono: bool,
}

/// Sampling parameters committed to in a receipt. Integer-only because
/// the canonical signing form forbids floats — temperature and top_p are
/// carried as milliunits (value × 1000). Mirrors the lexicon
/// `dev.cocore.compute.receipt#generationParams`.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize)]
pub struct GenerationParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maxTokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperatureMilli: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topPMilli: Option<u64>,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize)]
pub struct ReceiptRecord {
    pub job: StrongRefValue,
    pub requester: String,
    pub model: String,
    pub inputCommitment: String,
    pub outputCommitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputCipherCommitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoningCommitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<GenerationParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputCipherURL: Option<String>,
    pub tokens: TokenCounts,
    pub startedAt: String,
    pub completedAt: String,
    pub price: MoneyValue,
    pub attestation: StrongRefValue,
    /// Present (as `true`) only when this job was served pro bono.
    /// Omitted on a normal metered receipt so the byte layout — and
    /// thus the signed canonical form — is identical to a pre-proBono
    /// record.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub proBono: bool,
    /// Base64 of the DER-encoded ECDSA-P256 signature over the
    /// canonical bytes of every other field in this record.
    pub enclaveSignature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StrongRefValue {
    pub uri: String,
    pub cid: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenCounts {
    #[serde(rename = "in")]
    pub r#in: u64,
    pub out: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MoneyValue {
    pub amount: u64,
    pub currency: String,
}

/// Build the unsigned receipt JSON, canonicalise it, sign with the
/// provided identity, and return the typed record + the canonical
/// bytes that were signed (so callers can record them for audit).
pub fn build(
    inputs: ReceiptInputs,
    signer: &dyn SigningIdentity,
) -> anyhow::Result<(ReceiptRecord, Vec<u8>)> {
    let started_at = rfc3339(inputs.started_at);
    let completed_at = rfc3339(inputs.completed_at);

    let mut unsigned = json!({
        "job": { "uri": inputs.job.uri, "cid": inputs.job.cid },
        "requester": inputs.requester,
        "model": inputs.model,
        "inputCommitment": inputs.input_commitment,
        "outputCommitment": inputs.output_commitment,
        "tokens": { "in": inputs.tokens_in, "out": inputs.tokens_out },
        "startedAt": started_at,
        "completedAt": completed_at,
        "price": { "amount": inputs.price.amount, "currency": inputs.price.currency },
        "attestation": { "uri": inputs.attestation.uri, "cid": inputs.attestation.cid },
    });
    // Insert optional fields only when present, mirroring the typed
    // record's `skip_serializing_if = None` — the signed `unsigned`
    // value MUST canonicalise to the same bytes the verifier derives
    // from the published record (minus enclaveSignature).
    if let Some(c) = &inputs.output_cipher_commitment {
        unsigned
            .as_object_mut()
            .unwrap()
            .insert("outputCipherCommitment".into(), Value::String(c.clone()));
    }
    if let Some(c) = &inputs.reasoning_commitment {
        unsigned
            .as_object_mut()
            .unwrap()
            .insert("reasoningCommitment".into(), Value::String(c.clone()));
    }
    if let Some(p) = &inputs.params {
        // Serialize through serde so only the present sub-fields appear,
        // byte-identical to how the typed record emits `params`.
        unsigned
            .as_object_mut()
            .unwrap()
            .insert("params".into(), serde_json::to_value(p)?);
    }
    if let Some(url) = &inputs.output_cipher_url {
        unsigned
            .as_object_mut()
            .unwrap()
            .insert("outputCipherURL".into(), Value::String(url.clone()));
    }
    // Only emit `proBono` when true, mirroring the typed record's
    // `skip_serializing_if` — a normal receipt canonicalises to the
    // exact bytes a pre-proBono verifier derives.
    if inputs.pro_bono {
        unsigned
            .as_object_mut()
            .unwrap()
            .insert("proBono".into(), Value::Bool(true));
    }
    let canonical = to_canonical_bytes(&unsigned)?;
    let sig = signer
        .sign(&canonical)
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    Ok((
        ReceiptRecord {
            job: StrongRefValue {
                uri: inputs.job.uri,
                cid: inputs.job.cid,
            },
            requester: inputs.requester,
            model: inputs.model,
            inputCommitment: inputs.input_commitment,
            outputCommitment: inputs.output_commitment,
            outputCipherCommitment: inputs.output_cipher_commitment,
            reasoningCommitment: inputs.reasoning_commitment,
            params: inputs.params,
            outputCipherURL: inputs.output_cipher_url,
            tokens: TokenCounts {
                r#in: inputs.tokens_in,
                out: inputs.tokens_out,
            },
            startedAt: started_at,
            completedAt: completed_at,
            price: MoneyValue {
                amount: inputs.price.amount,
                currency: inputs.price.currency,
            },
            attestation: StrongRefValue {
                uri: inputs.attestation.uri,
                cid: inputs.attestation.cid,
            },
            proBono: inputs.pro_bono,
            enclaveSignature: B64.encode(&sig),
        },
        canonical,
    ))
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_enclave::{identity_lock, load_or_create_identity};
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;

    fn fixture(now: DateTime<Utc>) -> ReceiptInputs {
        ReceiptInputs {
            job: StrongRef {
                uri: "at://did:plc:r/dev.cocore.compute.job/1".into(),
                cid: "bafyjob".into(),
            },
            requester: "did:plc:r".into(),
            model: "llama-3.1-70b".into(),
            input_commitment: "a".repeat(64),
            output_commitment: "b".repeat(64),
            output_cipher_commitment: None,
            reasoning_commitment: None,
            params: None,
            output_cipher_url: None,
            tokens_in: 32,
            tokens_out: 128,
            started_at: now,
            completed_at: now + chrono::Duration::seconds(3),
            price: Money {
                amount: 12,
                currency: "USD".into(),
            },
            attestation: StrongRef {
                uri: "at://did:plc:p/dev.cocore.compute.attestation/1".into(),
                cid: "bafyatt".into(),
            },
            pro_bono: false,
        }
    }

    #[test]
    fn signature_verifies_against_published_public_key() {
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        let (rec, canonical) = build(fixture(chrono::Utc::now()), &*signer).unwrap();

        let sig_der = B64.decode(rec.enclaveSignature.as_bytes()).unwrap();
        let pub_b64 = signer.public_key_b64();
        let pub_raw = B64.decode(pub_b64.as_bytes()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_raw);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&sig_der).unwrap();
        vk.verify(&canonical, &sig)
            .expect("receipt signature must verify against published public key");
    }

    #[test]
    fn output_cipher_url_omitted_when_none() {
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();
        let (rec, _) = build(fixture(chrono::Utc::now()), &*signer).unwrap();
        // Roundtrip the typed record through serde_json and assert
        // `outputCipherURL` is absent (skip_serializing_if = None).
        let body = serde_json::to_value(&rec).unwrap();
        assert!(body.get("outputCipherURL").is_none());
    }

    #[test]
    fn reasoning_commitment_present_only_when_set() {
        let _g = identity_lock();
        let signer = load_or_create_identity().unwrap();

        // Absent by default — a job with no reasoning omits the field.
        let (rec, _) = build(fixture(chrono::Utc::now()), &*signer).unwrap();
        let body = serde_json::to_value(&rec).unwrap();
        assert!(body.get("reasoningCommitment").is_none());

        // Present (and signed) when the model produced reasoning.
        let mut inputs = fixture(chrono::Utc::now());
        inputs.reasoning_commitment = Some("d".repeat(64));
        let (rec, _) = build(inputs, &*signer).unwrap();
        let mut signed = serde_json::to_value(&rec).unwrap();
        assert_eq!(signed["reasoningCommitment"], json!("d".repeat(64)));
        // It is covered by the signature (verifies against record minus sig).
        signed.as_object_mut().unwrap().remove("enclaveSignature");
        let message = to_canonical_bytes(&signed).unwrap();
        let sig_der = B64.decode(rec.enclaveSignature.as_bytes()).unwrap();
        let pub_raw = B64.decode(signer.public_key_b64()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_raw);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&sig_der).unwrap();
        vk.verify(&message, &sig)
            .expect("signature must verify with reasoningCommitment present");
    }

    #[test]
    fn signature_covers_cipher_commitment_and_params() {
        // With the new optional fields present, the enclaveSignature must
        // still verify against the published record (minus the signature),
        // proving the signed canonical bytes include them — i.e. the
        // delivered ciphertext + params are bound by the signature.
        let signer = load_or_create_identity().unwrap();
        let mut inputs = fixture(chrono::Utc::now());
        inputs.output_cipher_commitment = Some("c".repeat(64));
        inputs.params = Some(GenerationParams {
            maxTokens: Some(256),
            seed: Some(42),
            temperatureMilli: Some(700),
            topPMilli: None,
        });
        let (rec, _) = build(inputs, &*signer).unwrap();

        // Reconstruct the verifier's view: published record minus the sig.
        let mut signed = serde_json::to_value(&rec).unwrap();
        signed.as_object_mut().unwrap().remove("enclaveSignature");
        // The fields are actually present in the published record.
        assert_eq!(signed["outputCipherCommitment"], json!("c".repeat(64)));
        assert_eq!(signed["params"]["maxTokens"], json!(256));
        assert_eq!(signed["params"]["temperatureMilli"], json!(700));
        assert!(signed["params"].get("topPMilli").is_none());
        let message = to_canonical_bytes(&signed).unwrap();

        let sig_der = B64.decode(rec.enclaveSignature.as_bytes()).unwrap();
        let pub_raw = B64.decode(signer.public_key_b64()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_raw);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&sig_der).unwrap();
        vk.verify(&message, &sig)
            .expect("signature must verify with cipher commitment + params present");
    }

    #[test]
    fn pro_bono_field_present_and_signed_when_set() {
        let signer = load_or_create_identity().unwrap();

        // A normal receipt omits proBono entirely — byte-identical to a
        // pre-proBono record so old verifiers see the same canonical form.
        let (rec, _) = build(fixture(chrono::Utc::now()), &*signer).unwrap();
        let body = serde_json::to_value(&rec).unwrap();
        assert!(body.get("proBono").is_none());

        // A pro-bono receipt: free + unmetered, so price and tokens are zero.
        let mut inputs = fixture(chrono::Utc::now());
        inputs.pro_bono = true;
        inputs.tokens_in = 0;
        inputs.tokens_out = 0;
        inputs.price = Money {
            amount: 0,
            currency: "CC".into(),
        };
        let (rec, _) = build(inputs, &*signer).unwrap();
        let mut signed = serde_json::to_value(&rec).unwrap();
        assert_eq!(signed["proBono"], json!(true));
        assert_eq!(signed["price"]["amount"], json!(0));
        assert_eq!(signed["tokens"], json!({ "in": 0, "out": 0 }));

        // The flag is covered by the signature (verifies against record minus sig).
        signed.as_object_mut().unwrap().remove("enclaveSignature");
        let message = to_canonical_bytes(&signed).unwrap();
        let sig_der = B64.decode(rec.enclaveSignature.as_bytes()).unwrap();
        let pub_raw = B64.decode(signer.public_key_b64()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_raw);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&sig_der).unwrap();
        vk.verify(&message, &sig)
            .expect("signature must verify with proBono present");
    }

    #[test]
    fn changing_one_field_invalidates_signature() {
        let signer = load_or_create_identity().unwrap();
        let inputs = fixture(chrono::Utc::now());
        let (rec, _) = build(inputs.clone(), &*signer).unwrap();

        // Mutate the price and recompute the canonical bytes the
        // verifier would use; the original signature must NOT match.
        let mut tampered = serde_json::to_value(&rec).unwrap();
        tampered.as_object_mut().unwrap().remove("enclaveSignature");
        tampered["price"]["amount"] = serde_json::json!(9999);
        let tampered_bytes = to_canonical_bytes(&tampered).unwrap();

        let sig_der = B64.decode(rec.enclaveSignature.as_bytes()).unwrap();
        let pub_raw = B64.decode(signer.public_key_b64()).unwrap();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pub_raw);
        let point = EncodedPoint::from_bytes(uncompressed).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&sig_der).unwrap();
        assert!(vk.verify(&tampered_bytes, &sig).is_err());
    }
}
