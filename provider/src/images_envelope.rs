//! Builds the canonical `images-v1` OUTPUT envelope bytes.
//!
//! Mirror of the TS SDK `packages/sdk/src/images-envelope.ts`. An
//! image-generation job commits `outputCommitment` over the SHA-256 of
//! these exact bytes, exactly as the text path commits over the answer's
//! UTF-8 bytes. A requester/verifier holding the delivered images
//! reconstructs the identical bytes here (or in TS) and recomputes the
//! commitment — so the canonicalization MUST stay byte-identical to the
//! SDK (`crate::canonical` already matches `packages/sdk/src/canonical.ts`).
//!
//! Envelope shape: `{ "images": [ { "data": <b64>, "mime": <str> } ], "v": 1 }`
//! (keys sorted, no insignificant whitespace).

use crate::canonical::to_canonical_bytes;
use serde_json::json;

/// One generated image: media type + base64-encoded raw bytes.
#[derive(Debug, Clone)]
pub struct EnvelopeImage {
    pub mime: String,
    pub data_b64: String,
}

/// Canonical bytes of the `images-v1` envelope over `images`, in order.
/// This is the exact payload `outputCommitment` is hashed over.
pub fn build_images_envelope_bytes(images: &[EnvelopeImage]) -> Vec<u8> {
    let arr: Vec<serde_json::Value> = images
        .iter()
        .map(|im| json!({ "mime": im.mime, "data": im.data_b64 }))
        .collect();
    let envelope = json!({ "v": 1, "images": arr });
    // canonical.rs sorts keys + forbids floats; an integer `v` and string
    // fields are always representable, so this cannot fail in practice.
    to_canonical_bytes(&envelope).expect("images envelope canonicalizes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // Cross-language parity fixture. The SAME canonical string + SHA-256 are
    // asserted on the TS side (packages/sdk/src/images-envelope.test.ts). A
    // divergence in either canonicalizer is caught here.
    const FIXTURE_CANONICAL: &str = r#"{"images":[{"data":"aGVsbG8=","mime":"image/png"}],"v":1}"#;
    const FIXTURE_SHA256: &str = "87727768fff8767ca20fdc4880a22a2899216722d446d498da395ef1ada58681";

    #[test]
    fn canonical_bytes_match_cross_language_fixture() {
        let images = vec![EnvelopeImage {
            mime: "image/png".into(),
            data_b64: "aGVsbG8=".into(),
        }];
        let bytes = build_images_envelope_bytes(&images);
        assert_eq!(String::from_utf8(bytes.clone()).unwrap(), FIXTURE_CANONICAL);
        let sha = hex::encode(Sha256::digest(&bytes));
        assert_eq!(sha, FIXTURE_SHA256);
    }

    #[test]
    fn preserves_image_order() {
        let images = vec![
            EnvelopeImage {
                mime: "image/png".into(),
                data_b64: "AAAA".into(),
            },
            EnvelopeImage {
                mime: "image/jpeg".into(),
                data_b64: "BBBB".into(),
            },
        ];
        let bytes = build_images_envelope_bytes(&images);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"images":[{"data":"AAAA","mime":"image/png"},{"data":"BBBB","mime":"image/jpeg"}],"v":1}"#,
        );
    }
}
