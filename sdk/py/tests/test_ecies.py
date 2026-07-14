"""Cross-language parity for the p256-ecies-se codec.

IDENTICAL fixed inputs to the Rust `crypto::ecies_golden_vector` test and the
TypeScript `ecies.test.ts`. All three must derive the same Z, AES key, and blob.
  K (recipient) priv = 0x01..=0x20, E (sender ephemeral) priv = 0x21..=0x40,
  iv = 0x000102..0b, plaintext = "cocore-ecies-golden".
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from cocore.ecies import derive_key, ecdh_raw_x, ecies_seal, open_blob, seal_with_iv

K_PUB = bytes.fromhex(
    "515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f"
    "4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354"
)
E_PRIV = 0x2122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40
GOLDEN_Z = "4fe243908f378aa1c2a69538822e6ed908c3225d8692575507c649901245150a"
GOLDEN_BLOB = (
    "000102030405060708090a0b18d935a95421e46242ea5aac5e58adf5ca4a6ec3cf3fdfdec85ba2f014b13c83cf0958"
)
IV = bytes.fromhex("000102030405060708090a0b")
PLAINTEXT = b"cocore-ecies-golden"


def test_ecdh_derives_golden_z():
    e_priv = ec.derive_private_key(E_PRIV, ec.SECP256R1())
    z = ecdh_raw_x(e_priv, K_PUB)
    assert z.hex() == GOLDEN_Z, "shared secret Z drifted"


def test_hkdf_aesgcm_reproduces_golden_blob():
    z = bytes.fromhex(GOLDEN_Z)
    blob = seal_with_iv(z, IV, PLAINTEXT)
    assert blob.hex() == GOLDEN_BLOB, "sealed blob drifted"
    assert open_blob(z, bytes.fromhex(GOLDEN_BLOB)) == PLAINTEXT


def test_seal_round_trips():
    # Seal to K_PUB with a fresh ephemeral; the provider (holding K_priv) would
    # recompute the same Z via its enclave. Here we prove the sender path emits a
    # 64-byte epk and a well-formed blob.
    epk, blob = ecies_seal(K_PUB, b"hi")
    assert len(epk) == 64
    assert len(blob) >= 12 + 16


def test_open_rejects_tampered_blob():
    z = bytes.fromhex(GOLDEN_Z)
    bad = bytearray(bytes.fromhex(GOLDEN_BLOB))
    bad[-1] ^= 0xFF
    assert open_blob(z, bytes(bad)) is None
