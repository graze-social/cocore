"""``p256-ecies-se`` sealed-box construction (mirror of the Rust
``crypto::ecies`` and the TypeScript ``ecies.ts``).

Given an ephemeral-static P-256 ECDH shared secret ``Z`` (raw 32-byte
X-coordinate), the wire is::

    key  = HKDF-SHA256(salt=0x00*32, IKM=Z, info="cocore/p256-ecies-se/v1", 32)
    iv   = 12 random bytes (fresh per message, ON the wire)
    blob = iv(12) || AES-256-GCM(key, iv, aad=<empty>, plaintext)   # ct || 16-byte tag

The recipient's static P-256 key lives in the provider's Secure Enclave, so the
decrypting scalar never leaves the machine (ADR-0005). The ephemeral public key
travels out-of-band (``epk`` / ``requester_pub_key``), so no wire framing
changes versus the X25519 path.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"cocore/p256-ecies-se/v1"
_IV_LEN = 12
_TAG_LEN = 16
_CURVE = ec.SECP256R1()


def _public_from_raw64(pub64: bytes) -> ec.EllipticCurvePublicKey:
    if len(pub64) != 64:
        raise ValueError(f"expected 64-byte P-256 point, got {len(pub64)}")
    return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, b"\x04" + pub64)


def ecdh_raw_x(private_key: ec.EllipticCurvePrivateKey, peer_pub64: bytes) -> bytes:
    """ECDH → raw 32-byte shared secret ``Z`` (the X-coordinate)."""
    return private_key.exchange(ec.ECDH(), _public_from_raw64(peer_pub64))


def derive_key(z: bytes) -> bytes:
    """HKDF-SHA256 over ``Z`` → the 32-byte AES-256 key."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=_INFO).derive(z)


def seal_with_iv(z: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Deterministic seal with an explicit IV → ``iv || ct || tag`` (golden vector)."""
    key = derive_key(z)
    ct = AESGCM(key).encrypt(iv, plaintext, None)
    return iv + ct


def seal(z: bytes, plaintext: bytes) -> bytes:
    """Seal with a fresh random IV → ``iv || ct || tag``."""
    return seal_with_iv(z, os.urandom(_IV_LEN), plaintext)


def open_blob(z: bytes, blob: bytes) -> bytes | None:
    """Open an ``iv || ct || tag`` blob. Returns None on auth failure."""
    if len(blob) < _IV_LEN + _TAG_LEN:
        return None
    key = derive_key(z)
    iv, body = blob[:_IV_LEN], blob[_IV_LEN:]
    try:
        return AESGCM(key).decrypt(iv, body, None)
    except Exception:
        return None


def ecies_seal(recipient_pub64: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Seal ``plaintext`` to a recipient's raw 64-byte P-256 key with a fresh
    ephemeral. Returns ``(epk_raw64, blob)``."""
    ephemeral = ec.generate_private_key(_CURVE)
    z = ecdh_raw_x(ephemeral, recipient_pub64)
    blob = seal(z, plaintext)
    epk = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )[1:]
    return epk, blob
