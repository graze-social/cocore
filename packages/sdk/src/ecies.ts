// `p256-ecies-se` sealed-box construction (WebCrypto; browser + Node safe).
//
// The cross-language mirror of the Rust provider's `crypto::ecies` and the
// Python `cocore/ecies.py`. Given an ephemeral-static P-256 ECDH shared secret
// `Z` (the raw 32-byte X-coordinate), the wire is:
//
//   key  = HKDF-SHA256(salt = 0x00*32, IKM = Z, info = "cocore/p256-ecies-se/v1", 32)
//   iv   = 12 random bytes (fresh per message, ON the wire)
//   blob = iv(12) || AES-256-GCM(key, iv, aad = <empty>, plaintext)   // ct || 16-byte tag
//
// The recipient's static P-256 key lives in the provider's Secure Enclave, so
// the decrypting scalar never leaves the machine — a copied software key can't
// recover a sealed prompt or the APNs code-challenge nonce (ADR-0005). The
// peer's ephemeral public key (`epk`) travels out-of-band, exactly where the
// X25519 path carries the sender key, so no wire framing changes.

// Type-only aliases for the WebCrypto types (erased at build; the runtime uses
// the global `crypto`). Sourced from node's webcrypto so this compiles under an
// ES-lib tsconfig without the DOM lib — matching how `p256.ts` stays lib-free.
import type { webcrypto } from "node:crypto";

type CryptoKeyT = webcrypto.CryptoKey;
type CryptoKeyPairT = webcrypto.CryptoKeyPair;

/** HKDF info label. Bump the `/vN` (and mint a new `encScheme`) if the
 *  construction ever changes. */
const INFO = new TextEncoder().encode("cocore/p256-ecies-se/v1");
const IV_LEN = 12;

function subtle(): webcrypto.SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto SubtleCrypto unavailable");
  return c.subtle;
}

/** Prepend the SEC1 uncompressed tag (0x04) to a raw 64-byte `X || Y` point. */
function uncompressed(pub64: Uint8Array): Uint8Array {
  if (pub64.length !== 64) throw new Error(`expected 64-byte P-256 point, got ${pub64.length}`);
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(pub64, 1);
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Import a raw 64-byte peer public key for ECDH. */
async function importPeerPublic(pub64: Uint8Array): Promise<CryptoKeyT> {
  return subtle().importKey(
    "raw",
    new Uint8Array(uncompressed(pub64)),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
}

/** ECDH → raw 32-byte shared secret `Z` (the X-coordinate). `privKey` is an
 *  ECDH private CryptoKey (a fresh ephemeral for sealing, or the requester's
 *  retained ephemeral for opening a reply); `peerPub64` is the other side's
 *  raw public key. WebCrypto's ECDH deriveBits returns exactly the raw X. */
export async function ecdhRawX(privKey: CryptoKeyT, peerPub64: Uint8Array): Promise<Uint8Array> {
  const peer = await importPeerPublic(peerPub64);
  const bits = await subtle().deriveBits({ name: "ECDH", public: peer }, privKey, 256);
  return new Uint8Array(bits);
}

/** HKDF-SHA256 over `Z` → the AES-256-GCM key. */
export async function deriveKey(z: Uint8Array): Promise<CryptoKeyT> {
  const zKey = await subtle().importKey("raw", new Uint8Array(z), "HKDF", false, ["deriveBits"]);
  const keyBits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new Uint8Array(INFO) },
    zKey,
    256,
  );
  return subtle().importKey("raw", keyBits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** AES-256-GCM seal with an explicit IV → `iv || ct || tag`. Deterministic;
 *  used by the cross-language golden vector. */
export async function sealWithIv(
  key: CryptoKeyT,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const ct = new Uint8Array(
    await subtle().encrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      key,
      new Uint8Array(plaintext),
    ),
  );
  return concat(iv, ct);
}

/** Open an `iv || ct || tag` blob given the AES key. Returns null on auth
 *  failure (wrong Z, tampered ciphertext). */
export async function openWithKey(key: CryptoKeyT, blob: Uint8Array): Promise<Uint8Array | null> {
  if (blob.length < IV_LEN + 16) return null;
  const iv = blob.subarray(0, IV_LEN);
  const body = blob.subarray(IV_LEN);
  try {
    const pt = await subtle().decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      key,
      new Uint8Array(body),
    );
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}

/** Seal `plaintext` to a recipient's raw 64-byte P-256 public key. Mints a
 *  fresh ephemeral keypair (forward secrecy). Returns the 64-byte ephemeral
 *  public key (`epk` — the `requester_pub_key`/advisor `epk` the provider needs
 *  to recompute `Z` via its Secure Enclave) and the `iv || ct || tag` blob.
 *  Also returns the ephemeral private CryptoKey so the caller can open the
 *  provider's reply (which reuses the same `Z`). */
export async function eciesSeal(
  recipientPub64: Uint8Array,
  plaintext: Uint8Array,
): Promise<{ epk: Uint8Array; blob: Uint8Array; ephemeralPrivate: CryptoKeyT }> {
  const eph = (await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ])) as CryptoKeyPairT;
  const z = await ecdhRawX(eph.privateKey, recipientPub64);
  const key = await deriveKey(z);
  const iv = new Uint8Array(IV_LEN);
  globalThis.crypto.getRandomValues(iv);
  const blob = await sealWithIv(key, iv, plaintext);
  const epkFull = new Uint8Array(await subtle().exportKey("raw", eph.publicKey));
  return { epk: epkFull.subarray(1), blob, ephemeralPrivate: eph.privateKey };
}

/** Open a blob the provider sealed back to us, reusing the ephemeral we sealed
 *  the request with. `providerPub64` is the provider's static ECIES key
 *  (`encryptionPubKey`); `Z = ECDH(ephemeralPrivate, providerPub)` is the same
 *  shared secret the provider computed via its enclave. */
export async function eciesOpenReply(
  ephemeralPrivate: CryptoKeyT,
  providerPub64: Uint8Array,
  blob: Uint8Array,
): Promise<Uint8Array | null> {
  const z = await ecdhRawX(ephemeralPrivate, providerPub64);
  const key = await deriveKey(z);
  return openWithKey(key, blob);
}
