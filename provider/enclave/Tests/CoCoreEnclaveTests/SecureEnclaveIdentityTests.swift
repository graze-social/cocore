// Run only on a real Mac with a Secure Enclave; the @MainActor +
// SecureEnclave.isAvailable guard short-circuits on CI runners that
// don't have one. CI builds run `swift build -c release` to confirm
// the package still compiles; the actual key creation is exercised
// in manual smoke tests on a paired machine.

import XCTest
import CryptoKit
@testable import CoCoreEnclave

final class SecureEnclaveIdentityTests: XCTestCase {
    func testLoadOrCreate_roundTrips() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "no Secure Enclave on this host")
        let id = try SecureEnclaveIdentity.loadOrCreate()
        let pub = id.publicKeyRaw64()
        XCTAssertEqual(pub.count, 64)
        let sig = try id.sign(Data("cocore-test".utf8))
        XCTAssertGreaterThan(sig.count, 0)
        // Verify with CryptoKit using the public key.
        let pkRaw = Data([0x04]) + pub
        // (CryptoKit's P256 init expects compressed or uncompressed —
        // we've stripped the 0x04 in publicKeyRaw64, restore it here.)
        let pk = try P256.Signing.PublicKey(x963Representation: pkRaw)
        let derSig = try P256.Signing.ECDSASignature(derRepresentation: sig)
        XCTAssertTrue(pk.isValidSignature(derSig, for: Data("cocore-test".utf8)))
    }

    /// The SE encryption key: an ECDH with a software ephemeral peer must yield
    /// the SAME 32-byte shared secret both sides compute — and it must be the
    /// raw SEC1 X-coordinate (what `crypto::ecies` HKDFs over). This is the
    /// physical-Mac leg of the cross-language `p256-ecies-se` parity check.
    func testEncKey_ecdhMatchesSoftwarePeer() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "no Secure Enclave on this host")
        let enc = try SecureEnclaveEncKey.loadOrCreate()
        let sePub = enc.publicKeyRaw64()
        XCTAssertEqual(sePub.count, 64)

        // Software ephemeral peer (the "sender" — advisor/SDK side).
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ephemeralPubRaw = ephemeral.publicKey.rawRepresentation // 64B X||Y

        // SE side: ECDH(SE_priv, ephemeral_pub)
        let zFromEnclave = try enc.ecdh(peerRaw64: ephemeralPubRaw)
        XCTAssertEqual(zFromEnclave.count, 32)

        // Software side: ECDH(ephemeral_priv, SE_pub)
        let sePubKey = try P256.KeyAgreement.PublicKey(rawRepresentation: sePub)
        let zFromSoftware = try ephemeral.sharedSecretFromKeyAgreement(with: sePubKey)
            .withUnsafeBytes { Data($0) }

        XCTAssertEqual(zFromEnclave, zFromSoftware, "SE ECDH must equal software ECDH (raw X)")
    }
}
