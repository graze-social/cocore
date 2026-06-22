// cocore-appattest — the App Attest companion helper.
//
// Purpose: produce an Apple App Attest attestation object BOUND to the
// agent's receipt-signing P-256 key, so the provider can publish it in its
// `dev.cocore.compute.attestation` record and earn trustLevel
// `hardware-attested` — WITHOUT any MDM / step-ca / SCEP stack.
//
// The binding is by construction: we set
//
//     clientDataHash = SHA256(signingPubKeyBytes)
//
// where `signingPubKeyBytes` is the raw 64-byte P-256 X‖Y point the agent
// publishes as `attestation.publicKey`. Apple commits that hash into the
// attestation's credential-certificate nonce extension
// (OID 1.2.840.113635.100.8.2). The verifier (appattest.rs / appattest.ts /
// appattest.py) recomputes `nonce = SHA256(authData ‖ SHA256(publicKey))` and
// requires it to equal that extension — that IS the binding to the signing
// key. See lexicons/dev/cocore/compute/attestation.json#appAttest.
//
// I/O contract (also consumed by the Rust agent via COCORE_APPATTEST_BINARY):
//   argv[1]  base64 of the raw 64-byte P-256 X‖Y signing public key
//            (falls back to reading the same value from stdin if absent).
//   stdout   a single JSON object:
//              { "object": "<base64 CBOR attestation object>",
//                "keyId":  "<base64 App Attest key id = SHA256(attested pubkey)>",
//                "clientDataHashHex": "<hex>",
//                "appId": "TEAMID.dev.cocore.provider",
//                "environment": "production" }
//   exit 0   success. Non-zero + a diagnostic on stderr otherwise (e.g. the
//            device doesn't support App Attest, or the entitlement is missing).
//
// stderr may contain device-identifying material on error paths, so the agent
// (mda_loader::load_appattest) deliberately does NOT route it to its logger.
//
// Build + sign: see ../build.sh. App Attest requires the entitlement
// `com.apple.developer.devicecheck.appattest-environment`, which must be in the
// embedded provisioning profile (regenerate the dev.cocore.provider profile in
// the Apple Developer portal with the App Attest capability — see ../README.md).

import CryptoKit
import DeviceCheck
import Foundation

let APP_ID = "4L45P7CP9M.dev.cocore.provider"
let ENVIRONMENT = "production"

func die(_ msg: String) -> Never {
    FileHandle.standardError.write(Data(("cocore-appattest: " + msg + "\n").utf8))
    exit(1)
}

func readSigningPubKeyB64() -> String {
    if CommandLine.arguments.count >= 2 {
        let a = CommandLine.arguments[1].trimmingCharacters(in: .whitespacesAndNewlines)
        if !a.isEmpty { return a }
    }
    // Fall back to stdin (one line / whitespace-trimmed).
    let data = FileHandle.standardInput.readDataToEndOfFile()
    let s = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    if s.isEmpty { die("no signing public key on argv[1] or stdin") }
    return s
}

let pubKeyB64 = readSigningPubKeyB64()
guard let pubKey = Data(base64Encoded: pubKeyB64) else {
    die("argv[1]/stdin is not valid base64")
}
// The agent publishes the raw 64-byte X‖Y point. Tolerate the 65-byte
// uncompressed-with-0x04-prefix form too, but bind to exactly what the
// verifier will hash, which is the published `publicKey` bytes.
if pubKey.count != 64 && !(pubKey.count == 65 && pubKey.first == 0x04) {
    die("signing public key must be 64 raw P-256 bytes (X‖Y); got \(pubKey.count)")
}

let service = DCAppAttestService.shared
guard service.isSupported else {
    die("DCAppAttestService not supported on this device (needs Apple silicon + Secure Enclave, and a non-sandboxed signed build)")
}

// clientDataHash = SHA256(published signing pubkey). This is the value Apple
// stamps into the credCert nonce extension; the verifier recomputes it.
let clientDataHash = Data(SHA256.hash(data: pubKey))

// generateKey → attestKey, both async completion-handler APIs; drive them
// synchronously with a semaphore since this is a one-shot CLI.
let sem = DispatchSemaphore(value: 0)
var keyIdOut: String?
var attestationOut: Data?
var errOut: Error?

service.generateKey { keyId, error in
    if let error = error { errOut = error; sem.signal(); return }
    guard let keyId = keyId else { errOut = nil; sem.signal(); return }
    keyIdOut = keyId
    service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
        if let error = error { errOut = error }
        attestationOut = attestation
        sem.signal()
    }
}
// Bounded wait so a wedged framework call can't hang the agent's boot.
if sem.wait(timeout: .now() + 20) == .timedOut {
    die("App Attest call timed out after 20s")
}

if let e = errOut { die("App Attest failed: \(e.localizedDescription)") }
guard let keyId = keyIdOut else { die("generateKey returned no key id") }
guard let attestation = attestationOut else { die("attestKey returned no attestation object") }

// The Apple key id is already base64 (it is the SHA256 of the attested public
// key). We emit it verbatim so `keyId` in the record decodes to that 32-byte
// hash, which the verifier cross-checks against authData's credentialId.
let out: [String: String] = [
    "object": attestation.base64EncodedString(),
    "keyId": keyId,
    "clientDataHashHex": clientDataHash.map { String(format: "%02x", $0) }.joined(),
    "appId": APP_ID,
    "environment": ENVIRONMENT,
]
let json = try! JSONSerialization.data(withJSONObject: out, options: [.sortedKeys])
FileHandle.standardOutput.write(json)
FileHandle.standardOutput.write(Data("\n".utf8))
