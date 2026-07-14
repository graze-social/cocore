// Unit coverage for the Secure Mode MDM coordinator's pure paths —
// per-device profile generation, fail-closed config, and the
// push-attestation tolerance that lets the shipped wizard advance.
// These never touch the SQLite chain store (that's exercised separately),
// so they run without the better-sqlite3 native binding.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";

import {
  attestationIsBundled,
  attestationNonceBytes,
  authenticateNanomdmWebhook,
  buildDeviceInformationAttestationCommand,
  buildEnrollmentProfile,
  chainBindsPubkey,
  enqueueTargetNotEnrolled,
  freshnessBindsPubkey,
  isValidSerial,
  isValidUdid,
  parseNanomdmAttestationWebhook,
  pushAttestationCommand,
  requestDeviceInformationAttestation,
  secureMdmConfig,
} from "./mdm-coordinator.server.ts";

const SCEP_KEYS = [
  "COCORE_MDM_SCEP_URL",
  "COCORE_MDM_SCEP_NAME",
  "COCORE_MDM_SCEP_CHALLENGE",
  "COCORE_MDM_SERVER_URL",
  "COCORE_MDM_CHECKIN_URL",
  "COCORE_MDM_TOPIC",
  "COCORE_MDM_ROOT_CA_PEM",
  "COCORE_MDM_INTERMEDIATE_CA_PEM",
  "COCORE_MDM_ACME_URL",
];

const SERIAL = "H2WHW38LQ6NV";
const UDID = "00008103-001869192E20801E"; // Apple-silicon Provisioning UDID (8hex-16hex)
const REAL_UDID = "A1B2C3D4-1111-2222-3333-444455556666"; // Hardware UUID form

function clearEnv(): void {
  for (const k of SCEP_KEYS) delete process.env[k];
  delete process.env["COCORE_NANOMDM_URL"];
  delete process.env["COCORE_NANOMDM_API_KEY"];
}

function configureFull(): void {
  process.env["COCORE_MDM_SCEP_URL"] = "https://ca.example.test:43462/scep/cocore-scep";
  process.env["COCORE_MDM_SCEP_CHALLENGE"] = "s3cr3t&<challenge>";
  process.env["COCORE_MDM_SERVER_URL"] = "https://mdm.example.test/mdm";
  process.env["COCORE_MDM_TOPIC"] = "com.apple.mgmt.External.abc";
  process.env["COCORE_MDM_ROOT_CA_PEM"] =
    "-----BEGIN CERTIFICATE-----\nQUJDREVG\n-----END CERTIFICATE-----";
  process.env["COCORE_MDM_ACME_URL"] = "https://ca.example.test:43462/acme/cocore-attest/directory";
}

const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of [...SCEP_KEYS, "COCORE_NANOMDM_URL", "COCORE_NANOMDM_API_KEY"])
    saved[k] = process.env[k];
  clearEnv();
});
afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

describe("validation", () => {
  it("accepts real Apple serials + UUID and Apple-silicon UDID forms, rejects garbage", () => {
    expect(isValidSerial(SERIAL)).toBe(true);
    expect(isValidSerial("no-dashes-allowed")).toBe(false);
    expect(isValidUdid(REAL_UDID)).toBe(true); // Hardware UUID form
    expect(isValidUdid(UDID)).toBe(true); // Apple-silicon Provisioning UDID (8hex-16hex)
    expect(isValidUdid("0123456789abcdef0123456789abcdef01234567")).toBe(true); // 40-hex legacy
    expect(isValidUdid("not-a-udid")).toBe(false);
    expect(isValidUdid("00008103-ZZZZ69192E20801E")).toBe(false); // non-hex
  });
});

describe("secureMdmConfig — fail-closed", () => {
  it("reports every missing required key when unconfigured", () => {
    const r = secureMdmConfig();
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.missing).toContain("COCORE_MDM_SCEP_URL");
      expect(r.missing).toContain("COCORE_MDM_SCEP_CHALLENGE");
      expect(r.missing).toContain("COCORE_MDM_SERVER_URL");
      expect(r.missing).toContain("COCORE_MDM_TOPIC");
      expect(r.missing).toContain("COCORE_MDM_ROOT_CA_PEM");
    }
  });

  it("resolves once the required keys are present", () => {
    configureFull();
    const r = secureMdmConfig();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.config.scepName).toBe("cocore-scep"); // default
      expect(r.config.checkInUrl).toBe(r.config.mdmServerUrl); // defaults to server URL
      expect(r.config.rootCaB64).toBe("QUJDREVG"); // PEM armor stripped
    }
  });
});

describe("buildEnrollmentProfile", () => {
  it("returns null when the backend isn't configured (route → 503)", () => {
    expect(buildEnrollmentProfile(SERIAL, REAL_UDID)).toBeNull();
  });

  it("emits a SCEP identity + MDM + bundled ACME profile (no empty PKCS12)", () => {
    configureFull();
    const built = buildEnrollmentProfile(SERIAL, REAL_UDID);
    expect(built).not.toBeNull();
    const p = built!.profile;

    // SCEP device identity — not the old empty-PKCS12 stub.
    expect(p).toContain("com.apple.security.scep");
    expect(p).not.toContain("com.apple.security.pkcs12");
    expect(p).toContain("https://ca.example.test:43462/scep/cocore-scep");
    // SCEP challenge is XML-escaped, not raw.
    expect(p).toContain("s3cr3t&amp;&lt;challenge&gt;");
    expect(p).not.toContain("s3cr3t&<challenge>");

    // MDM payload, least-privilege + signed check-ins.
    expect(p).toContain("com.apple.mdm");
    // 19 = 1|2|16: profile inspect/install + Device Information query (bit 16),
    // which DevicePropertiesAttestation requires. No lock/erase/app rights.
    expect(p).toContain("<key>AccessRights</key><integer>19</integer>");
    expect(p).toContain("<key>SignMessage</key><true/>");
    // Newer macOS requires the MDM payload to advertise the user channel.
    expect(p).toContain("com.apple.mdm.per-user-connections");
    expect(p).toContain("https://mdm.example.test/mdm");
    expect(p).toContain("com.apple.mgmt.External.abc");

    // Root trust anchor embedded.
    expect(p).toContain("com.apple.security.root");
    expect(p).toContain("QUJDREVG");

    // Bundled per-serial ACME attestation (CN + ClientIdentifier = serial).
    expect(p).toContain("com.apple.security.acme");
    expect(p).toContain("<key>Attest</key><true/>");
    expect(p).toContain(`<key>ClientIdentifier</key><string>${SERIAL}</string>`);

    // The MDM payload binds to the SCEP identity by UUID.
    const idUuid =
      /com\.apple\.security\.scep[\s\S]*?<key>PayloadUUID<\/key><string>([0-9A-F-]+)<\/string>/.exec(
        p,
      )?.[1];
    expect(idUuid).toBeTruthy();
    expect(p).toContain(`<key>IdentityCertificateUUID</key><string>${idUuid}</string>`);

    expect(built!.signed).toBe(false);
    expect(built!.enrollmentId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("omits the ACME payload when attestation isn't bundled", () => {
    configureFull();
    delete process.env["COCORE_MDM_ACME_URL"];
    expect(attestationIsBundled()).toBe(false);
    const p = buildEnrollmentProfile(SERIAL, REAL_UDID)!.profile;
    expect(p).toContain("com.apple.security.scep");
    expect(p).not.toContain("com.apple.security.acme");
  });
});

describe("pushAttestationCommand — tolerance (no 400 for the shipped wizard)", () => {
  it("ACKs with no MDM target and bundled attestation", async () => {
    configureFull();
    const r = await pushAttestationCommand(SERIAL, null);
    expect(r.queued).toBe(true);
    expect(r.status).toBe("bundled");
  });

  it("ACKs (acknowledged) with no target and no bundling", async () => {
    const r = await pushAttestationCommand(SERIAL, null);
    expect(r.queued).toBe(true);
    expect(r.status).toBe("acknowledged");
  });

  it("stubs the enqueue when a target is given but NanoMDM is unconfigured", async () => {
    const r = await pushAttestationCommand(SERIAL, REAL_UDID);
    expect(r.queued).toBe(true);
    expect(r.stubbed).toBe(true);
    expect(r.status).toBe("queued");
  });
});

describe("enqueueTargetNotEnrolled — transient not-yet-registered race", () => {
  it("matches the field Postgres enrollment_queue FK violation on a 500", () => {
    // The exact NanoMDM body the reporting user pasted from the wizard.
    const body = JSON.stringify({
      command_error:
        'pq: insert or update on table "enrollment_queue" violates foreign key constraint "enrollment_queue_id_fkey"',
      command_uuid: "A9D544A1-294C-4158-A2EC-E48A45A7DE65",
    });
    expect(enqueueTargetNotEnrolled(500, body)).toBe(true);
  });

  it("matches the MySQL foreign-key phrasing referencing enrollment_queue", () => {
    expect(
      enqueueTargetNotEnrolled(
        500,
        "Error 1452: Cannot add or update a child row: a foreign key constraint fails (`nanomdm`.`enrollment_queue`, ...)",
      ),
    ).toBe(true);
  });

  it("ignores unrelated 500s and non-500 statuses", () => {
    expect(enqueueTargetNotEnrolled(500, "internal server error")).toBe(false);
    expect(enqueueTargetNotEnrolled(503, "enrollment_queue foreign key")).toBe(false);
    expect(enqueueTargetNotEnrolled(400, "bad request")).toBe(false);
    expect(enqueueTargetNotEnrolled(200, "")).toBe(false);
  });
});

describe("option-B DeviceInformation attestation (freshness binding)", () => {
  // A representative raw 64-byte P-256 X‖Y public key (base64).
  const PUBKEY_B64 = Buffer.alloc(64, 7).toString("base64");

  it("nonce is sha256 of the raw pubkey bytes (32 bytes)", () => {
    const nonce = attestationNonceBytes(PUBKEY_B64);
    expect(nonce.length).toBe(32);
    const expected = createHash("sha256").update(Buffer.from(PUBKEY_B64, "base64")).digest();
    expect(nonce.equals(expected)).toBe(true);
  });

  it("builds a DeviceInformation command: nonce as <data>, queries attestation + serial", () => {
    const nonce = attestationNonceBytes(PUBKEY_B64);
    const cmd = buildDeviceInformationAttestationCommand(
      "ABCDEF01-2345-6789-ABCD-EF0123456789",
      nonce,
    );
    expect(cmd).toContain("<string>DeviceInformation</string>");
    expect(cmd).toContain("<string>DevicePropertiesAttestation</string>");
    // Must query SerialNumber too — the webhook event has only the UDID, and the
    // chain store is keyed by serial, so the response must carry the serial.
    expect(cmd).toContain("<string>SerialNumber</string>");
    // DeviceAttestationNonce MUST be <data> (Apple schema), carrying the raw
    // 32-byte sha256(pubkey) as base64 — so freshness == sha256(pubkey) exactly.
    expect(cmd).toContain(
      `<key>DeviceAttestationNonce</key>\n    <data>${nonce.toString("base64")}</data>`,
    );
    expect(cmd).not.toContain(`<string>${nonce.toString("base64")}</string>`);
  });

  it("requestDeviceInformationAttestation errors without an MDM target", async () => {
    const r = await requestDeviceInformationAttestation("H2WHW38LQ6NV", null, PUBKEY_B64);
    expect(r.status).toBe("error");
    expect(r.queued).toBe(false);
  });

  it("requestDeviceInformationAttestation stubs when NanoMDM is unconfigured", async () => {
    delete process.env["COCORE_NANOMDM_URL"];
    delete process.env["COCORE_NANOMDM_API_KEY"];
    const r = await requestDeviceInformationAttestation(
      "H2WHW38LQ6NV",
      "A1B2C3D4-1111-2222-3333-444455556666",
      PUBKEY_B64,
    );
    expect(r.stubbed).toBe(true);
    expect(r.status).toBe("queued");
  });

  it("parses a NanoMDM webhook carrying a DevicePropertiesAttestation chain", () => {
    // The device's DeviceInformation response plist (leaf-first base64 DER certs).
    const responsePlist = `<?xml version="1.0"?>
<plist version="1.0"><dict>
  <key>Status</key><string>Acknowledged</string>
  <key>SerialNumber</key><string>H2WHW38LQ6NV</string>
  <key>QueryResponses</key><dict>
    <key>DevicePropertiesAttestation</key>
    <array>
      <data>bGVhZi1kZXItYnl0ZXM=</data>
      <data>aW50ZXJtZWRpYXRlLWRlcg==</data>
    </array>
  </dict>
</dict></plist>`;
    const payload = {
      topic: "mdm.Connect",
      serial: "H2WHW38LQ6NV",
      raw_command_response: Buffer.from(responsePlist, "utf8").toString("base64"),
    };
    const parsed = parseNanomdmAttestationWebhook(payload);
    expect(parsed).not.toBeNull();
    expect(parsed!.serial).toBe("H2WHW38LQ6NV");
    expect(parsed!.chain).toEqual(["bGVhZi1kZXItYnl0ZXM=", "aW50ZXJtZWRpYXRlLWRlcg=="]);
  });

  it("returns null for a webhook with no attestation (e.g. a TokenUpdate)", () => {
    expect(
      parseNanomdmAttestationWebhook({ topic: "mdm.TokenUpdate", serial: "H2WHW38LQ6NV" }),
    ).toBeNull();
    expect(parseNanomdmAttestationWebhook(null)).toBeNull();
    expect(parseNanomdmAttestationWebhook("nope")).toBeNull();
  });

  it("parses the REAL NanoMDM event: acknowledge_event.raw_payload, serial from QueryResponses", () => {
    // Mirrors micromdm/nanomdm testdata/DeviceInformation.1.json: the event has
    // NO top-level serial (only acknowledge_event.udid); the queried SerialNumber
    // + DevicePropertiesAttestation land inside the response's QueryResponses.
    const responsePlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CommandUUID</key><string>76eda240-5488-4989-8339-f2ae160113c4</string>
  <key>QueryResponses</key><dict>
    <key>DevicePropertiesAttestation</key>
    <array><data>bGVhZg==</data><data>aW50ZXI=</data></array>
    <key>SerialNumber</key><string>H2WHW38LQ6NV</string>
  </dict>
  <key>Status</key><string>Acknowledged</string>
</dict></plist>`;
    const payload = {
      topic: "mdm.Connect",
      event_id: "e1",
      acknowledge_event: {
        command_uuid: "76eda240-5488-4989-8339-f2ae160113c4",
        udid: "376AF848-8EC9-5336-AB51-0801857F726D",
        status: "Acknowledged",
        raw_payload: Buffer.from(responsePlist, "utf8").toString("base64"),
      },
    };
    const parsed = parseNanomdmAttestationWebhook(payload);
    expect(parsed).not.toBeNull();
    expect(parsed!.serial).toBe("H2WHW38LQ6NV"); // pulled from the plist, not the event
    expect(parsed!.chain).toEqual(["bGVhZg==", "aW50ZXI="]);
  });

  it("authenticateNanomdmWebhook accepts the ?key= URL secret and a bearer; rejects wrong/unset", () => {
    process.env["COCORE_NANOMDM_WEBHOOK_KEY"] = "s3cr3t-webhook-key-value";
    const viaQuery = new Request(
      "https://c.test/api/agent/mdm/nanomdm-webhook?key=s3cr3t-webhook-key-value",
      {
        method: "POST",
      },
    );
    const viaBearer = new Request("https://c.test/api/agent/mdm/nanomdm-webhook", {
      method: "POST",
      headers: { authorization: "Bearer s3cr3t-webhook-key-value" },
    });
    const wrong = new Request("https://c.test/api/agent/mdm/nanomdm-webhook?key=nope", {
      method: "POST",
    });
    expect(authenticateNanomdmWebhook(viaQuery)).toBe(true);
    expect(authenticateNanomdmWebhook(viaBearer)).toBe(true);
    expect(authenticateNanomdmWebhook(wrong)).toBe(false);
    delete process.env["COCORE_NANOMDM_WEBHOOK_KEY"];
    expect(authenticateNanomdmWebhook(viaQuery)).toBe(false); // fail-closed when unset
  });
});

describe("attestation key-binding guard (stale-command discard)", () => {
  // A 64-byte raw P-256 pubkey (X||Y), base64 — the shape agent pubkey emits.
  const PUBKEY = Buffer.alloc(64, 7).toString("base64");
  const OTHER = Buffer.alloc(64, 9).toString("base64");

  it("the nonce the coordinator sends for a key binds that key", () => {
    // attestationNonceBytes(pubkey) is exactly the DeviceAttestationNonce we set,
    // and Apple reflects it as the leaf freshness code.
    const fresh = new Uint8Array(attestationNonceBytes(PUBKEY));
    expect(freshnessBindsPubkey(fresh, PUBKEY)).toBe(true);
  });

  it("tolerates a DER OCTET STRING wrapper (04 20) on the freshness value", () => {
    const fresh = attestationNonceBytes(PUBKEY);
    const wrapped = new Uint8Array(Buffer.concat([Buffer.from([0x04, 0x20]), fresh]));
    expect(freshnessBindsPubkey(wrapped, PUBKEY)).toBe(true);
  });

  it("REJECTS a stale key's freshness (the signing-key-rotation trap)", () => {
    // A leftover queued command attested OTHER's nonce; it must not bind PUBKEY.
    const staleFresh = new Uint8Array(attestationNonceBytes(OTHER));
    expect(freshnessBindsPubkey(staleFresh, PUBKEY)).toBe(false);
  });

  it("rejects a wrong-length freshness value", () => {
    expect(freshnessBindsPubkey(new Uint8Array(16), PUBKEY)).toBe(false);
  });

  it("chainBindsPubkey fails closed on an empty or unparseable chain", () => {
    expect(chainBindsPubkey([], PUBKEY)).toBe(false);
    expect(chainBindsPubkey(["not-base64-DER"], PUBKEY)).toBe(false);
  });
});
