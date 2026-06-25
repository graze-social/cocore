// SecureModeWizard: a guided (but MANUAL) flow that walks the owner through
// hardware-attesting this Mac as a co/core provider via an MDM enrollment +
// step-ca attestation chain. macOS will NOT let the app install the profile
// or Touch-ID on the user's behalf — so every step the app can only OPEN the
// right pane, narrate what to click, and POLL for the result, then advance.
//
// Driven by an explicit `Step` state machine so each phase is self-contained
// and skippable: Secure Mode is best-effort hardening, never a gate. Network
// calls are wrapped so a failure shows a friendly error + a Skip, never a
// crash.

import AppKit
import SwiftUI

@MainActor
final class SecureModeWizardController {
    private var window: NSWindow?
    private let state: AppState
    private let updater: Updater
    private let onReauth: () -> Void

    init(
        state: AppState,
        updater: Updater,
        onReauth: @escaping () -> Void
    ) {
        self.state = state
        self.updater = updater
        self.onReauth = onReauth
    }

    func show() {
        if window == nil {
            let view = SecureModeWizardView(
                state: state,
                updater: updater,
                close: { [weak self] in self?.window?.close() },
                onReauth: { [weak self] in
                    self?.window?.close()
                    self?.onReauth()
                }
            )
            let w = NSWindow(contentViewController: NSHostingController(rootView: view))
            w.title = "co/core — Secure Mode"
            w.styleMask = [.titled, .closable]
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        if let w = window { WindowActivation.present(w) }
    }
}

// MARK: - hardware identity probe

/// This Mac's hardware serial + UDID (provisioning UDID), needed to request
/// an MDM enrollment profile. Both are read via the standard macOS tools.
enum HardwareID {
    /// `IOPlatformSerialNumber` from the IO registry. Empty on failure.
    static func serial() -> String {
        // Prefer ioreg (stable across macOS versions); fall back to
        // system_profiler. Both are read-only probes.
        if let s = ioregValue("IOPlatformSerialNumber"), !s.isEmpty { return s }
        let (status, out) = run("/usr/sbin/system_profiler", ["SPHardwareDataType"])
        guard status == 0 else { return "" }
        for line in out.split(separator: "\n") where line.contains("Serial Number") {
            if let v = line.split(separator: ":").last {
                return v.trimmingCharacters(in: .whitespaces)
            }
        }
        return ""
    }

    /// `IOPlatformUUID` (the provisioning UDID). Empty on failure.
    static func udid() -> String {
        ioregValue("IOPlatformUUID") ?? ""
    }

    /// Pull a single quoted value for `key` out of `ioreg -rd1 -c
    /// IOPlatformExpertDevice` (lines look like `"key" = "value"`).
    private static func ioregValue(_ key: String) -> String? {
        let (status, out) = run("/usr/sbin/ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"])
        guard status == 0 else { return nil }
        for line in out.split(separator: "\n") where line.contains("\"\(key)\"") {
            // `    "IOPlatformSerialNumber" = "XXXX"`
            let parts = line.components(separatedBy: "=")
            guard parts.count >= 2 else { continue }
            let raw = parts[1].trimmingCharacters(in: .whitespaces)
            return raw.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        }
        return nil
    }

    private static func run(_ tool: String, _ args: [String]) -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        do {
            try p.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
        } catch {
            return (-1, "")
        }
    }
}

// MARK: - enrollment detection

/// Reads MDM enrollment state via `profiles status -type enrollment`. The
/// app can only detect; the user must Allow + Touch-ID the install.
enum EnrollmentProbe {
    /// True once this Mac reports an enrolled (MDM) configuration. We match
    /// the strings `profiles status` prints when an enrollment is present.
    static func isEnrolled() -> Bool {
        let (status, out) = run("/usr/bin/profiles", ["status", "-type", "enrollment"])
        guard status == 0 else { return false }
        let lower = out.lowercased()
        // "Enrolled via DEP: No" / "MDM enrollment: Yes (...)" — treat any
        // affirmative MDM-enrollment line as enrolled.
        if lower.contains("mdm enrollment: yes") { return true }
        // TODO: confirm exact phrasing on the target macOS; fall back to a
        // looser match so a wording change doesn't silently block the flow.
        if lower.contains("enrolled") && !lower.contains("not enrolled") { return true }
        return false
    }

    private static func run(_ tool: String, _ args: [String]) -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do {
            try p.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
        } catch {
            return (-1, "")
        }
    }
}

// MARK: - attestation failure diagnostic

/// A structured, copy-pasteable diagnostic for a stalled/failed attesting
/// step. Built only from signals we actually observed — the device's
/// enrollment state, the `push-attestation` response, and the last
/// `attestation-chain` poll — so a failure carries WHY, not just "not ready".
///
/// We `NSLog` `report` (so it lands in the log file: greppable, and feedable
/// to a model verbatim) and show `userMessage` inline so the owner can paste
/// it back to us. Pure value type, no I/O, so the classification is easy to
/// reason about (and test) in isolation.
struct AttestationDiagnostic {
    var serial: String
    var enrolled: Bool
    var elapsedSeconds: Int
    var polls: Int
    /// `push-attestation` response: status (bundled|acknowledged|queued|
    /// queued-no-push|error), whether it was a stub (no real NanoMDM call),
    /// and any server-side detail.
    var pushStatus: String?
    var pushStubbed: Bool?
    var pushDetail: String?
    /// Last `attestation-chain` poll: store status (pending|error|captured),
    /// any detail, and the last non-200 HTTP code seen (nil when every GET was
    /// a clean 200 that simply carried no chain yet).
    var chainStatus: String?
    var chainDetail: String?
    var chainHTTP: Int?

    /// Stable, greppable code for the classified failure. Ordered most- to
    /// least-specific so the first matching cause wins.
    var code: String {
        if !enrolled { return "secure-mode/not-enrolled" }
        if pushStatus == "error" { return "secure-mode/push-failed" }
        if chainStatus == "error" || chainHTTP != nil { return "secure-mode/chain-store-error" }
        return "secure-mode/chain-not-captured"
    }

    /// Plain-language cause, safe to show the owner.
    var summary: String {
        switch code {
        case "secure-mode/not-enrolled":
            return "This Mac doesn't report MDM enrollment, so it can't be asked "
                + "to hardware-attest. Re-run the enroll step and Allow + Touch ID "
                + "the management profile."
        case "secure-mode/push-failed":
            return "The coordinator couldn't queue the attestation request "
                + "(\(pushDetail ?? "no detail"))."
        case "secure-mode/chain-store-error":
            let detail = chainDetail ?? (chainHTTP.map { "HTTP \($0)" } ?? "unknown")
            return "The attestation-chain store returned an error (\(detail))."
        default:
            return "No hardware attestation landed within \(elapsedSeconds)s. "
                + "Hardware attestation runs in the background and is rate-limited "
                + "by Apple, so it can take a while — this Mac may still attest "
                + "later without any action from you."
        }
    }

    /// Internal next-step for whoever debugs this next (logged, not a user nag).
    var operatorNextStep: String {
        switch code {
        case "secure-mode/not-enrolled":
            return "agent: mdm_enrolled() is false; confirm `profiles status -type enrollment`."
        case "secure-mode/push-failed":
            return "check NanoMDM /v1/enqueue + /v1/push and that the device's UDID is a valid NanoMDM target."
        case "secure-mode/chain-store-error":
            return "check the console chain store + the step-ca / NanoMDM attestation webhook ingest."
        default:
            return "the Attest button does not itself trigger a hardware attestation — "
                + "capture is driven by the agent's background option-B flow. Check the "
                + "agent log for \"MDA auto:\" lines (request/bind), and with "
                + "COCORE_MDM_WEBHOOK_DEBUG set GET attestation-chain?serial="
                + "zzwebhookdebuglast to see whether NanoMDM is posting results."
        }
    }

    /// The full key=value block we log + surface. One place to read every
    /// signal that fed the classification.
    var report: String {
        let stub = pushStubbed.map { $0 ? "true" : "false" } ?? "—"
        // nil chainHTTP means either a clean 200 last poll OR no poll ever ran
        // (push-failed path) — distinguish them via polls so the log never
        // shows a fabricated "200" for a leg that never executed.
        let http = chainHTTP.map { "\($0)" } ?? (polls == 0 ? "n/a" : "200")
        return [
            "co/core Secure Mode attestation failed [\(code)]",
            "serial=\(serial) enrolled=\(enrolled) elapsed=\(elapsedSeconds)s polls=\(polls)",
            "push-attestation: status=\(pushStatus ?? "—") stubbed=\(stub) detail=\(pushDetail ?? "—")",
            "chain-store: status=\(chainStatus ?? "—") http=\(http) detail=\(chainDetail ?? "—")",
            "cause: \(summary)",
            "next: \(operatorNextStep)",
        ].joined(separator: "\n")
    }

    /// What the wizard shows inline: the plain cause, the Retry/Skip nudge,
    /// then the full report so the owner can copy it straight to us.
    var userMessage: String {
        summary + "\n\nClick Retry, or Skip this step and revisit Secure Mode "
            + "later. If you report this, copy the detail below:\n\n" + report
    }
}

// MARK: - wizard view

struct SecureModeWizardView: View {
    @ObservedObject var state: AppState
    @ObservedObject var updater: Updater
    let close: () -> Void
    /// Route to the sign-in flow. Used when the agent's publish session is
    /// dead — attesting is pointless until it's restored.
    let onReauth: () -> Void

    /// The wizard's explicit state machine. Every step is reachable, and
    /// every step is skippable (→ Secure Mode stays best-effort).
    enum Step: Int {
        case intro, updating, enroll, attesting, done
    }

    @State private var step: Step = .intro
    /// A friendly, non-fatal error from the current step's network call, if
    /// any. Shown inline with a Retry + Skip; never blocks the wizard.
    @State private var stepError: String?
    /// True while the current step's async work (a poll / a fetch) is live.
    @State private var working = false
    /// A short progress/status line under the current step.
    @State private var progress: String?

    // Enrollment artifacts carried between steps.
    @State private var enrollmentId: String?
    @State private var serial: String = HardwareID.serial()
    @State private var udid: String = HardwareID.udid()

    /// Active poll task, cancelled when the user skips/closes a step.
    @State private var pollTask: Task<Void, Never>?

    /// Diagnostic signals captured during the attesting step, so a stall
    /// surfaces WHY (see `AttestationDiagnostic`) instead of just "not ready".
    @State private var pushStatus: String?
    @State private var pushStubbed: Bool?
    @State private var pushDetail: String?
    @State private var chainStatus: String?
    @State private var chainDetail: String?
    @State private var chainHTTP: Int?
    @State private var pollAttempts = 0

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    content
                    if let stepError {
                        Text(stepError)
                            .font(.callout).foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let progress {
                        HStack(spacing: 8) {
                            if working { ProgressView().controlSize(.small) }
                            Text(progress).font(.callout).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            footer
        }
        .frame(width: 540, height: 600)
        .brandStyled()
        .onAppear { fastPathIfAlreadyEnrolled() }
        .onDisappear { pollTask?.cancel() }
    }

    /// When the wizard opens on a Mac that's ALREADY MDM-enrolled (the owner
    /// re-running Secure Mode), jump past intro/update/enroll straight to
    /// re-attesting — never re-issue an enrollment profile. This is the primary
    /// guard against re-adding a pending enrollment; `startEnrollStep` is the
    /// backstop if the user navigates there another way.
    private func fastPathIfAlreadyEnrolled() {
        guard step == .intro, EnrollmentProbe.isEnrolled() else { return }
        NSLog("cocore: Secure Mode wizard opened on an already-enrolled Mac — re-attesting only")
        MenuBarController.setSecureModeDesired(true)
        state.secureModeDesired = true
        advance(to: .attesting)
        startAttestingStep()
    }

    // MARK: header / footer

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "lock.shield")
                .font(.system(size: 34))
                .foregroundStyle(Brand.mark)
            VStack(alignment: .leading, spacing: 3) {
                Text("Secure Mode")
                    .font(.largeTitle).bold()
                    .foregroundStyle(Brand.accentText)
                Text("Hardware-attest this Mac so requesters can verify it.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Brand.surface)
    }

    private var footer: some View {
        HStack(spacing: 12) {
            // Skip is always available — Secure Mode is best-effort.
            if step != .done {
                Button("Skip this step") { skipStep() }
                    .buttonStyle(.link)
            }
            Spacer()
            if step == .done {
                Button("Done") { close() }
                    .keyboardShortcut(.defaultAction)
            } else {
                Button("Not now") { close() }
            }
        }
        .padding(20)
    }

    // MARK: per-step content

    @ViewBuilder private var content: some View {
        switch step {
        case .intro: introStep
        case .updating: updatingStep
        case .enroll: enrollStep
        case .attesting: attestingStep
        case .done: doneStep
        }
    }

    private var introStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Let's harden your agent")
                .font(.title2).bold().foregroundStyle(Brand.accentText)
            Text(
                "We're hardening your co/core agent so requesters can verify your Mac in "
                    + "hardware. We'll ask for a couple of small permissions — all the profile "
                    + "can do is install configuration profiles."
            )
            .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 10) {
                Button("Continue") { advance(to: .updating); startUpdatingStep() }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                Button("Not now") { close() }
            }
        }
    }

    private var updatingStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Make sure you're on the latest secure build")
                .font(.title3).bold().foregroundStyle(Brand.accentText)
            Text(
                "Secure Mode needs the latest co/core build. We'll check for an update and "
                    + "install it if there's a newer one; otherwise we move on."
            )
            .fixedSize(horizontal: false, vertical: true)
            switch updater.status {
            case .available(let v), .required(let v):
                Text("Update \(v) available — installing…").font(.callout).foregroundStyle(.secondary)
            case .updating(let v):
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Updating to \(v)…").font(.callout).foregroundStyle(.secondary)
                }
            case .failed(let m):
                Text(m).font(.callout).foregroundStyle(.red).lineLimit(3)
            case .upToDate:
                Label("You're on the latest build.", systemImage: "checkmark.seal")
                    .foregroundStyle(Brand.success)
            }
            Button("Continue") { advance(to: .enroll) }
                .buttonStyle(.borderedProminent).controlSize(.large)
        }
    }

    private var enrollStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Install the management profile")
                .font(.title3).bold().foregroundStyle(Brand.accentText)
            Text(
                "We'll hand macOS a configuration profile, then open System Settings ▸ "
                    + "Device Management. There you must click Allow and confirm with Touch ID — "
                    + "macOS won't let us do that for you. The profile only installs "
                    + "configuration profiles; it can't read your data."
            )
            .fixedSize(horizontal: false, vertical: true)
            if serial.isEmpty || udid.isEmpty {
                Text("Couldn't read this Mac's serial/UDID — you can still continue, but enrollment may not complete.")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 10) {
                Button("Fetch & open the profile") { startEnrollStep() }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .disabled(working)
                Button("Open System Settings again") { openDeviceManagement() }
            }
            if working {
                Text("Waiting for you to Allow + Touch ID the profile…")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private var attestingStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Attesting your hardware")
                .font(.title3).bold().foregroundStyle(Brand.accentText)
            if state.needsReauth {
                // Attesting writes a provider record. If the agent's publish
                // session is dead, that write 401s and the attestation never
                // lands — the silent dead-end this guard exists to prevent. So
                // we refuse to attest and route to sign-in first.
                Label(
                    "Your co/core session expired, so this Mac can't publish its attestation "
                        + "yet. Sign in again, then come back to Secure Mode.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                Button("Sign in again") { onReauth() }
                    .buttonStyle(.borderedProminent).controlSize(.large)
            } else {
                Text(
                    "Your Mac is enrolled. We're now asking it to attest its hardware identity and "
                        + "building the attestation chain. This can take a moment."
                )
                .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    Button("Attest now") { startAttestingStep() }
                        .buttonStyle(.borderedProminent).controlSize(.large)
                        .disabled(working)
                    Button("Retry") { startAttestingStep() }
                        .disabled(working)
                }
            }
        }
    }

    private var doneStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("🎉 This Mac is now a hardware-attested co/core provider.")
                .font(.title2).bold().foregroundStyle(Brand.accentText)
                .fixedSize(horizontal: false, vertical: true)
            Text("Requesters can now verify your Mac in hardware before sending it work.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: step transitions

    private func advance(to next: Step) {
        pollTask?.cancel()
        working = false
        stepError = nil
        progress = nil
        step = next
    }

    /// Skip the current step → move to the next, staying best-effort.
    private func skipStep() {
        let next = Step(rawValue: step.rawValue + 1) ?? .done
        advance(to: next)
        if next == .updating { startUpdatingStep() }
    }

    // MARK: step 2 — updating

    private func startUpdatingStep() {
        Task {
            await updater.check(autoApplyRequired: false)
            // If an update is available, apply it (the app relaunches, so the
            // wizard won't proceed here on a real update). If up to date, the
            // step view shows the green check and the user clicks Continue.
            if case .available = updater.status { await updater.apply() }
        }
    }

    // MARK: step 3 — enroll

    private func startEnrollStep() {
        stepError = nil
        // The owner has committed to Secure Mode — record the durable intent
        // now so a restart, a lapsed attestation, or a transient failure keeps
        // re-driving it instead of silently dropping back to self-attested.
        MenuBarController.setSecureModeDesired(true)
        state.secureModeDesired = true
        // Already enrolled (re-running the wizard on a Mac that's been secured
        // before): do NOT fetch a fresh enrollment profile — that mints a brand
        // -new pending enrollment macOS prompts to install AGAIN, which is the
        // "keeps re-adding the pending enrollment" bug. Skip straight to
        // (re)attesting against the existing enrollment.
        if EnrollmentProbe.isEnrolled() {
            NSLog("cocore: Secure Mode wizard — already MDM-enrolled, skipping re-enrollment")
            working = false
            progress = nil
            advance(to: .attesting)
            startAttestingStep()
            return
        }
        working = true
        progress = "Requesting your enrollment profile…"
        Task {
            do {
                let (mobileconfig, enrollId) = try await fetchEnrollProfile()
                enrollmentId = enrollId
                // Write the .mobileconfig to a temp file and open it.
                let tmp = FileManager.default.temporaryDirectory
                    .appendingPathComponent("cocore-enroll-\(UUID().uuidString).mobileconfig")
                try mobileconfig.write(to: tmp)
                NSWorkspace.shared.open(tmp)
                openDeviceManagement()
                progress = "Click Allow in Device Management, then confirm with Touch ID. We'll detect it automatically."
                pollForEnrollment()
            } catch {
                working = false
                stepError = friendly(error, "We couldn't fetch your enrollment profile.")
            }
        }
    }

    /// The paired service's base URL + bearer key. Every /api/agent/* call —
    /// including the MDM coordinator endpoints — must target the service that
    /// paired us (`session.apiBase`) and carry our key, or it 401s. Using the
    /// baked console URL or omitting the header is the classic failure mode;
    /// see AppState.refreshStatus / AgentSupervisor for the same posture.
    private func agentAuth() throws -> (base: String, apiKey: String) {
        guard let s = state.session, let key = s.apiKey, let base = s.apiBase else {
            throw WizardError.notPaired
        }
        return (base, key)
    }

    /// POST {apiBase}/api/agent/mdm/enroll-profile {serial,udid} → returns the
    /// .mobileconfig bytes + an enrollmentId.
    private func fetchEnrollProfile() async throws -> (Data, String?) {
        let (base, apiKey) = try agentAuth()
        guard let url = URL(string: "\(base)/api/agent/mdm/enroll-profile") else {
            throw WizardError.badURL
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        req.timeoutInterval = 20
        let body = ["serial": serial, "udid": udid]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            throw WizardError.http((resp as? HTTPURLResponse)?.statusCode ?? 0)
        }
        // The endpoint may return the raw .mobileconfig, or a JSON envelope
        // { profile: <base64>, enrollmentId }. Handle both.
        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let enrollId = obj["enrollmentId"] as? String
            if let b64 = obj["profile"] as? String, let decoded = Data(base64Encoded: b64) {
                return (decoded, enrollId)
            }
            // JSON but no profile field — treat the whole body as the config.
            return (data, enrollId)
        }
        return (data, nil)
    }

    /// Poll `profiles status -type enrollment` until enrolled (or timeout).
    private func pollForEnrollment() {
        pollTask?.cancel()
        pollTask = Task {
            let deadline = Date().addingTimeInterval(300) // 5 min
            while !Task.isCancelled, Date() < deadline {
                if EnrollmentProbe.isEnrolled() {
                    working = false
                    progress = nil
                    advance(to: .attesting)
                    startAttestingStep()
                    return
                }
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
            if !Task.isCancelled {
                working = false
                stepError =
                    "We didn't detect the enrollment. Click \"Open System Settings again\", "
                    + "Allow the profile + Touch ID, or Skip this step."
            }
        }
    }

    // MARK: step 4 — attesting

    private func startAttestingStep() {
        stepError = nil
        resetAttestDiagnostics()
        working = true
        progress = "Requesting a hardware attestation…"
        Task {
            // Confirm the agent can actually publish before we attest — a fresh
            // status probe sets state.needsReauth. Attesting with a dead session
            // produces a chain the agent can never publish (the silent dead-end).
            await state.refreshStatus()
            if state.needsReauth {
                working = false
                progress = nil
                return  // attestingStep now renders the "Sign in again" panel
            }
            let pushStart = Date()
            do {
                try await pushAttestation()
                progress = "Building the attestation chain…"
                pollForAttestationChain()
            } catch {
                working = false
                // The push leg failing is the same silent-failure pattern we
                // fix for the poll leg — classify + log it instead of dropping
                // to a bare string. The push definitively failed (it threw), so
                // force the error status UNCONDITIONALLY: recordPushResponse may
                // have already captured a non-"error" body status, and a plain
                // `?? "error"` would leave that stale value and misclassify the
                // failure onto a chain code. Keep the server's message as the
                // detail when it gave one, else the thrown error's text.
                pushStatus = "error"
                pushDetail = pushDetail ?? error.localizedDescription
                let diag = AttestationDiagnostic(
                    serial: serial,
                    enrolled: EnrollmentProbe.isEnrolled(),
                    elapsedSeconds: Int(Date().timeIntervalSince(pushStart)),
                    polls: 0,
                    pushStatus: pushStatus,
                    pushStubbed: pushStubbed,
                    pushDetail: pushDetail,
                    chainStatus: nil,
                    chainDetail: nil,
                    chainHTTP: nil
                )
                NSLog("cocore: %@", diag.report)
                stepError = diag.userMessage
            }
        }
    }

    /// POST {apiBase}/api/agent/mdm/push-attestation {serial,enrollmentId}.
    private func pushAttestation() async throws {
        let (base, apiKey) = try agentAuth()
        guard let url = URL(string: "\(base)/api/agent/mdm/push-attestation") else {
            throw WizardError.badURL
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        req.timeoutInterval = 20
        var body: [String: String] = ["serial": serial]
        if let id = enrollmentId { body["enrollmentId"] = id }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await URLSession.shared.data(for: req)
        recordPushResponse(data)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            throw WizardError.http((resp as? HTTPURLResponse)?.statusCode ?? 0)
        }
    }

    /// Reset the captured diagnostic signals at the start of an attest run so a
    /// Retry never reports stale state from a previous attempt.
    private func resetAttestDiagnostics() {
        pushStatus = nil
        pushStubbed = nil
        pushDetail = nil
        chainStatus = nil
        chainDetail = nil
        chainHTTP = nil
        pollAttempts = 0
    }

    /// Capture the `push-attestation` response signals (status/stubbed/detail)
    /// for the failure diagnostic. Best-effort: a non-JSON body just leaves the
    /// fields nil.
    private func recordPushResponse(_ data: Data) {
        guard
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return }
        pushStatus = obj["status"] as? String
        pushStubbed = obj["stubbed"] as? Bool
        pushDetail = obj["detail"] as? String
    }

    /// Poll GET {apiBase}/api/agent/mdm/attestation-chain?serial=... until a
    /// chain returns (or timeout).
    private func pollForAttestationChain() {
        pollTask?.cancel()
        pollTask = Task {
            let deadline = Date().addingTimeInterval(180)
            guard
                let auth = try? agentAuth(),
                let serialEnc = serial.addingPercentEncoding(
                    withAllowedCharacters: .urlQueryAllowed),
                let url = URL(string: "\(auth.base)/api/agent/mdm/attestation-chain?serial=\(serialEnc)")
            else {
                working = false
                stepError = "We couldn't build the attestation-chain request."
                return
            }
            let start = Date()
            while !Task.isCancelled, Date() < deadline {
                // Count every attempt, including ones whose request throws
                // (network error / timeout), so `polls` in the report reflects
                // the real effort, not just the responses that came back.
                pollAttempts += 1
                var req = URLRequest(url: url)
                req.setValue("Bearer \(auth.apiKey)", forHTTPHeaderField: "Authorization")
                req.timeoutInterval = 15
                if let (data, resp) = try? await URLSession.shared.data(for: req) {
                    let http = (resp as? HTTPURLResponse)?.statusCode ?? 0
                    recordChainResponse(data, http: http)
                    if http == 200, hasChain(data) {
                        working = false
                        progress = nil
                        // Attestation landed — make sure the durable intent is set
                        // so the posture survives restarts (intro fast-path may have
                        // skipped startEnrollStep where it's normally written).
                        MenuBarController.setSecureModeDesired(true)
                        state.secureModeDesired = true
                        advance(to: .done)
                        return
                    }
                }
                try? await Task.sleep(nanoseconds: 4_000_000_000)
            }
            if !Task.isCancelled {
                working = false
                // Don't fail silently with a bare "not ready" — classify what we
                // observed into a structured diagnostic, log the full report (so
                // it's greppable / feedable to a model), and surface the cause.
                let diag = AttestationDiagnostic(
                    serial: serial,
                    enrolled: EnrollmentProbe.isEnrolled(),
                    elapsedSeconds: Int(Date().timeIntervalSince(start)),
                    polls: pollAttempts,
                    pushStatus: pushStatus,
                    pushStubbed: pushStubbed,
                    pushDetail: pushDetail,
                    chainStatus: chainStatus,
                    chainDetail: chainDetail,
                    chainHTTP: chainHTTP
                )
                NSLog("cocore: %@", diag.report)
                stepError = diag.userMessage
            }
        }
    }

    /// Capture the latest `attestation-chain` poll signals for the diagnostic.
    /// A non-200 records the HTTP code (so the diagnostic classifies it as a
    /// store error); a 200 leaves `chainHTTP` nil (clean poll, just no chain
    /// yet) and pulls status/detail from the JSON body when present.
    private func recordChainResponse(_ data: Data, http: Int) {
        // Reflect ONLY the last poll's signals so a transient blip never
        // sticks: a mid-window non-200 (or its JSON `status:"error"` body)
        // must not survive into a later clean-but-pending poll and misclassify
        // the timeout as a store error. We therefore overwrite all three
        // fields every call — including to nil when a 200 body is empty or
        // unparseable (no status this poll), rather than early-returning and
        // leaving a stale status behind.
        chainHTTP = http == 200 ? nil : http
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        chainStatus = obj?["status"] as? String
        chainDetail = obj?["detail"] as? String
    }

    /// A response carries a usable chain when it's a non-empty array, or an
    /// object with a non-empty `chain`. Lenient so a shape tweak doesn't stall.
    private func hasChain(_ data: Data) -> Bool {
        guard let json = try? JSONSerialization.jsonObject(with: data) else { return false }
        if let arr = json as? [Any] { return !arr.isEmpty }
        if let obj = json as? [String: Any] {
            if let chain = obj["chain"] as? [Any] { return !chain.isEmpty }
            if let chain = obj["chain"] as? String { return !chain.isEmpty }
        }
        return false
    }

    // MARK: helpers

    private func openDeviceManagement() {
        // The Device Management pane (where the user Allows the profile).
        if let url = URL(string: "x-apple.systempreferences:com.apple.Profiles-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }

    private enum WizardError: LocalizedError {
        case badURL
        case http(Int)
        case notPaired
        var errorDescription: String? {
            switch self {
            case .badURL: return "bad URL"
            case .http(let c): return "HTTP \(c)"
            case .notPaired: return "this Mac isn't paired with co/core yet — finish pairing first"
            }
        }
    }

    /// Turn any thrown error into a friendly, non-fatal sentence + the raw
    /// detail, so a failure shows a clear message and a Skip — never a crash.
    private func friendly(_ error: Error, _ lead: String) -> String {
        "\(lead) \(error.localizedDescription). You can Retry, or Skip this step — Secure Mode is optional."
    }
}
