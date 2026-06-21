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
    private let supervisor: AgentSupervisor
    private let updater: Updater
    private let modelManager: ModelManager

    init(state: AppState, supervisor: AgentSupervisor, updater: Updater, modelManager: ModelManager) {
        self.state = state
        self.supervisor = supervisor
        self.updater = updater
        self.modelManager = modelManager
    }

    func show() {
        if window == nil {
            let view = SecureModeWizardView(
                state: state,
                supervisor: supervisor,
                updater: updater,
                modelManager: modelManager,
                close: { [weak self] in self?.window?.close() }
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

// MARK: - wizard view

struct SecureModeWizardView: View {
    @ObservedObject var state: AppState
    let supervisor: AgentSupervisor
    @ObservedObject var updater: Updater
    @ObservedObject var modelManager: ModelManager
    let close: () -> Void

    /// The wizard's explicit state machine. Every step is reachable, and
    /// every step is skippable (→ Secure Mode stays best-effort).
    enum Step: Int {
        case intro, updating, enroll, attesting, models, done
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

    // Models step state (WS-D recommended set + WS-E meter).
    @State private var recommended: [ModelManager.CatalogEntry] =
        ModelManager.recommendedCatalog
    @State private var schedules: [String: ModelManager.Window] = [:]
    @State private var pinning = false

    /// Active poll task, cancelled when the user skips/closes a step.
    @State private var pollTask: Task<Void, Never>?

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
        .onDisappear { pollTask?.cancel() }
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
        case .models: modelsStep
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

    private var modelsStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pin the recommended models")
                .font(.title3).bold().foregroundStyle(Brand.accentText)
            Text(
                "Now that this Mac is attested, pin the latest-&-greatest models so it serves "
                    + "the best mix it can run."
            )
            .fixedSize(horizontal: false, vertical: true)

            // WS-E meter, computed over the recommended set we'd pin.
            secureBudgetMeter

            // The recommended set (WS-D), each marked fits/too-big.
            VStack(alignment: .leading, spacing: 6) {
                ForEach(recommended, id: \.nsid) { item in
                    let fits = ModelManager.fitsDevice(item.minRamGB)
                    HStack(spacing: 8) {
                        Image(systemName: fits ? "checkmark.circle.fill" : "exclamationmark.triangle")
                            .foregroundStyle(fits ? AnyShapeStyle(Brand.success) : AnyShapeStyle(.orange))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(item.label).font(.caption).fontWeight(.medium)
                            Text(
                                fits
                                    ? "needs ~\(item.minRamGB)GB · fits this Mac"
                                    : "needs ~\(item.minRamGB)GB — more than this Mac"
                            )
                            .font(.caption2).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    .opacity(fits ? 1 : 0.6)
                }
            }

            HStack(spacing: 10) {
                Button(pinning ? "Pinning…" : "Pin recommended (latest & greatest)") {
                    pinRecommended()
                }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(pinning)
                Button("Keep my current selection") { advance(to: .done) }
            }
        }
        .task {
            // Refresh the recommended set live (WS-D), falling back to mirror.
            recommended = await ModelManager.fetchRecommended()
            schedules = ModelManager.loadSchedules()
        }
    }

    /// The WS-E meter, computed over the recommended set this step would pin
    /// (so the owner sees the budget BEFORE committing).
    @ViewBuilder private var secureBudgetMeter: some View {
        if ModelManager.deviceRamGB > 0 {
            let fitting = recommended.filter { ModelManager.fitsDevice($0.minRamGB) }.map { $0.nsid }
            let report = ModelManager.budgetReport(models: fitting, schedules: schedules)
            let (color, title): (Color, String) = {
                switch report.status {
                case .comfortable: return (Brand.success, "Comfortable")
                case .tight: return (.orange, "Tight")
                case .oversubscribed: return (.red, "Oversubscribed")
                }
            }()
            VStack(alignment: .leading, spacing: 6) {
                GeometryReader { geo in
                    let w = geo.size.width
                    let denom = CGFloat(max(report.totalGB, max(report.usedGB, 1)))
                    let usedW = min(w, w * CGFloat(report.usedGB) / denom)
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 5).fill(Color.secondary.opacity(0.18))
                        RoundedRectangle(cornerRadius: 5).fill(color.opacity(0.85))
                            .frame(width: max(0, usedW))
                    }
                }
                .frame(height: 12)
                Text(
                    "Pinned \(report.usedGB) GB · Reserved for you \(report.reserveGB) GB · This Mac \(report.totalGB) GB"
                )
                .font(.caption2).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Circle().fill(color).frame(width: 8, height: 8)
                    Text(title).font(.caption.weight(.semibold)).foregroundStyle(color)
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
        working = true
        progress = "Requesting a hardware attestation…"
        Task {
            do {
                try await pushAttestation()
                progress = "Building the attestation chain…"
                pollForAttestationChain()
            } catch {
                working = false
                stepError = friendly(error, "We couldn't start hardware attestation.")
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
        let (_, resp) = try await URLSession.shared.data(for: req)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            throw WizardError.http((resp as? HTTPURLResponse)?.statusCode ?? 0)
        }
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
            while !Task.isCancelled, Date() < deadline {
                var req = URLRequest(url: url)
                req.setValue("Bearer \(auth.apiKey)", forHTTPHeaderField: "Authorization")
                req.timeoutInterval = 15
                if let (data, resp) = try? await URLSession.shared.data(for: req),
                    (resp as? HTTPURLResponse)?.statusCode == 200,
                    hasChain(data) {
                    working = false
                    progress = nil
                    advance(to: .models)
                    return
                }
                try? await Task.sleep(nanoseconds: 4_000_000_000)
            }
            if !Task.isCancelled {
                working = false
                stepError =
                    "The attestation chain isn't ready yet. Click Retry, or Skip this step "
                    + "and revisit Secure Mode later."
            }
        }
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

    // MARK: step 5 — models

    private func pinRecommended() {
        pinning = true
        Task {
            // Pin the recommended models that fit this Mac, via the existing
            // model-set path (which bounces the agent). We use the manager's
            // add() so it goes through the same CLI/UserDefaults logic the
            // Models window uses.
            let fitting = recommended.filter { ModelManager.fitsDevice($0.minRamGB) }
            for item in fitting where !modelManager.models.contains(item.nsid) {
                await modelManager.add(item.nsid)
            }
            // Bounce the agent so it re-reads the new set.
            await supervisor.stop()
            await supervisor.start()
            pinning = false
            advance(to: .done)
        }
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
