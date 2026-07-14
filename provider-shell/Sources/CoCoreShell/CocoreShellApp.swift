// CocoreShellApp: AppKit entry for the menu-bar provider shell.
//
// Lifecycle:
//   launch       -> AppDelegate.applicationDidFinishLaunching
//   pair (first) -> kick PairFlow (cocore agent pair), persist session
//   serve        -> AgentSupervisor.start (spawns cocore-provider)
//   quit         -> AgentSupervisor.stop, then NSApp.terminate
//
// We use a plain NSApplication main (not SwiftUI's App + Settings scene).
// On macOS Tahoe, the SwiftUI Settings scene creates infrastructure that
// interferes with NSStatusItem compositing. All UI is AppKit: NSStatusItem
// plus NSHostingController windows.

import AppKit
import ServiceManagement
import SwiftUI

@main
enum CoCoreShellMain {
    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let state = AppState()
    let supervisor = AgentSupervisor()
    let updater = Updater()
    private var menu: MenuBarController?
    private var updateTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Tahoe parks NSStatusItems off-screen when created under `.accessory`
        // or LSUIElement. Launch `.regular`, create the tray icon, then hide
        // the Dock via DockActivation once the item is composited on-screen.
        registerLoginItem()
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        menu = MenuBarController(state: state, supervisor: supervisor, updater: updater)
        Task { await updater.check() }
        updateTimer = Timer.scheduledTimer(withTimeInterval: 6 * 60 * 60, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in await self?.updater.check() }
        }
        Task { @MainActor in
            await state.refreshSession()
            // Defer onboarding so the status item can settle before we open a
            // SwiftUI window (welcome wizard).
            DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) { [weak self] in
                self?.menu?.showWelcomeIfNeeded()
            }
            if state.session != nil, !supervisor.isLaunchAgentManaged {
                await supervisor.start()
            }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows { menu?.showMainWindow() }
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        supervisor.stopSynchronously()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    private func registerLoginItem() {
        // Only the app installed in /Applications may register itself as a login
        // item. Dev builds run from the build directory must NOT, otherwise every
        // local build accumulates its own login item and they all launch at boot,
        // each spawning a competing `agent serve` against the advisor.
        guard Bundle.main.bundlePath.hasPrefix("/Applications/") else {
            NSLog("cocore: skipping login-item registration (not installed in /Applications): %@", Bundle.main.bundlePath)
            return
        }
        do {
            if SMAppService.mainApp.status != .enabled {
                try SMAppService.mainApp.register()
            }
        } catch {
            NSLog("cocore: login-item registration failed: %@", String(describing: error))
        }
    }
}

@MainActor
final class AppState: ObservableObject {
    @Published var session: PersistedSession?
    @Published var trustLevel: TrustLevel = .selfAttested
    /// The advisor's VERIFIED confidential standing for this machine (cdHash
    /// known-good + challenge-verified posture). Distinct from `trustLevel`,
    /// which is the provider record's self-asserted value.
    @Published var confidential: Bool = false
    /// The owner's DURABLE intent to run confidential (the provider record's
    /// `desiredTier`, written by `agent confidential`). Survives restarts, so a
    /// fresh launch can show "Applying…" during the advisor verify window
    /// instead of "Best-effort" — which read as "the setting was forgotten".
    /// This, not `confidential`, drives the toggle's label + action.
    @Published var confidentialDesired: Bool = false
    /// When confidential is DESIRED but not yet VERIFIED, the single most
    /// actionable blocking leg, phrased for the operator (from the advisor's
    /// per-leg breakdown). Nil when verified, off, or the advisor can't be
    /// reached to know.
    @Published var confidentialBlockedReason: String?
    /// The owner's DURABLE intent to run Secure Mode (hardware attestation),
    /// persisted as a local marker (`~/.cocore/secure-mode-desired`). Lets a
    /// fresh launch re-drive / surface "Securing…" until it's attested, rather
    /// than silently dropping back to self-attested. Refreshed from the marker
    /// on each status poll.
    @Published var secureModeDesired: Bool = false
    /// The last time the advisor reported confidential as VERIFIED for this
    /// machine — stamped locally whenever `confidential` is observed true (the
    /// tray polls every 5s). Two uses: show "verified Xm ago", and distinguish a
    /// routine background RE-verification (the periodic APNs code-attestation
    /// refresh — the measured build + enclave-held keys are unchanged) from
    /// genuinely turning on / a lapsed proof. Persisted so a quick relaunch keeps
    /// the signal.
    @Published var confidentialLastVerifiedAt: Date?
    /// How long after the last VERIFIED reading a not-verified poll is still
    /// treated as a routine re-verification ("protected, re-checking") rather
    /// than "Applying…". Matched to the advisor's code-attestation TTL (~11 min)
    /// plus slack, so the window closes only once the proof would truly be stale.
    static let confidentialProofWindow: TimeInterval = 12 * 60
    /// The last time this Mac was reported hardware-attested (Secure Mode).
    /// Same idea as `confidentialLastVerifiedAt`: lets the UI show a routine
    /// background MDA re-attestation as "attested, re-verifying" instead of the
    /// alarming "Securing…". Persisted across relaunch.
    @Published var hardwareAttestedLastAt: Date?
    /// Secure Mode's re-attest window. Generous vs. confidential's: genuine
    /// Apple hardware doesn't change, and the MDA chain refresh is infrequent,
    /// so a recent attestation stays trustworthy across a longer refresh gap.
    static let secureProofWindow: TimeInterval = 45 * 60
    @Published var attestationExpiresAt: Date?
    @Published var creditsLast24h: Int = 0
    @Published var balanceCredits: Int?
    @Published var agentVersion: String?
    @Published var serving: Bool = false
    /// The agent's ATProto publish session is dead (refresh token expired or
    /// revoked) — every record publish is 401ing, so trustLevel/receipts are
    /// silently stuck. The UI surfaces a "Sign in again" prompt and the Secure
    /// Mode wizard refuses to attest until it clears (attesting is pointless
    /// when the result can't be published).
    @Published var needsReauth: Bool = false
    @Published var lastError: String?

    private enum CacheKey {
        static let credits24h = "cachedCredits24h"
        static let balance = "cachedBalanceCredits"
        static let agentVersion = "cachedAgentVersion"
        static let confidentialDesired = "cachedConfidentialDesired"
        static let confidentialLastVerifiedAt = "cachedConfidentialLastVerifiedAt"
        static let hardwareAttestedLastAt = "cachedHardwareAttestedLastAt"
    }

    init() {
        let d = UserDefaults.standard
        if let c = d.object(forKey: CacheKey.credits24h) as? Int { creditsLast24h = c }
        if let b = d.object(forKey: CacheKey.balance) as? Int { balanceCredits = b }
        if let v = d.string(forKey: CacheKey.agentVersion) { agentVersion = v }
        // Show the desired posture instantly on launch (the toggle label +
        // "Applying…" state) without waiting for the first status round-trip,
        // so a relaunch never momentarily reads as "Best-effort / off".
        confidentialDesired = d.bool(forKey: CacheKey.confidentialDesired)
        if let ts = d.object(forKey: CacheKey.confidentialLastVerifiedAt) as? Double {
            confidentialLastVerifiedAt = Date(timeIntervalSince1970: ts)
        }
        if let ts = d.object(forKey: CacheKey.hardwareAttestedLastAt) as? Double {
            hardwareAttestedLastAt = Date(timeIntervalSince1970: ts)
        }
        secureModeDesired = MenuBarController.secureModeDesired()
    }

    /// The honest, three-way confidential posture the UI renders — desired vs.
    /// verified collapsed into one state machine so the view never shows a bare
    /// boolean that looks like the setting was forgotten mid-verify.
    enum ConfidentialPhase: Equatable {
        case off                             // not desired
        case applying(reason: String?)       // desired, never verified yet (or proof lapsed past the window)
        case reverifying(lastVerified: Date) // desired, momentarily unverified but within the proof window — a routine refresh, NOT a lapse
        case active                          // desired and advisor-verified right now
    }
    var confidentialPhase: ConfidentialPhase {
        if confidential { return .active }
        if confidentialDesired {
            // Was verified recently → this is the periodic re-attestation, not a
            // failure. The machine is running the same measured build with the
            // same enclave-held keys; only the advisor's live routing proof is
            // refreshing. Render it calmly so it doesn't read as an insecure blip.
            if let last = confidentialLastVerifiedAt,
               Date().timeIntervalSince(last) < Self.confidentialProofWindow {
                return .reverifying(lastVerified: last)
            }
            return .applying(reason: confidentialBlockedReason)
        }
        return .off
    }

    /// Compact "how long ago" for the last-verified signal. Coarse on purpose —
    /// this is reassurance, not a stopwatch.
    static func agoText(_ date: Date, now: Date = Date()) -> String {
        let secs = max(0, Int(now.timeIntervalSince(date)))
        if secs < 45 { return "just now" }
        let mins = Int((Double(secs) / 60).rounded())
        if mins < 60 { return "\(mins)m ago" }
        return "\(mins / 60)h ago"
    }

    /// The honest Secure Mode posture: attested wins; otherwise desired-but-not
    /// -attested is "Securing…"; otherwise off. The reason distinguishes
    /// "needs you to finish enrollment" from "re-attesting in the background".
    enum SecureModePhase: Equatable {
        case off
        case securing(reason: String)          // desired, not attested — needs enrollment or first attest
        case reattesting(lastAttested: Date)   // was attested recently; MDA chain refreshing — still genuine hardware
        case on
    }
    var secureModePhase: SecureModePhase {
        if trustLevel == .hardwareAttested { return .on }
        if secureModeDesired {
            // Enrolled + attested recently → this is the periodic MDA chain
            // refresh, not a loss of hardware trust. The Mac is still genuine
            // Apple hardware; only the attestation proof is being renewed.
            if EnrollmentProbe.isEnrolled(),
               let last = hardwareAttestedLastAt,
               Date().timeIntervalSince(last) < Self.secureProofWindow {
                return .reattesting(lastAttested: last)
            }
            return .securing(
                reason: EnrollmentProbe.isEnrolled()
                    ? "Re-attesting this Mac in the background…"
                    : "Finish enrollment in System Settings ▸ Device Management to complete Secure Mode.")
        }
        return .off
    }

    func refreshSession() async {
        self.session = SessionStore.load()
    }

    func setError(_ msg: String) {
        self.lastError = msg
    }

    private struct StatusResponse: Decodable {
        let earned24h: Int?
        let balance: Int?
        let trustLevel: String?
        // `confidential` (legacy) == `confidentialVerified`; both carry the
        // advisor's VERIFIED standing. `confidentialDesired` is the owner's
        // durable intent; `confidentialBlockedReason` names the failing leg
        // while desired-but-not-verified. New fields are optional so an older
        // service that only sends `confidential` still decodes.
        let confidential: Bool?
        let confidentialVerified: Bool?
        let confidentialDesired: Bool?
        let confidentialBlockedReason: String?
        let agentVersion: String?
        let needsReauth: Bool?
    }

    func refreshStatus() async {
        // Target session.apiBase — the service that paired us, which both holds
        // our bearer key and serves /api/agent/status. Console-paired agents
        // get the console; device-pair'd agents get the AppView. Using a fixed
        // console URL would send AppView-keyed agents to a service that can't
        // resolve their key (401).
        guard let s = session,
              let apiKey = s.apiKey,
              let base = s.apiBase,
              let url = URL(string: "\(base)/api/agent/status")
        else { return }
        var req = URLRequest(url: url)
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        req.timeoutInterval = 10
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else { return }
            let e = try JSONDecoder().decode(StatusResponse.self, from: data)
            let d = UserDefaults.standard
            if let earned = e.earned24h {
                self.creditsLast24h = earned
                d.set(earned, forKey: CacheKey.credits24h)
            }
            self.balanceCredits = e.balance
            if let bal = e.balance { d.set(bal, forKey: CacheKey.balance) }
            if let raw = e.trustLevel, let t = TrustLevel(rawValue: raw) { self.trustLevel = t }
            if self.trustLevel == .hardwareAttested {
                let now = Date()
                self.hardwareAttestedLastAt = now
                d.set(now.timeIntervalSince1970, forKey: CacheKey.hardwareAttestedLastAt)
            }
            // Prefer the explicit verified field; fall back to the legacy
            // `confidential` so older services still light the badge.
            self.confidential = e.confidentialVerified ?? e.confidential ?? false
            // Stamp the last-verified time whenever we see a verified reading, so
            // the UI can show "verified Xm ago" and treat a subsequent momentary
            // not-verified poll as a routine re-attestation (see confidentialPhase).
            if self.confidential {
                let now = Date()
                self.confidentialLastVerifiedAt = now
                d.set(now.timeIntervalSince1970, forKey: CacheKey.confidentialLastVerifiedAt)
            }
            // Only overwrite desired from the server when it actually reports
            // it (older builds omit it) — otherwise keep the cached intent so a
            // transient old-service response can't wipe the "Applying…" state.
            if let desired = e.confidentialDesired {
                self.confidentialDesired = desired
                d.set(desired, forKey: CacheKey.confidentialDesired)
            }
            self.confidentialBlockedReason = e.confidentialBlockedReason
            // Keep the Secure Mode intent mirror fresh from the local marker.
            self.secureModeDesired = MenuBarController.secureModeDesired()
            self.needsReauth = e.needsReauth ?? false
            if let v = e.agentVersion {
                self.agentVersion = v
                d.set(v, forKey: CacheKey.agentVersion)
            }
        } catch {
            // keep the last good values
        }
    }
}

enum TrustLevel: String { case selfAttested = "self-attested", hardwareAttested = "hardware-attested" }

func creditsDisplay(_ n: Int) -> String {
    let fmt = NumberFormatter()
    fmt.numberStyle = .decimal
    let num = fmt.string(from: NSNumber(value: n)) ?? "\(n)"
    return "\(num) credit\(n == 1 ? "" : "s")"
}
