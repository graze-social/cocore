// CocoreShellApp: SwiftUI app entry. We don't want a dock icon, so
// the actual UI is a status-bar-only menu (see MenuBarController).
// SwiftUI is used for the preferences window only.
//
// Lifecycle:
//   launch       -> AppDelegate.applicationDidFinishLaunching
//   pair (first) -> kick PairFlow (cocore agent pair), persist session
//   serve        -> AgentSupervisor.start (spawns cocore-provider)
//   quit         -> AgentSupervisor.stop, then NSApp.terminate

import AppKit
import ServiceManagement
import SwiftUI

@main
struct CocoreShellApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        // Settings scene is the only proper SwiftUI window; the menu
        // bar is an NSStatusItem managed by MenuBarController so that
        // we keep the activation policy at .accessory (no dock icon).
        Settings {
            PreferencesView(supervisor: appDelegate.supervisor)
                .environmentObject(appDelegate.state)
        }
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
        NSApp.setActivationPolicy(.accessory)
        registerLoginItem()
        menu = MenuBarController(state: state, supervisor: supervisor, updater: updater)
        // Auto-update: check on launch, then every 6 hours (a few times a
        // day) so a published release reaches users without a manual check.
        // A below-minSupported version auto-applies (the forced path);
        // otherwise it surfaces in the menu and pulses the icon yellow (see
        // MenuBarController.needsAttention).
        Task { await updater.check() }
        updateTimer = Timer.scheduledTimer(withTimeInterval: 6 * 60 * 60, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in await self?.updater.check() }
        }
        // Safety net for a stranded status item: macOS occasionally creates
        // the NSStatusItem but never assigns it a visible menu-bar slot, which
        // leaves this menu-bar-only app with no way in (the tray menu is the
        // sole entry point). Placement is async, so give the bar a moment to
        // settle before judging; if we still never landed, open the main window
        // (which promotes to .regular) so the app is reachable via Dock/Cmd-Tab.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            guard let self, let menu = self.menu, !menu.statusItemPlaced else { return }
            NSLog("cocore: status item not placed on menu bar; opening main window as fallback")
            menu.showMainWindow()
        }
        Task { @MainActor in
            await state.refreshSession()
            // First-run onboarding: walk a not-yet-paired user through
            // sign in → choose a model → start serving.
            menu?.showWelcomeIfNeeded()
            // Auto-start serving in the SELF-CONTAINED app case only: signed
            // in AND no `dev.cocore.provider` LaunchAgent present (a
            // download-only install where the app supervises the bundled
            // agent itself). When the LaunchAgent exists (headless/curl
            // install) launchd already runs the agent — don't double-run.
            if state.session != nil, !supervisor.isLaunchAgentManaged {
                await supervisor.start()
            }
        }
    }

    /// Re-launching the app (double-clicking it in Finder while it's already
    /// running, or clicking a Dock icon) routes here. As a menu-bar-only app
    /// the default is a silent no-op — which reads as "it won't launch" when
    /// the tray icon is missing. Surface the main window instead so there's
    /// always a way in.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows { menu?.showMainWindow() }
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Synchronous: a detached `Task { await supervisor.stop() }` loses
        // the race with app exit and leaves the agent child orphaned
        // (reparented to launchd), which is how two agents end up
        // registered for one DID. Reap it inline before we go.
        supervisor.stopSynchronously()
    }

    /// This is a menu-bar app: closing its last window (Welcome, Models,
    /// Preferences) must NOT quit it — the status item, the supervised
    /// agent, and the auto-update timer all have to keep running. Critical
    /// now that WindowActivation flips us to `.regular` while a window is
    /// open, since `.regular` apps otherwise terminate on last-window-close.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    /// Register the menu-bar app to launch at login so the tray icon
    /// survives a reboot. Idempotent; best-effort (ad-hoc-signed dev
    /// builds may not persist, which is fine — the notarized release
    /// will). Users can still toggle it in System Settings › Login Items.
    private func registerLoginItem() {
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
    @Published var attestationExpiresAt: Date?
    // cocore is a closed-loop credit system — there is no USD payout.
    // Earnings are denominated in credits.
    @Published var creditsLast24h: Int = 0
    @Published var balanceCredits: Int?
    @Published var agentVersion: String?
    @Published var serving: Bool = false
    @Published var lastError: String?

    private enum CacheKey {
        static let credits24h = "cachedCredits24h"
        static let balance = "cachedBalanceCredits"
        static let agentVersion = "cachedAgentVersion"
    }

    init() {
        // Seed from the last successful /api/agent/status so a relaunch
        // shows the last-known earnings/balance immediately instead of a
        // misleading 0 until the first poll returns (~seconds on a cold
        // network). The live refresh overwrites these.
        let d = UserDefaults.standard
        if let c = d.object(forKey: CacheKey.credits24h) as? Int { creditsLast24h = c }
        if let b = d.object(forKey: CacheKey.balance) as? Int { balanceCredits = b }
        if let v = d.string(forKey: CacheKey.agentVersion) { agentVersion = v }
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
        let agentVersion: String?
    }

    /// Pull live status (earnings, balance, real trust level, agent
    /// version) from the console's bearer-authed /api/agent/status using
    /// the paired session's apiKey + apiBase. Transient failures leave
    /// the previous values untouched (so a brief network blip doesn't
    /// flash the count back to 0).
    func refreshStatus() async {
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

/// Format a credit balance for display, e.g. `1 credit` / `1,234 credits`.
func creditsDisplay(_ n: Int) -> String {
    let fmt = NumberFormatter()
    fmt.numberStyle = .decimal
    let num = fmt.string(from: NSNumber(value: n)) ?? "\(n)"
    return "\(num) credit\(n == 1 ? "" : "s")"
}
