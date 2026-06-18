// Status-bar menu for the provider shell: ATProto OAuth via
// PairFlow, supervisor lifecycle, and a "verify on AppView" link
// that opens the user's receipts.

import AppKit
import Combine

@MainActor
final class MenuBarController {
    private let item: NSStatusItem
    private let state: AppState
    private let supervisor: AgentSupervisor
    private let updater: Updater
    private var bag = Set<AnyCancellable>()
    private var pollTimer: Timer?
    private var earningsTimer: Timer?
    private var heartbeatTimer: Timer?
    private var heartbeatPhase = false
    private enum IconState { case plain, serving, alert, attention, paused }
    private var iconState: IconState = .plain
    /// Mirrors the bad-standing marker; drives the menu's "needs attention"
    /// row. Only flips (and rebuilds the menu) on a real transition.
    private var badStanding = false
    /// The reason line from the bad-standing marker, if any — the agent
    /// writes a short code (e.g. "preflight-no-response") when first flagged
    /// and a fuller remediation sentence when an auto-recovery attempt
    /// couldn't bring the engine back. Surfaced under the alert row so the
    /// operator knows what to do. Tracked so the menu rebuilds when the
    /// reason changes even while bad standing stays on.
    private var badStandingReason: String?
    /// Mirrors the remote-stop marker; drives the menu's "stopped from the
    /// console" row. Only flips (and rebuilds) on a real transition.
    private var remotelyPausedShown = false
    /// True when WE stopped the agent because the owner's `active` switch
    /// read paused. Gates the reconciler's auto-restart so we only resurrect
    /// an agent we paused (never fight the schedule / a crash-restart).
    private var pausedByOwner = false
    /// Non-zero once the supervisor reports the agent is crash-looping.
    /// Drives a loud "keeps crashing — send a report" menu row so a flapping
    /// machine doesn't just silently respawn behind a flat ledger.
    private var crashLoopCount = 0

    /// Show the green heartbeat for this long after the agent's most
    /// recent served response (it touches `~/.cocore/last-served-at`).
    private static let heartbeatWindow: TimeInterval = 15

    init(state: AppState, supervisor: AgentSupervisor, updater: Updater) {
        self.state = state
        self.supervisor = supervisor
        self.updater = updater
        self.item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.image = MenuBarController.brandImage()
        item.button?.toolTip = "cocore"
        refreshServing()
        rebuildMenu()

        // Apply any Pause done on the website while the app was closed.
        Task { @MainActor in await self.reconcileServeSwitch() }

        // Reflect reality without a click: re-read the session (so a pair
        // done outside the app — `cocore agent pair`, or the installer —
        // advances the menu from "Sign in" to the signed-in state) and the
        // LaunchAgent's serving state, every 5s. On the nil→signed-in
        // transition, immediately pull live status.
        pollTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                let wasSignedIn = self.state.session != nil
                await self.state.refreshSession()
                self.refreshServing()
                if !wasSignedIn, self.state.session != nil {
                    await self.state.refreshStatus()
                }
            }
        }

        // Live earnings/balance: fetch once now, then every 30s.
        Task { await state.refreshStatus() }
        earningsTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.state.refreshStatus()
                // Apply a Pause / Resume done on the website to the local
                // agent process (stop / start), keeping both sides in sync.
                await self?.reconcileServeSwitch()
            }
        }

        // React to state changes by rebuilding the menu (cheap; ~10
        // items). For per-frame stuff this would be wasteful, but
        // status-menu reconstruction is the idiomatic AppKit pattern.
        state.$session.sink { [weak self] _ in self?.rebuildMenu() }.store(in: &bag)
        state.$serving.sink { [weak self] _ in self?.rebuildMenu() }.store(in: &bag)
        // The menu still shows the 24h-earnings glance line, so keep that
        // sink; balance/attestation moved to the Status window (a SwiftUI
        // view bound to AppState — it updates itself, no rebuild needed).
        state.$creditsLast24h.sink { [weak self] _ in self?.rebuildMenu() }.store(in: &bag)
        updater.$status.sink { [weak self] _ in self?.rebuildMenu() }.store(in: &bag)
        updater.$notice.sink { [weak self] _ in self?.rebuildMenu() }.store(in: &bag)

        // Surface a sustained agent crash loop in the menu (and stop the
        // silent respawn-behind-a-flat-ledger failure mode).
        supervisor.onCrashLoop = { [weak self] count in
            self?.crashLoopCount = count
            self?.rebuildMenu()
        }

        startHeartbeatTimer()
    }

    private func rebuildMenu() {
        let menu = NSMenu()
        if let s = state.session {
            menu.addItem(disabled("Signed in as \(s.handle)"))
        } else {
            menu.addItem(disabled("Welcome to cocore"))
            menu.addItem(disabled("Step 1: sign in to turn this Mac into a provider."))
            menu.addItem(.separator())
            menu.addItem(action(title: "Sign in with ATProto…", #selector(signIn)))
            menu.addItem(.separator())
            menu.addItem(action(title: "Quit", #selector(quit)))
            item.menu = menu
            return
        }
        // Schedule-aware display: a scheduled-idle agent is "running" to
        // launchd but disconnected, and a console/tray pause stops the
        // process; treat both as not-serving for the indicator + toggle.
        let sched = Self.scheduleState()
        let scheduledIdle = sched.limited && !sched.within
        // The owner stopped this machine from the console (the agent wrote
        // the marker and disconnected). `state.serving` only tracks the
        // PROCESS, so it stays true — this is what makes a remote stop
        // visible locally instead of still reading "Serving".
        let remotelyPaused = Self.isRemotelyPaused()
        // While the agent is still downloading/loading a model the PROCESS is
        // alive (state.serving == true), but it isn't actually serving yet.
        // The provisioning marker is the truth here — show it instead of
        // "serving and earning" so the app doesn't claim earnings prematurely.
        let provision = Self.provisionStatus()
        let provisioning = provision?.phase == "provisioning"
        let effectiveServing =
            state.serving && !scheduledIdle && !remotelyPaused && !provisioning

        menu.addItem(.separator())
        // At-a-glance state + the one metric worth a glance. Everything
        // else — identity detail, models, preferences, profile, bug report,
        // sign out, uninstall, version — moved into the "Open cocore…"
        // window so the menu stays short.
        let atAGlance: String
        if remotelyPaused {
            atAGlance = "⏸ Stopped from the console"
        } else if provisioning {
            let bytes = provision?.bytesDownloaded ?? 0
            atAGlance =
                bytes > 0
                ? "⏳ Provisioning… downloading model (\(Self.provisionMB(bytes)))"
                : "⏳ Provisioning a model… (not earning yet)"
        } else if provision?.phase == "failed" {
            atAGlance = "⚠ Provisioning failed — not serving"
        } else if scheduledIdle {
            atAGlance = "✓ Set up — idle until \(PreferencesView.hourLabel(sched.start)) (scheduled)"
        } else if effectiveServing {
            atAGlance = "✓ You're set up — serving and earning credits"
        } else {
            atAGlance = "Next: choose “Start serving” below to begin earning"
        }
        menu.addItem(disabled(atAGlance))
        menu.addItem(disabled("Earnings (24h): \(creditsDisplay(state.creditsLast24h))"))

        menu.addItem(.separator())
        if provision?.phase == "failed", let msg = provision?.faultMessage {
            // Provisioning failed (e.g. a model download that gave up, or a
            // non-MLX repo). Surface it with the agent's content-safe reason +
            // a one-click restart, instead of leaving the operator guessing.
            menu.addItem(disabled("⚠ Couldn't start serving"))
            menu.addItem(disabled(String(msg.prefix(180))))
            menu.addItem(action(title: "Restart serving", #selector(restartServing)))
            menu.addItem(.separator())
        }
        if badStanding {
            // The advisor stopped routing jobs here. Surface it loudly with
            // a one-click restart, plus the specific reason / remediation the
            // agent reported (so "what do I do" is answerable from the menu).
            menu.addItem(disabled("⚠ Not receiving jobs — this machine stopped responding"))
            if let detail = Self.friendlyBadStandingDetail(badStandingReason) {
                menu.addItem(disabled(detail))
            }
            menu.addItem(action(title: "Restart serving", #selector(restartServing)))
            menu.addItem(.separator())
        }
        if crashLoopCount > 0 {
            // The agent keeps exiting. Say so plainly and offer the one-click
            // report inline rather than letting it respawn silently.
            menu.addItem(disabled("⚠ The agent keeps crashing (\(crashLoopCount)×)"))
            menu.addItem(action(title: "Send bug report…", #selector(sendBugReport)))
            menu.addItem(.separator())
        }
        if remotelyPaused {
            menu.addItem(disabled("○ Paused"))
            menu.addItem(action(title: "Resume serving", #selector(startServing)))
        } else if scheduledIdle {
            menu.addItem(disabled("○ Idle — serves \(PreferencesView.hourLabel(sched.start))–\(PreferencesView.hourLabel(sched.end))"))
        } else {
            menu.addItem(disabled(effectiveServing ? "● Serving" : "○ Not serving"))
            if effectiveServing {
                menu.addItem(action(title: "Pause serving", #selector(stopServing)))
            } else {
                menu.addItem(action(title: "Start serving", #selector(startServing)))
            }
        }
        // Update status: a pending update surfaces its one-click action; when
        // up to date, a routine "Check for updates…" (also in the Help tab).
        addUpdateItems(to: menu)
        menu.addItem(.separator())
        menu.addItem(action(title: "Open cocore…", #selector(openMainWindow)))
        if let err = state.lastError {
            menu.addItem(disabled("⚠ \(err)"))
        }
        menu.addItem(action(title: "Quit cocore", #selector(quit)))
        item.menu = menu
    }

    /// The cocore "receipt notch" mark, rendered as a menu-bar template
    /// image. Geometry is transcribed verbatim from the brand favicon
    /// (packages/console/public/favicon.svg): an outer square with its
    /// bottom-right corner sheared off, minus an inner notched square via
    /// the even-odd winding rule. We draw it with NSBezierPath rather than
    /// shipping a raster so it stays crisp at any backing scale, and mark
    /// it `isTemplate` so AppKit tints it for light/dark menu bars.
    /// `dot`, when set, overlays a small colored status dot (green = just
    /// served, red = bad standing) and renders the glyph as a non-template
    /// image so the color survives AppKit tinting. `pulse` (0…1) scales the
    /// dot for a gentle beat. `dot == nil` is the plain template glyph.
    static func brandImage(
        pointSize: CGFloat = 18, dot: NSColor? = nil, pulse: CGFloat = 1.0, cut: Bool = false
    ) -> NSImage {
        let hasDot = dot != nil
        let image = NSImage(size: NSSize(width: pointSize, height: pointSize), flipped: false) { _ in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }

            // Glyph, drawn in the favicon's 0..100 viewBox. Save/restore so
            // the heartbeat dot below draws in screen-point space, not the
            // scaled+flipped viewBox space.
            ctx.saveGState()
            let glyph = pointSize - 2          // 1pt of breathing room each side
            let scale = glyph / 100.0          // favicon viewBox is 0..100
            let offset = (pointSize - glyph) / 2.0
            // SVG is top-left origin (y down); AppKit (flipped:false) is
            // bottom-left (y up). Flip y and scale the viewBox into the
            // padded glyph box.
            ctx.translateBy(x: offset, y: pointSize - offset)
            ctx.scaleBy(x: scale, y: -scale)

            let path = NSBezierPath()
            path.windingRule = .evenOdd
            // Outer notched square: M0 0 H100 V70 L70 100 H0 Z
            path.move(to: NSPoint(x: 0, y: 0))
            path.line(to: NSPoint(x: 100, y: 0))
            path.line(to: NSPoint(x: 100, y: 70))
            path.line(to: NSPoint(x: 70, y: 100))
            path.line(to: NSPoint(x: 0, y: 100))
            path.close()
            // Inner cutout (subtracted): M22 22 V78 H55.6 L78 55.6 V22 Z
            path.move(to: NSPoint(x: 22, y: 22))
            path.line(to: NSPoint(x: 22, y: 78))
            path.line(to: NSPoint(x: 55.6, y: 78))
            path.line(to: NSPoint(x: 78, y: 55.6))
            path.line(to: NSPoint(x: 78, y: 22))
            path.close()

            // Template mode lets AppKit tint the glyph for light/dark; with
            // a status dot we bake a non-template image, so fill with
            // labelColor (the menu bar's text color for the current
            // appearance) to mimic the template look.
            (hasDot ? NSColor.labelColor : NSColor.black).setFill()
            path.fill()
            ctx.restoreGState()

            // Paused: carve a diagonal gap straight through the glyph — the
            // icon reads as "cut"/stopped. `.clear` zeroes the alpha along
            // the stroke, so the break survives both the baked-color path
            // (status dots) and AppKit's template tinting (the mask is the
            // alpha channel either way).
            if cut {
                ctx.saveGState()
                ctx.setBlendMode(.clear)
                ctx.setLineCap(.round)
                ctx.setLineWidth(max(1.5, pointSize * 0.16))
                ctx.move(to: CGPoint(x: pointSize * 0.14, y: pointSize * 0.14))
                ctx.addLine(to: CGPoint(x: pointSize * 0.86, y: pointSize * 0.86))
                ctx.strokePath()
                ctx.restoreGState()
            }

            if let dotColor = dot {
                let r = 3.0 * pulse
                let cx = pointSize - r - 0.5
                let cy = pointSize - r - 0.5
                let glyphDot = NSBezierPath(ovalIn: NSRect(x: cx - r, y: cy - r, width: r * 2, height: r * 2))
                dotColor.setFill()
                glyphDot.fill()
            }
            return true
        }
        image.isTemplate = !hasDot
        image.accessibilityDescription = hasDot ? "cocore — status" : "cocore"
        return image
    }

    private func disabled(_ s: String) -> NSMenuItem {
        let it = NSMenuItem(title: s, action: nil, keyEquivalent: "")
        it.isEnabled = false
        return it
    }

    private func action(title: String, _ sel: Selector) -> NSMenuItem {
        let it = NSMenuItem(title: title, action: sel, keyEquivalent: "")
        it.target = self
        return it
    }

    @objc private func signIn() {
        // Route the menu's "Sign in" through the wizard rather than running
        // the pair flow headlessly: the wizard shows the approval URL + code
        // inline (and walks the rest of setup), so the user can't get stuck
        // on a browser tab that opened behind a window.
        welcomeWindow.show()
    }

    @objc private func signOut() {
        Task {
            await supervisor.stop()
            SessionStore.clear()
            await state.refreshSession()
        }
    }

    // Pause / Resume drive ONE shared switch (`active` on this machine's
    // provider record) so the site and the tray never disagree: the CLI
    // write flips the switch the console reads, and we stop/start the agent
    // process locally for the immediate effect. The reconciler below applies
    // the same stop/start when the switch is flipped from the website.
    @objc private func startServing() {
        Task {
            // Flip the shared switch FIRST and only touch the local process
            // once it actually landed. If the CLI write fails we leave the
            // marker / latch untouched and tell the user, rather than starting
            // a process the console still believes is paused (the resume mirror
            // of the stuck-pause bug below).
            let (status, out) = await ModelManager.run(["agent", "resume"])
            guard status == 0 else {
                NSLog("cocore: resume failed (status %d): %@", status, out)
                presentServeSwitchError(action: "resume", detail: out)
                return
            }
            Self.setOwnerPaused(false)
            pausedByOwner = false
            await supervisor.start()
            refreshServing()
            rebuildMenu()
        }
    }
    @objc private func stopServing() {
        Task {
            // The `active` switch is the source of truth the 30s reconciler
            // reads. If this write fails (CAS race with the still-serving
            // agent, network blip, unpaired) the switch stays "serving" — so
            // we must NOT stop the process and arm `pausedByOwner`, or the
            // reconciler reads "serving" + latch-set and turns the agent right
            // back on. Only proceed when the pause actually landed.
            let (status, out) = await ModelManager.run(["agent", "pause"])
            guard status == 0 else {
                NSLog("cocore: pause failed (status %d): %@", status, out)
                presentServeSwitchError(action: "pause", detail: out)
                return
            }
            await supervisor.stop()
            Self.setOwnerPaused(true)
            pausedByOwner = true
            refreshServing()
            rebuildMenu()
        }
    }

    /// Surface a failed Pause / Resume switch write so the user knows the
    /// menu state didn't change (and can retry) instead of silently desyncing
    /// from what the console believes about this machine.
    @MainActor
    private func presentServeSwitchError(action: String, detail: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Couldn’t \(action) serving"
        let trimmed = detail.trimmingCharacters(in: .whitespacesAndNewlines)
        alert.informativeText = trimmed.isEmpty
            ? "The change didn’t go through — check your connection and try again."
            : "The change didn’t go through — check your connection and try again.\n\n\(trimmed)"
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    /// Reconcile the agent PROCESS to the owner's shared `active` switch,
    /// whichever side changed it. Polled (every status refresh) so a Pause /
    /// Resume done on the website stops / starts the agent here too — the
    /// "pause fully stops the process" behaviour, driven remotely.
    ///
    /// `pausedByOwner` gates the auto-START: we only resurrect an agent WE
    /// paused, so we never fight the schedule window, a crash-restart, or a
    /// user who stopped serving some other way.
    private func reconcileServeSwitch() async {
        let (status, out) = await ModelManager.run(["agent", "active"])
        guard status == 0 else { return } // network blip / not paired — leave as-is
        let paused = out.contains("paused")
        guard paused || out.contains("serving") else { return }
        if paused {
            if supervisor.isServing() { await supervisor.stop() }
            Self.setOwnerPaused(true)
            pausedByOwner = true
        } else {
            Self.setOwnerPaused(false)
            if pausedByOwner {
                if !supervisor.isServing() { await supervisor.start() }
                pausedByOwner = false
            }
        }
        refreshServing()
        rebuildMenu()
    }

    /// Write / clear the `~/.cocore/serving-paused` marker the menu reads to
    /// render the paused state. The agent writes the same file when it's
    /// headless (no app); here the app owns it because it stops the process.
    static func setOwnerPaused(_ paused: Bool) {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".cocore/serving-paused")
        if paused {
            try? FileManager.default.createDirectory(
                at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? Data().write(to: path)
        } else {
            try? FileManager.default.removeItem(at: path)
        }
    }

    /// Bounce the agent after the advisor flagged this machine unresponsive.
    /// A clean re-register clears the bad-standing marker (the agent does
    /// this on connect), so the red ping + this row drop away once it
    /// reconnects healthily.
    @objc private func restartServing() {
        Task {
            await supervisor.stop()
            await supervisor.start()
            refreshServing()
        }
    }

    private func refreshServing() {
        state.serving = supervisor.isServing()
    }

    @objc private func openProfile() {
        guard let handle = state.session?.handle else { return }
        let console = UserDefaults.standard.string(forKey: "consoleBaseUrl")
            ?? "https://console.cocore.dev"
        guard let url = URL(string: "\(console)/u/\(handle)") else { return }
        NSWorkspace.shared.open(url)
    }

    /// Model-list state for the Models tab (one shared instance).
    private lazy var modelManager = ModelManager(supervisor: supervisor)

    /// The single window the tray's "Open cocore…" opens — Status / Models /
    /// Preferences / Help as tabs. Action closures route back to the methods
    /// here (which own the NSAlert flows + supervisor lifecycle).
    private lazy var mainWindow: MainWindowController = {
        let view = MainTabView(
            state: state,
            supervisor: supervisor,
            updater: updater,
            modelManager: modelManager,
            onOpenProfile: { [weak self] in self?.openProfile() },
            onOpenSetupGuide: { [weak self] in self?.openWelcome() },
            onSignOut: { [weak self] in self?.signOut() },
            onSendBugReport: { [weak self] in self?.sendBugReport() },
            onCheckUpdates: { [weak self] in self?.checkUpdates() },
            onInstallUpdate: { [weak self] in self?.installUpdate() },
            onUninstall: { [weak self] in self?.confirmUninstall() }
        )
        return MainWindowController(rootView: view)
    }()
    @objc private func openMainWindow() { mainWindow.show() }

    private lazy var welcomeWindow: WelcomeWindowController = {
        let c = WelcomeWindowController(state: state, supervisor: supervisor)
        c.onOpenModels = { [weak self] in self?.mainWindow.show() }
        return c
    }()
    @objc private func openWelcome() { welcomeWindow.show() }

    /// Auto-show the welcome wizard on launch whenever setup isn't
    /// finished — not signed in, no model chosen, runtime missing, or not
    /// yet serving — unless the user has explicitly dismissed it with
    /// "Done"/"Do this later". Previously this only fired when signed out,
    /// so a user who signed in but stopped before choosing a model never
    /// got walked through the rest.
    func showWelcomeIfNeeded() {
        if UserDefaults.standard.bool(forKey: "onboardingSeen") { return }
        let signedIn = state.session != nil
        let hasModels = !ModelManager.storedModels().isEmpty
        let runtimeReady = VenvBootstrapper.isInstalled
        let serving = supervisor.isServing()
        if !(signedIn && hasModels && runtimeReady && serving) {
            welcomeWindow.show()
        }
    }

    @objc private func confirmUninstall() {
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Uninstall cocore?"
        alert.informativeText = """
        This deregisters this machine (removes its provider record from \
        your PDS) and removes the cocore agent, its LaunchAgent, the \
        ~/.cocore state, the Python runtime, and this app.

        Your identity-level records (past receipts, API keys, console \
        account) are not touched. This cannot be undone.
        """
        alert.addButton(withTitle: "Uninstall")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        Task {
            await supervisor.stop()
            let console = UserDefaults.standard.string(forKey: "consoleBaseUrl")
                ?? "https://console.cocore.dev"
            await Uninstaller.run(console: console)
            // Move our own .app to the Trash (the hosted uninstaller wipes
            // the agent, not the GUI bundle), then quit.
            Uninstaller.trashSelf()
            NSApp.terminate(nil)
        }
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }

    /// Generate a content-safe diagnostic bundle and upload it to the
    /// console, then tell the user the ticket id (or, if upload failed, the
    /// local path they can attach by hand). The bundle carries crash +
    /// health telemetry only — no prompts, no API key, no signing key.
    @objc private func sendBugReport() {
        Task { @MainActor in
            // Once consumed by a report, the crash-loop nag has served its
            // purpose — clear it so the menu returns to normal.
            crashLoopCount = 0
            rebuildMenu()
            let result = await supervisor.sendBugReport()
            let alert = NSAlert()
            if let result, !result.hasPrefix("file://") {
                alert.messageText = "Bug report sent"
                alert.informativeText = """
                Thanks — your diagnostic bundle was uploaded.
                Reference: \(result)

                It contains crash and health telemetry only (no prompts, \
                no API key, no signing key).
                """
            } else if let result {
                alert.alertStyle = .warning
                alert.messageText = "Couldn't upload — bundle saved locally"
                alert.informativeText = """
                We couldn't reach the console, so the diagnostic bundle was \
                saved here instead:

                \(result.replacingOccurrences(of: "file://", with: ""))

                You can attach it to a GitHub issue or DM it to @cocore.dev.
                """
            } else {
                alert.alertStyle = .warning
                alert.messageText = "Couldn't create a bug report"
                alert.informativeText = "The cocore agent binary wasn't found. Try reinstalling."
            }
            alert.addButton(withTitle: "OK")
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
    }

    /// Update status + (when present) the deprecation notice from the
    /// console's /agent/policy. `required` auto-applies via the Updater;
    /// `available` offers a one-click install.
    private func addUpdateItems(to menu: NSMenu) {
        if let n = updater.notice, !n.isEmpty {
            menu.addItem(disabled("ⓘ \(n)"))
        }
        switch updater.status {
        case .available(let v):
            menu.addItem(action(title: "Update to \(v)…", #selector(installUpdate)))
        case .required(let v):
            menu.addItem(disabled("⚠ Update required (\(v)) — installing…"))
        case .updating(let v):
            menu.addItem(disabled("Updating to \(v)…"))
        case .failed(let m):
            menu.addItem(disabled("⚠ \(m)"))
            menu.addItem(action(title: "Retry update", #selector(installUpdate)))
        case .upToDate:
            // No pending update — offer a routine on-demand check right here
            // on the first page (it also lives in the window's Help tab).
            menu.addItem(action(title: "Check for updates…", #selector(checkUpdates)))
        }
    }

    @objc private func checkUpdates() { Task { await updater.check(autoApplyRequired: false) } }
    @objc private func installUpdate() { Task { await updater.apply() } }

    /// The app's serve-window prefs + whether the current local hour is
    /// inside the window. Mirrors PreferencesView's storage + the agent's
    /// ServeWindow.contains (exclusive end, midnight wrap).
    static func scheduleState() -> (limited: Bool, within: Bool, start: Int, end: Int) {
        let d = UserDefaults.standard
        let limited = d.bool(forKey: "scheduleLimited")
        let start = d.object(forKey: "idleStart") as? Int ?? 22
        let end = d.object(forKey: "idleEnd") as? Int ?? 8
        let h = Calendar.current.component(.hour, from: Date())
        let within = start < end ? (h >= start && h < end) : (h >= start || h < end)
        return (limited, within, start, end)
    }

    // MARK: - Serving heartbeat

    /// Poll once a second for a recent served-response marker and flash a
    /// green heartbeat on the menu-bar icon while one is fresh. The agent
    /// touches `~/.cocore/last-served-at` on every served response (see
    /// `advisor::mark_served`); we only read its mtime, so this works for
    /// both app-supervised and LaunchAgent installs. We only reassign the
    /// button image when the visible state actually changes (active toggle
    /// or pulse phase), so the steady-state cost is a single `stat`.
    private func startHeartbeatTimer() {
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tickHeartbeat() }
        }
    }

    private func tickHeartbeat() {
        // Icon precedence, most-dominant first:
        //   paused   → diagonal CUT (owner stopped serving; not in rotation)
        //   bad      → RED pulse    (console says we're nonresponsive)
        //   serving  → GREEN pulse  (actively generating tokens, transient)
        //   attention→ YELLOW pulse (update available / failed — needs you)
        //   else     → plain
        // Paused tops the list: a stopped machine isn't routed jobs, so red
        // (no jobs) / green (serving) don't apply, and the cut is the honest
        // state. Red outranks the transient green; green (working now)
        // outranks the persistent yellow so live serving still shows, with
        // yellow surfacing once idle.
        let paused = Self.isRemotelyPaused()
        let bad = !paused && Self.isInBadStanding()
        let served =
            !paused && !bad
            && (Self.secondsSinceLastServe().map { $0 >= 0 && $0 <= Self.heartbeatWindow } ?? false)
        let attention = !paused && !bad && !served && needsAttention()
        heartbeatPhase.toggle()
        if paused {
            // Static (no pulse) — only redraw on entry.
            if iconState != .paused {
                item.button?.image = Self.brandImage(cut: true)
                iconState = .paused
            }
        } else if bad {
            item.button?.image = Self.brandImage(dot: .systemRed, pulse: heartbeatPhase ? 1.0 : 0.55)
            iconState = .alert
        } else if served {
            item.button?.image = Self.brandImage(dot: .systemGreen, pulse: heartbeatPhase ? 1.0 : 0.66)
            iconState = .serving
        } else if attention {
            item.button?.image = Self.brandImage(dot: .systemYellow, pulse: heartbeatPhase ? 1.0 : 0.6)
            iconState = .attention
        } else if iconState != .plain {
            item.button?.image = Self.brandImage()
            iconState = .plain
        }
        // Only touch the menu when a state the menu renders actually flips —
        // bad standing (the "needs attention" row + its reason), or a remote
        // stop (the "stopped from the console" row).
        let reason = bad ? Self.badStandingReason() : nil
        if bad != badStanding || paused != remotelyPausedShown || reason != badStandingReason {
            badStanding = bad
            badStandingReason = reason
            remotelyPausedShown = paused
            rebuildMenu()
        }
    }

    /// Yellow "needs attention" condition: an update is available or required,
    /// or the updater is reporting a failure the operator should see. Distinct
    /// from the red bad-standing pulse (console says we're nonresponsive) and
    /// the paused cut (owner stopped serving).
    private func needsAttention() -> Bool {
        switch updater.status {
        case .available, .required, .failed:
            return true
        case .upToDate, .updating:
            return updater.notice != nil
        }
    }

    /// True while the owner has this machine stopped from the console — the
    /// agent wrote `~/.cocore/serving-paused` and disconnected (see
    /// `wait_until_active`). It removes the file the moment it reconnects to
    /// serve, so the file's presence tracks the live remote-stop state.
    static func isRemotelyPaused() -> Bool {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".cocore/serving-paused").path
        return FileManager.default.fileExists(atPath: path)
    }

    /// Seconds since the agent last recorded a served response, or nil if
    /// it never has (file absent) on this install.
    static func secondsSinceLastServe() -> TimeInterval? {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".cocore/last-served-at").path
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let mtime = attrs[.modificationDate] as? Date else { return nil }
        return Date().timeIntervalSince(mtime)
    }

    /// True while the agent's `~/.cocore/bad-standing-at` marker exists and
    /// is recent — the advisor told this machine it stopped routing jobs
    /// here (see `advisor::write_bad_standing`). The agent clears the file
    /// on a clean re-register, so its presence tracks live bad standing; we
    /// ignore a marker older than 12h so an orphaned file (agent died before
    /// clearing it) can't pin the alert on forever.
    static func isInBadStanding() -> Bool {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".cocore/bad-standing-at").path
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let mtime = attrs[.modificationDate] as? Date else { return false }
        return Date().timeIntervalSince(mtime) < 12 * 3600
    }

    /// The reason line from the bad-standing marker (second line of
    /// `<timestamp>\n<reason>`), trimmed, or nil when absent/empty. The agent
    /// writes a short code on first flag and a fuller sentence when an
    /// auto-recovery attempt failed (see `advisor::write_bad_standing`).
    static func badStandingReason() -> String? {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".cocore/bad-standing-at").path
        guard let body = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        let lines = body.split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count >= 2 else { return nil }
        let reason = lines[1].trimmingCharacters(in: .whitespacesAndNewlines)
        return reason.isEmpty ? nil : reason
    }

    /// Provisioning state the agent reports while bringing a model online,
    /// from `~/.cocore/provision-status.json` (see `write_provision_status`).
    /// nil when absent — the agent cleared it because it's serving (or the
    /// machine is stopped). A marker older than 1h is ignored so a crashed
    /// agent can't pin "Provisioning…" on forever.
    struct ProvisionStatus {
        let phase: String  // "provisioning" | "failed"
        let bytesDownloaded: UInt64
        let faultMessage: String?
    }
    static func provisionStatus() -> ProvisionStatus? {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".cocore/provision-status.json").path
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
            let mtime = attrs[.modificationDate] as? Date,
            Date().timeIntervalSince(mtime) < 3600,
            let data = FileManager.default.contents(atPath: path),
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let phase = obj["phase"] as? String
        else { return nil }
        let bytes = (obj["bytesDownloaded"] as? NSNumber)?.uint64Value ?? 0
        let fault = (obj["fault"] as? [String: Any])?["message"] as? String
        return ProvisionStatus(phase: phase, bytesDownloaded: bytes, faultMessage: fault)
    }

    /// Content-safe human download size for the provisioning line.
    static func provisionMB(_ bytes: UInt64) -> String {
        String(format: "%.0f MB", Double(bytes) / (1024 * 1024))
    }

    /// Map the marker's reason to a one-line, operator-facing remediation.
    /// Known short codes get friendly text; a longer sentence the agent
    /// already wrote (e.g. an unrecoverable engine) is shown verbatim.
    static func friendlyBadStandingDetail(_ reason: String?) -> String? {
        guard let reason, !reason.isEmpty else { return nil }
        switch reason {
        case "preflight-no-response":
            return "It stopped answering readiness checks — trying to self-right."
        case "job-idle-timeout":
            return "It took a job and went quiet — trying to self-right."
        case "console-requested":
            return "Recovery requested — restarting the inference engine."
        default:
            // Already a human-readable sentence (e.g. the recovery-failed
            // detail). Keep it short for the menu.
            return reason.count > 120 ? String(reason.prefix(117)) + "…" : reason
        }
    }
}
