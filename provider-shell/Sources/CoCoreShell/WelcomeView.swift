// WelcomeView: a first-run onboarding wizard that hand-holds a new
// provider through every setup step IN ONE WINDOW — sign in, choose a
// model, install the Python runtime, start serving — with a live
// checklist that ticks each step off as the app's state advances.
//
// The whole flow lives here: the model picker and the ~280MB Python
// runtime bootstrap are inlined (reusing ModelManager + VenvBootstrapper)
// rather than bouncing the user out to the separate Models window, which
// was the main onboarding friction. Shown automatically on launch (and
// right after a menu sign-in) until setup is complete, and reopenable any
// time from the menu's "Setup Guide…".

import AppKit
import SwiftUI

@MainActor
final class WelcomeWindowController {
    private var window: NSWindow?
    private let state: AppState
    private let supervisor: AgentSupervisor
    /// Hook so the wizard's "Manage all models…" escape hatch opens the
    /// shared, full-featured models window for power users.
    var onOpenModels: (() -> Void)?

    init(state: AppState, supervisor: AgentSupervisor) {
        self.state = state
        self.supervisor = supervisor
    }

    func show() {
        if window == nil {
            let view = WelcomeView(
                state: state,
                supervisor: supervisor,
                openModels: { [weak self] in self?.onOpenModels?() },
                close: { [weak self] in self?.window?.close() }
            )
            let w = NSWindow(contentViewController: NSHostingController(rootView: view))
            w.title = "Welcome to co/core"
            w.styleMask = [.titled, .closable]
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        if let w = window { WindowActivation.present(w) }
    }
}

struct WelcomeView: View {
    @ObservedObject var state: AppState
    let supervisor: AgentSupervisor
    let openModels: () -> Void
    let close: () -> Void

    @StateObject private var models: ModelManager
    @StateObject private var venv = VenvBootstrapper()
    @State private var signingIn = false
    @State private var startingServe = false
    @State private var venvInstalled = VenvBootstrapper.isInstalled
    /// Latch so the runtime install auto-fires at most once per window —
    /// a failure the user is retrying shouldn't re-trigger from the poll.
    @State private var autoKickedRuntime = false
    /// Approval URL + code from the device-pair flow, shown so the user has
    /// a reliable click-through even if the browser didn't auto-open.
    @State private var pairPrompt: PairPrompt?
    @State private var pairError: String?
    /// Owner-chosen display name for this machine. Seeded on appear with the
    /// Mac's friendly "Computer Name" so the default isn't the raw `.local`
    /// hostname; the agent reads it via COCORE_MACHINE_LABEL on serve start.
    @AppStorage("machineLabel") private var machineName = ""

    init(
        state: AppState, supervisor: AgentSupervisor,
        openModels: @escaping () -> Void, close: @escaping () -> Void
    ) {
        _state = ObservedObject(wrappedValue: state)
        self.supervisor = supervisor
        self.openModels = openModels
        self.close = close
        // The checklist's model store must match what the agent reads:
        // app-managed (UserDefaults) on no-LaunchAgent installs.
        _models = StateObject(wrappedValue: ModelManager(supervisor: supervisor))
    }

    private var signedIn: Bool { state.session != nil }
    private var hasModels: Bool { !models.models.isEmpty }
    private var runtimeReady: Bool { venvInstalled }
    private var serving: Bool { state.serving }
    private var allDone: Bool { signedIn && hasModels && runtimeReady && serving }
    /// Real models can't run until the runtime exists, so block "Start
    /// serving" while a real model is selected and the runtime isn't
    /// ready yet (a stub-only setup — no models — can serve immediately).
    private var canServe: Bool { signedIn && (runtimeReady || !hasModels) }

    var body: some View {
        VStack(spacing: 0) {
            splash
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    nameField
                    stepSignIn
                    stepModel
                    stepRuntime
                    stepServe
                }
                .padding(24)
            }
            Divider()
            footer
        }
        .frame(width: 520, height: 620)
        .brandStyled()
        .onAppear {
            // Seed the name with the Mac's friendly "Computer Name" so the
            // default isn't the raw `.local` hostname — the whole point of
            // the field. Only when the owner hasn't already set one.
            if machineName.trimmingCharacters(in: .whitespaces).isEmpty {
                machineName = WelcomeView.suggestedMachineName()
            }
        }
        .task { await refresh() }
        // The checklist auto-advances: re-read session/models/runtime/
        // serving every few seconds so steps tick over as background work
        // (sign-in approval, runtime install, agent start) completes.
        .onReceive(Timer.publish(every: 3, on: .main, in: .common).autoconnect()) { _ in
            Task { await refresh() }
        }
    }

    // MARK: splash

    private var splash: some View {
        HStack(spacing: 16) {
            Image(nsImage: MenuBarController.brandImage(pointSize: 44))
                .resizable()
                .renderingMode(.template)
                .frame(width: 44, height: 44)
                .foregroundStyle(Brand.mark)
            VStack(alignment: .leading, spacing: 3) {
                Text("Welcome to co/core")
                    .font(.largeTitle).bold()
                    .foregroundStyle(Brand.accentText)
                Text("Turn this Mac into a verifiable compute provider — a few quick steps and you're earning credits.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Brand.surface)
    }

    // MARK: name this machine

    private var nameField: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Name this machine")
                .font(.headline)
                .foregroundStyle(Brand.accentText)
            Text("How this rig shows up to people who send it work. Defaults to your Mac's name — change it so you're not sharing a “.local” hostname.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("My Mac", text: $machineName)
                .textFieldStyle(.roundedBorder)
                // New setup: persisting is enough — the name is read on Start
                // serving. Re-provisioning a machine that's already serving:
                // apply now so the record re-publishes with the new name.
                .onSubmit {
                    if serving { Task { await supervisor.applyMachineNameAndReconnect() } }
                }
        }
    }

    /// The Mac's friendly "Computer Name" (e.g. "Devin's MacBook Pro"),
    /// which is what we want to default to instead of the `.local` hostname.
    static func suggestedMachineName() -> String {
        let friendly = Host.current().localizedName?.trimmingCharacters(in: .whitespaces) ?? ""
        if !friendly.isEmpty { return friendly }
        let host = ProcessInfo.processInfo.hostName.trimmingCharacters(in: .whitespaces)
        return host.isEmpty ? "My Mac" : host
    }

    // MARK: step 1 — sign in

    private var stepSignIn: some View {
        step(1, done: signedIn, active: !signedIn, title: "Sign in",
             desc: signedIn
                ? "Signed in as \(state.session?.handle ?? "your identity")."
                : "Connect your ATProto identity to pair this machine.") {
            if !signedIn {
                VStack(alignment: .leading, spacing: 10) {
                    // Three-state so the click registers instantly with an
                    // honest label: idle → "Sign in", then the soft
                    // "Signing in…" (with a spinner) the moment the OAuth
                    // handshake begins, then "Waiting for approval…" once
                    // there's actually a device-pair URL to approve. The old
                    // single flip to "Waiting for approval…" was premature —
                    // nothing to approve yet while the pair flow spins up.
                    Button {
                        signIn()
                    } label: {
                        HStack(spacing: 8) {
                            if signingIn, pairPrompt == nil {
                                ProgressView().controlSize(.small)
                            }
                            Text(signInButtonTitle)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(signingIn)

                    // Once the device-pair flow has a URL, show it inline so
                    // the user is never stuck waiting on a browser that
                    // didn't come forward (the app is foreground now, so an
                    // auto-opened tab can land behind this window).
                    if signingIn, let p = pairPrompt {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack(spacing: 8) {
                                ProgressView().controlSize(.small)
                                Text("Approve this Mac in your browser to finish.")
                                    .font(.callout).foregroundStyle(.secondary)
                            }
                            Button {
                                NSWorkspace.shared.open(p.url)
                            } label: {
                                Label("Open approval page", systemImage: "safari")
                            }
                            if !p.code.isEmpty {
                                (Text("Didn't open? Visit ")
                                    + Text("\(p.url.host ?? "the console")/devices/new").bold()
                                    + Text(" and enter code ")
                                    + Text(p.code).font(.system(.body, design: .monospaced)).bold())
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    if let e = pairError {
                        Text(e).font(.caption).foregroundStyle(.red).lineLimit(3)
                    }
                }
            }
        }
    }

    // MARK: step 2 — choose a model (inline picker, no separate window)

    private var stepModel: some View {
        step(2, done: hasModels, active: signedIn && !hasModels, title: "Choose a model",
             desc: hasModels
                ? "Serving \(models.models.count) model\(models.models.count == 1 ? "" : "s"). Add more or pick a bigger one any time."
                : "Pick which model this Mac will serve. Larger models earn more but need more memory.") {
            VStack(alignment: .leading, spacing: 8) {
                if hasModels {
                    FlowChips(items: models.models) { nsid in
                        Task { await models.onboardingToggle(nsid); await refresh() }
                    }
                }
                HStack(spacing: 10) {
                    Menu {
                        // Best-fitting model for this Mac first; each shows its
                        // RAM need + whether it fits this device.
                        ForEach(ModelManager.catalogForDevice, id: \.nsid) { item in
                            Button {
                                Task { await models.onboardingToggle(item.nsid); await refresh() }
                            } label: {
                                Text(
                                    ModelManager.fitsDevice(item.minRamGB)
                                        ? "\(item.label) · needs ~\(item.minRamGB)GB"
                                        : "\(item.label) · needs ~\(item.minRamGB)GB (more than this Mac)"
                                )
                            }
                            .disabled(models.models.contains(item.nsid))
                        }
                    } label: {
                        Label(hasModels ? "Add another model" : "Choose a model", systemImage: "plus.circle")
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                    .disabled(!signedIn || models.busy)

                    Button("Manage all models…") { openModels() }
                        .buttonStyle(.link)
                        .disabled(!signedIn)
                }
                if let e = models.error {
                    Text(e).font(.caption).foregroundStyle(.red).lineLimit(3)
                }
            }
        }
    }

    // MARK: step 3 — install the Python runtime (inline, auto-kicked)

    private var stepRuntime: some View {
        step(3, done: runtimeReady, active: signedIn && hasModels && !runtimeReady,
             title: "Set up the runtime",
             desc: runtimeReady
                ? "Python runtime installed — real models can run."
                : "Real models need a one-time Python runtime (~280 MB). We'll install it for you.") {
            if !runtimeReady {
                switch venv.state {
                case .running(let line):
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Installing… \(line)")
                            .font(.callout).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.middle)
                    }
                case .failed(let msg):
                    VStack(alignment: .leading, spacing: 6) {
                        Text(msg).font(.callout).foregroundStyle(.red).lineLimit(3)
                        Button("Retry runtime setup") { runBootstrap() }
                    }
                default:
                    // Idle: offer a manual start too, in case the user
                    // jumped here before picking a model (auto-kick only
                    // fires once a model is selected).
                    Button("Install the runtime (~280 MB)") { runBootstrap() }
                        .disabled(!signedIn)
                }
            }
        }
    }

    // MARK: step 4 — start serving

    private var stepServe: some View {
        step(4, done: serving, active: canServe && !serving, title: "Start serving",
             desc: serving
                ? "Serving — answering requests and earning credits."
                : (signedIn && hasModels && !runtimeReady)
                    ? "Ready to serve as soon as the runtime finishes installing."
                    : "Connect to the network and begin earning credits.") {
            if !serving {
                Button(startingServe ? "Starting…" : "Start serving") { startServing() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(!canServe || startingServe)
            }
        }
    }

    // MARK: footer

    private var footer: some View {
        HStack(spacing: 12) {
            if allDone {
                Text("🎉 You're all set — this Mac is a live co/core provider.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button(allDone ? "Done" : "Do this later") {
                UserDefaults.standard.set(true, forKey: "onboardingSeen")
                close()
            }
            .keyboardShortcut(.defaultAction)
        }
        .padding(20)
    }

    // MARK: step chrome

    @ViewBuilder
    private func step(
        _ n: Int, done: Bool, active: Bool, title: String, desc: String,
        @ViewBuilder action: () -> some View
    ) -> some View {
        HStack(alignment: .top, spacing: 14) {
            ZStack {
                Circle()
                    .fill(done ? Brand.success : (active ? Brand.accent : Color.secondary.opacity(0.22)))
                    .frame(width: 26, height: 26)
                if done {
                    Image(systemName: "checkmark")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(.white)
                } else {
                    Text("\(n)")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(active ? .white : .secondary)
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.headline)
                Text(desc).font(.subheadline).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                action()
            }
            Spacer(minLength: 0)
        }
        .opacity(done || active ? 1 : 0.55)
    }

    // MARK: actions

    /// Re-read all the state the checklist keys off, and auto-start the
    /// runtime install once the user is signed in and has a model but the
    /// runtime is missing — so the long download overlaps with them
    /// reading the next step instead of waiting on a click.
    private func refresh() async {
        await models.refresh()
        venvInstalled = VenvBootstrapper.isInstalled
        state.serving = supervisor.isServing()
        if signedIn, hasModels, !venvInstalled, !venv.isRunning, !autoKickedRuntime {
            autoKickedRuntime = true
            runBootstrap()
        }
    }

    /// Label for the sign-in button — idle / handshake-beginning / waiting.
    private var signInButtonTitle: String {
        if !signingIn { return "Sign in with ATProto" }
        return pairPrompt == nil ? "Signing in…" : "Waiting for approval…"
    }

    private func signIn() {
        signingIn = true
        pairError = nil
        pairPrompt = nil
        Task {
            defer { signingIn = false; pairPrompt = nil }
            do {
                _ = try await PairFlow.signIn(onPrompt: { p in pairPrompt = p })
                await state.refreshSession()
                await state.refreshStatus()
                await refresh()
                state.lastError = nil  // clear any prior failed-sign-in line
            } catch {
                pairError = "Couldn't finish pairing. Click “Sign in with ATProto” to try again."
                // The window shows the actionable `pairError` above; the menu's
                // catch-all gets a short, directive line (the raw error goes to
                // the log, not the menu, so it can't balloon a single row).
                NSLog("cocore: pairing failed: %@", String(describing: error))
                state.setError("Sign-in didn’t finish — open co/core to retry.")
            }
        }
    }

    private func runBootstrap() {
        Task {
            await venv.bootstrap()
            venvInstalled = VenvBootstrapper.isInstalled
            if venvInstalled { await models.refresh() }
        }
    }

    private func startServing() {
        startingServe = true
        Task {
            await supervisor.start()
            state.serving = supervisor.isServing()
            startingServe = false
        }
    }
}

/// A simple wrapping row of removable model chips. Kept local to the
/// wizard — the full Models window has its own richer list.
private struct FlowChips: View {
    let items: [String]
    let onRemove: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(items, id: \.self) { nsid in
                HStack(spacing: 6) {
                    Text(shortLabel(nsid))
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1).truncationMode(.middle)
                    Button {
                        onRemove(nsid)
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .help("Remove this model")
                }
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(Color.secondary.opacity(0.12), in: Capsule())
            }
        }
    }

    /// Prefer the catalog's friendly label when we recognize the NSID,
    /// else show the raw NSID.
    private func shortLabel(_ nsid: String) -> String {
        ModelManager.catalog.first(where: { $0.nsid == nsid })?.label ?? nsid
    }
}
