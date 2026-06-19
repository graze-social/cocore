// MainWindow: the single window the tray's "Open co/core…" opens. It folds
// what used to be separate Status / Models / Preferences windows plus the
// About housekeeping (version, updates, bug report, uninstall) into one
// window, so the status-bar menu can stay short — the menu keeps only the
// serving toggle, the at-a-glance lines, contextual alerts, "Open co/core…",
// and Quit.
//
// Why AppKit toolbar tabs (NSTabViewController `.toolbar`) instead of a
// SwiftUI `TabView`: SwiftUI renders its tab strip jammed against the
// titlebar with no breathing room. The toolbar tab style gives the native,
// System-Settings look — icon+label tabs integrated into the titlebar with
// correct spacing — and names the window after the active tab. Each tab is a
// SwiftUI view hosted in an NSHostingController; action closures route back
// to MenuBarController, which owns the NSAlert flows and supervisor lifecycle.
//
// Flow / ordering (what a provider wants, in order): Status (am I serving +
// earning?) → Models (what am I running?) → Settings (configure it) → About
// (version / updates / report / uninstall).

import AppKit
import SwiftUI

@MainActor
final class MainWindowController {
    private var window: NSWindow?

    private let state: AppState
    private let supervisor: AgentSupervisor
    private let updater: Updater
    private let modelManager: ModelManager
    private let onOpenProfile: () -> Void
    private let onOpenSetupGuide: () -> Void
    private let onSignOut: () -> Void
    private let onSendBugReport: () -> Void
    private let onCheckUpdates: () -> Void
    private let onInstallUpdate: () -> Void
    private let onUninstall: () -> Void

    init(
        state: AppState,
        supervisor: AgentSupervisor,
        updater: Updater,
        modelManager: ModelManager,
        onOpenProfile: @escaping () -> Void,
        onOpenSetupGuide: @escaping () -> Void,
        onSignOut: @escaping () -> Void,
        onSendBugReport: @escaping () -> Void,
        onCheckUpdates: @escaping () -> Void,
        onInstallUpdate: @escaping () -> Void,
        onUninstall: @escaping () -> Void
    ) {
        self.state = state
        self.supervisor = supervisor
        self.updater = updater
        self.modelManager = modelManager
        self.onOpenProfile = onOpenProfile
        self.onOpenSetupGuide = onOpenSetupGuide
        self.onSignOut = onSignOut
        self.onSendBugReport = onSendBugReport
        self.onCheckUpdates = onCheckUpdates
        self.onInstallUpdate = onInstallUpdate
        self.onUninstall = onUninstall
    }

    func show() {
        if window == nil {
            let tabs = NSTabViewController()
            tabs.tabStyle = .toolbar
            tabs.tabViewItems = [
                tab("Status", "gauge.medium",
                    StatusTab(
                        onOpenProfile: onOpenProfile,
                        onOpenSetupGuide: onOpenSetupGuide,
                        onSignOut: onSignOut)),
                tab("Models", "cpu", ModelsView(manager: modelManager)),
                tab("Settings", "gearshape", PreferencesView(supervisor: supervisor)),
                tab("About", "info.circle",
                    AboutTab(
                        updater: updater,
                        onSendBugReport: onSendBugReport,
                        onCheckUpdates: onCheckUpdates,
                        onInstallUpdate: onInstallUpdate,
                        onUninstall: onUninstall)),
            ]
            let w = NSWindow(contentViewController: tabs)
            w.title = "co/core"
            w.styleMask = [.titled, .closable, .miniaturizable]
            // `.preference` centers the tab toolbar under the title — the
            // standard preferences-window layout, and what gives the tabs
            // their breathing room instead of hugging the titlebar.
            w.toolbarStyle = .preference
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        if let w = window { WindowActivation.present(w) }
    }

    /// Wrap a SwiftUI tab body in an NSHostingController with the shared
    /// environment + brand tint at a fixed size, so the window stays one
    /// consistent size across tabs (no per-tab resize jank).
    private func tab(_ label: String, _ symbol: String, _ content: some View) -> NSTabViewItem {
        let root =
            content
            .environmentObject(state)
            .frame(width: 540, height: 600)
            .brandStyled()
        let host = NSHostingController(rootView: root)
        host.sizingOptions = []
        // NSTabViewController titles the window from the selected pane's
        // controller — leaving it nil reads "Untitled", and using the tab
        // label makes the title flip per tab. Pin every pane to "co/core" so
        // the window stays consistently branded; the toolbar buttons still
        // carry their own labels (set on the NSTabViewItem below).
        host.title = "co/core"
        let item = NSTabViewItem(viewController: host)
        item.label = label
        item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: label)
        return item
    }
}

/// Identity + serving + credits + versions (the shared `StatusRows`), plus
/// the account actions that used to be their own menu items. Updates live in
/// About now, so there's one home for them instead of two.
private struct StatusTab: View {
    let onOpenProfile: () -> Void
    let onOpenSetupGuide: () -> Void
    let onSignOut: () -> Void
    @EnvironmentObject private var state: AppState

    var body: some View {
        Form {
            StatusRows()
            Section {
                Button("View my profile on console", action: onOpenProfile)
                    .disabled(state.session == nil)
                Button("Setup guide…", action: onOpenSetupGuide)
                Button("Sign out", action: onSignOut)
                    .disabled(state.session == nil)
            }
        }
        .formStyle(.grouped)
    }
}

/// The update affordance — shown in About (and mirrored by the status-bar
/// menu when an update is pending), so it surfaces the same state-appropriate
/// control: check / update / retry.
private struct UpdateControl: View {
    @ObservedObject var updater: Updater
    let onCheckUpdates: () -> Void
    let onInstallUpdate: () -> Void

    var body: some View {
        switch updater.status {
        case .upToDate:
            Button("Check for updates…", action: onCheckUpdates)
        case .available(let v):
            Button("Update to \(v)…", action: onInstallUpdate)
        case .required(let v):
            Text("Update required (\(v)) — installing…").foregroundStyle(.secondary)
        case .updating(let v):
            Text("Updating to \(v)…").foregroundStyle(.secondary)
        case .failed(let m):
            LabeledContent("Update", value: m)
            Button("Retry update", action: onInstallUpdate)
        }
    }
}

/// Version, the update control, the bug-report action, and the uninstall —
/// the housekeeping that doesn't belong in the tray menu.
private struct AboutTab: View {
    @ObservedObject var updater: Updater
    let onSendBugReport: () -> Void
    let onCheckUpdates: () -> Void
    let onInstallUpdate: () -> Void
    let onUninstall: () -> Void

    var body: some View {
        Form {
            Section("Software") {
                LabeledContent("Version", value: Updater.currentVersion)
                UpdateControl(
                    updater: updater,
                    onCheckUpdates: onCheckUpdates,
                    onInstallUpdate: onInstallUpdate
                )
            }
            if let n = updater.notice, !n.isEmpty {
                Section { Text(n).foregroundStyle(.secondary) }
            }
            Section("Something wrong?") {
                Button("Send bug report…", action: onSendBugReport)
                Text("Sends crash + health telemetry only — no prompts, no API key, no signing key.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section {
                Button("Uninstall co/core…", role: .destructive, action: onUninstall)
            }
        }
        .formStyle(.grouped)
    }
}
