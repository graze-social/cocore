// StatusView: a dedicated window that packs up the at-a-glance details
// that used to crowd the menu bar as grayed-out rows — identity, trust,
// earnings/balance, attestation, serving state, and the app + agent
// versions. The same rows render in Preferences › Status via `StatusRows`.

import AppKit
import SwiftUI

/// The detail rows, factored so the Status window and the Preferences
/// Status tab stay in sync. Designed to live inside a `Form`.
struct StatusRows: View {
    @EnvironmentObject private var state: AppState

    var body: some View {
        Section("Identity") {
            if let s = state.session {
                LabeledContent("Handle", value: s.handle)
                LabeledContent("DID", value: s.did)
                if let apiBase = s.apiBase {
                    LabeledContent("API", value: apiBase)
                }
            } else {
                Text("Not signed in.")
            }
        }
        Section("Serving") {
            LabeledContent("State", value: servingText)
            LabeledContent("Trust level", value: state.trustLevel.rawValue)
            if let exp = state.attestationExpiresAt {
                LabeledContent("Attestation expires", value: exp.formatted(.dateTime))
            }
        }
        Section("Credits") {
            if let bal = state.balanceCredits {
                LabeledContent("Balance", value: creditsDisplay(bal))
            }
            LabeledContent("Earnings (24h)", value: creditsDisplay(state.creditsLast24h))
        }
        Section("Version") {
            LabeledContent("App", value: Updater.currentVersion)
            if let v = state.agentVersion {
                LabeledContent("Agent", value: v)
            }
        }
    }

    /// Human-readable serving state, schedule-aware to match the menu's
    /// indicator (a scheduled-idle agent is "running" to launchd but not
    /// actually serving).
    private var servingText: String {
        let sched = MenuBarController.scheduleState()
        if sched.limited && !sched.within {
            return "Idle until \(PreferencesView.hourLabel(sched.start)) (scheduled)"
        }
        // The agent is still bringing a model online — the process is up but
        // it isn't serving yet, so don't claim "Serving".
        if let p = MenuBarController.provisionStatus() {
            if p.phase == "provisioning" {
                return p.bytesDownloaded > 0
                    ? "Provisioning… (\(MenuBarController.provisionMB(p.bytesDownloaded)) downloaded)"
                    : "Provisioning…"
            }
            if p.phase == "failed" { return "Provisioning failed" }
        }
        return state.serving ? "Serving" : "Not serving"
    }
}

struct StatusView: View {
    @EnvironmentObject private var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Status")
                .font(.title2).bold()
                .foregroundStyle(Brand.accentText)

            Form { StatusRows() }
                .formStyle(.grouped)

            if state.session != nil {
                Button("View my profile on console") { openProfile() }
                    .buttonStyle(.link)
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(width: 470, height: 520)
        .brandStyled()
    }

    private func openProfile() {
        guard let handle = state.session?.handle else { return }
        let console = UserDefaults.standard.string(forKey: "consoleBaseUrl")
            ?? "https://console.cocore.dev"
        guard let url = URL(string: "\(console)/u/\(handle)") else { return }
        NSWorkspace.shared.open(url)
    }
}

/// Hosts StatusView in a standalone window opened from the menu bar.
@MainActor
final class StatusWindowController {
    private var window: NSWindow?
    private let state: AppState

    init(state: AppState) { self.state = state }

    func show() {
        if window == nil {
            let hosting = NSHostingController(rootView: StatusView().environmentObject(state))
            let w = NSWindow(contentViewController: hosting)
            w.title = "cocore — Status"
            w.styleMask = [.titled, .closable, .miniaturizable]
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        if let w = window { WindowActivation.present(w) }
    }
}
