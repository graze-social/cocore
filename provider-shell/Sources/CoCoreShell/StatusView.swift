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

    /// When provided, the Security section shows an "Enable Secure Mode…"
    /// action (the MDM/attestation wizard). Left `nil` where there's no place
    /// to host the wizard (e.g. the read-only standalone Status window), which
    /// just hides the button.
    var onEnableSecureMode: (() -> Void)? = nil

    /// When provided, the Security section shows an Enable/Turn-off Confidential
    /// toggle (writes the owner's `desiredTier`). The Bool is the desired state
    /// (true = enable). Left `nil` to hide the control (read-only contexts).
    var onSetConfidential: ((Bool) -> Void)? = nil

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
            // The full provisioning-failure reason lives here (not the menu,
            // where a long single line can't wrap and balloons the window).
            if let p = MenuBarController.provisionStatus(), p.phase == "failed",
                let msg = p.faultMessage
            {
                Text(msg)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        // Two ORTHOGONAL postures, deliberately separated so neither is mistaken
        // for the other:
        //   • Secure Mode (attestation) — proves this is genuine Apple hardware.
        //   • Confidential — seals inference so the operator can't read prompts.
        Section("Security") {
            LabeledContent("Secure Mode") {
                Text(state.trustLevel == .hardwareAttested
                    ? "On — hardware-attested"
                    : "Off — self-attested (software)")
                    .foregroundStyle(state.trustLevel == .hardwareAttested ? .green : .secondary)
            }
            Text(state.trustLevel == .hardwareAttested
                ? "This Mac is enrolled and proven to be genuine Apple hardware (SIP verified)."
                : "Proves this is genuine, untampered Apple hardware (SIP verified). Optional.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let exp = state.attestationExpiresAt {
                LabeledContent("Attestation expires", value: exp.formatted(.dateTime))
            }
            // Gated on a paired session: the wizard's MDM coordinator calls
            // need this agent's bearer key (session.apiKey/apiBase), so there's
            // nothing to enable until pairing completes. Mirrors the Identity
            // section's signed-in / "Not signed in" split above.
            if state.trustLevel != .hardwareAttested, state.session != nil,
                let enable = onEnableSecureMode {
                Button("Enable Secure Mode…", action: enable)
            }

            LabeledContent("Confidential tier") {
                Text(state.confidential ? "🔒 Confidential" : "Best-effort")
                    .foregroundStyle(state.confidential ? .green : .secondary)
            }
            // Whose data, and from whom: confidential seals the REQUESTOR's
            // prompts against YOU (this Mac's operator) — not the other way
            // round. Written from the operator's seat so "operator" isn't
            // mistaken for some third party.
            Text(state.confidential
                ? "Requests run sealed inside the measured, signed agent, so not even you — this Mac's operator — can read what requestors send or receive. That unreadable-by-the-operator guarantee is what requestors get."
                : "Requests run in a local helper process that you, this Mac's operator, could read — fine for non-sensitive work. Enable confidential to seal them so requestors get a no-snooping guarantee. The confidential engine serves Qwen2 / Qwen3 / Llama / Gemma / Phi-class models.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let setConfidential = onSetConfidential {
                Button(state.confidential ? "Turn off confidential" : "Enable confidential…") {
                    setConfidential(!state.confidential)
                }
            }
            if let url = URL(string: "\(Endpoints.consoleURL)/docs/security") {
                Link("Learn more about Secure Mode & Confidential", destination: url)
                    .font(.caption)
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
                    ? "Provisioning… (\(MenuBarController.humanBytes(p.bytesDownloaded)) downloaded)"
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
        let console = Endpoints.consoleURL
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
            w.title = "co/core — Status"
            w.styleMask = [.titled, .closable, .miniaturizable]
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        if let w = window { WindowActivation.present(w) }
    }
}
