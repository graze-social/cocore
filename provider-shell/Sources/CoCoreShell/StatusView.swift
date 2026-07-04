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

    /// When provided, an explicit "Turn off Secure Mode" action — clears the
    /// durable intent so the reconciler stops re-driving attestation. Left
    /// `nil` in read-only contexts (button hidden).
    var onTurnOffSecureMode: (() -> Void)? = nil

    /// When provided, a "Retry now" action shown while confidential is
    /// Applying… — re-bounces the agent to re-trigger verification without
    /// waiting for the periodic reconciler. Left `nil` to hide it.
    var onRetryConfidential: (() -> Void)? = nil

    /// When provided, a "Sign in again" action shown while the agent's publish
    /// session is dead (`state.needsReauth`). Routes to the sign-in flow. Left
    /// `nil` in read-only contexts (the banner still warns, just no button).
    var onReauth: (() -> Void)? = nil

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
        // A dead publish session is the one failure that silently freezes
        // everything downstream — trustLevel, receipts, the machine listing —
        // while the agent still looks like it's "Serving". Surface it loudly,
        // above the rest, with a one-click path back to sign-in.
        if state.needsReauth, state.session != nil {
            Section {
                Label(
                    "Your co/core session expired. The agent can't publish "
                        + "records — receipts and Secure Mode are paused until you sign in again.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                if let onReauth {
                    Button("Sign in again", action: onReauth)
                }
            }
        }
        Section("Serving") {
            LabeledContent("State", value: servingText)
            // While downloading, name the models so a multi-GB wait is
            // explained ("which models?" is the first question), and set the
            // expectation that serving starts on its own afterwards.
            if let p = MenuBarController.provisionStatus(), p.phase == "provisioning",
                !p.models.isEmpty
            {
                Text(
                    "Fetching \(p.models.joined(separator: ", ")) — often several GB. "
                        + "Serving starts automatically when it finishes."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
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
            // ----- Secure Mode (attestation) -----
            LabeledContent("Secure Mode") {
                switch state.secureModePhase {
                case .on:
                    Text("On — hardware-attested (experimental)").foregroundStyle(.green)
                case .securing:
                    Text("Securing…").foregroundStyle(.orange)
                case .off:
                    Text("Off — self-attested (software)").foregroundStyle(.secondary)
                }
            }
            switch state.secureModePhase {
            case .on:
                secureCaption(
                    "This Mac is enrolled and attested as genuine Apple hardware (SIP verified). Experimental — a best-effort signal, not a guarantee.",
                    .secondary)
            case .securing(let reason):
                // The interstitial: tell the operator it's mid-flight and what,
                // if anything, they need to do — instead of looking simply off.
                secureCaption(reason, .orange)
            case .off:
                secureCaption(
                    "Attests this is genuine, untampered Apple hardware (SIP verified). Experimental; optional.",
                    .secondary)
            }
            if let exp = state.attestationExpiresAt {
                LabeledContent("Attestation expires", value: exp.formatted(.dateTime))
            }
            // Gated on a paired, live session: the wizard's MDM coordinator calls
            // need this agent's bearer key, and attesting while the publish
            // session is dead is a silent dead-end (the re-auth banner above is
            // the actionable step until it clears).
            if state.session != nil, !state.needsReauth {
                switch state.secureModePhase {
                case .on:
                    if let off = onTurnOffSecureMode {
                        Button("Turn off Secure Mode", action: off)
                    }
                case .securing:
                    // Needs the user to finish enrollment → re-open the wizard;
                    // otherwise it's re-attesting on its own and they can bail out.
                    if !EnrollmentProbe.isEnrolled(), let enable = onEnableSecureMode {
                        Button("Finish Secure Mode setup…", action: enable)
                    }
                    if let off = onTurnOffSecureMode {
                        Button("Turn off Secure Mode", action: off)
                    }
                case .off:
                    if let enable = onEnableSecureMode {
                        Button("Enable Secure Mode…", action: enable)
                    }
                }
            }

            // ----- Confidential (sealed inference) -----
            LabeledContent("Confidential tier") {
                switch state.confidentialPhase {
                case .active:
                    Text("🔒 Confidential (experimental)").foregroundStyle(.green)
                case .applying:
                    Text("Applying…").foregroundStyle(.orange)
                case .off:
                    Text("Best-effort").foregroundStyle(.secondary)
                }
            }
            // Whose data, and from whom: confidential seals the REQUESTOR's
            // prompts against YOU (this Mac's operator) — not the other way round.
            switch state.confidentialPhase {
            case .active:
                secureCaption(
                    "Requests run inside the measured, signed agent, under a hardened runtime with no subprocess to tap — this aims to keep what requestors send and receive unreadable to you, this Mac's operator. It's experimental and not independently audited: a software-sealed posture, not a hardware enclave, and it only holds as long as macOS and the signed build aren't compromised.",
                    .secondary)
            case .applying(let reason):
                // The interstitial that fixes "I have to toggle until it takes":
                // say exactly what's still pending instead of falling silent.
                secureCaption(
                    reason
                        ?? "Turning on confidential — finishing verification with the network. This can take a moment.",
                    .orange)
            case .off:
                secureCaption(
                    "Requests run in a local helper process that you, this Mac's operator, could read — fine for non-sensitive work. Confidential mode aims to keep them unreadable to you by running inside the measured agent (experimental — a hardened-runtime posture, not a hardware enclave). The confidential engine serves Qwen2 / Qwen3 / Llama / Gemma / Phi-class models.",
                    .secondary)
            }
            if let setConfidential = onSetConfidential {
                // Drive the action by the DURABLE intent (desired), not the
                // advisor-verified flag: while Applying… the action is "Turn
                // off", never "Enable" again (the old verified-driven label
                // re-fired Enable and re-bounced — part of the finickiness).
                switch state.confidentialPhase {
                case .off:
                    Button("Enable confidential…") { setConfidential(true) }
                case .applying:
                    Button("Turn off confidential") { setConfidential(false) }
                    if let retry = onRetryConfidential {
                        Button("Retry now", action: retry)
                    }
                case .active:
                    Button("Turn off confidential") { setConfidential(false) }
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

    /// A wrapping caption line (description / interstitial reason). Factored so
    /// the Secure Mode + Confidential rows render their multi-state captions
    /// identically.
    @ViewBuilder
    private func secureCaption(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(color)
            .fixedSize(horizontal: false, vertical: true)
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
                if p.loading { return "Loading models into memory…" }
                return p.bytesDownloaded > 0
                    ? "Downloading models… (\(MenuBarController.humanBytes(p.bytesDownloaded)) so far)"
                    : "Downloading models…"
            }
            // Engines are up; the machine is registering with the network.
            // Gated on state.serving so a stopped agent's leftover marker
            // can't pin "connecting" over an honest "Not serving".
            if p.phase == "starting", state.serving { return "Connecting to the network…" }
            if p.phase == "failed" { return "Model setup failed" }
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
