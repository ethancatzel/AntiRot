import AppKit
import SwiftUI

/// The menu bar panel, laid out in the System Settings idiom: a grouped `Form`
/// headed by a status row with the master switch, the way the Firewall and VPN
/// panes work. Blocklist edits apply immediately; there is no Save button.
/// Typing this phrase confirms a disable. The friction is the point: turning off
/// blocking should be a deliberate act, not a reflex.
private let disablePhrase = "AntiRot"

struct ContentView: View {
    @Environment(FilterController.self) private var controller
    @State private var newSite = ""
    @State private var pendingDisable: (() -> Void)?

    var body: some View {
        Form {
            Section {
                statusRow
            } footer: {
                if !controller.status.isEmpty {
                    Text(controller.status).foregroundStyle(.secondary)
                }
            }

            Section {
                if controller.domains.isEmpty {
                    Text("No sites blocked yet.").foregroundStyle(.secondary)
                }
                ForEach(controller.domains, id: \.self) { site in
                    HStack {
                        Text(site).monospaced()
                        Spacer()
                        Button("Remove \(site)", systemImage: "minus.circle.fill") {
                            controller.removeSite(site)
                        }
                        .labelStyle(.iconOnly)
                        .buttonStyle(.borderless)
                        .foregroundStyle(.secondary)
                    }
                }
                HStack {
                    TextField("Site to block", text: $newSite, prompt: Text(verbatim: ""))
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(add)
                    Button("Add", action: add)
                        .disabled(newSite.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            } header: {
                Text("Blocked Sites")
            } footer: {
                Text("Subdomains are blocked too.")
                    .foregroundStyle(.secondary)
            }

            Section {
                LabeledContent("System extension") {
                    HStack(spacing: 8) {
                        Button("Activate") { controller.activate() }
                        Button("Deactivate") { requestDisable { controller.deactivate() } }
                    }
                }
            } footer: {
                Text("AntiRot filters network traffic with a system extension. You'll approve it once in System Settings. Quitting stops blocking; the extension stays installed.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Button {
                    NSApp.terminate(nil)
                } label: {
                    Text("Quit").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.red)
                .keyboardShortcut("q")
            }
        }
        .formStyle(.grouped)
        .frame(width: 360, height: 460)
        .overlay {
            // Inline, not a `.sheet`: a sheet opens its own window, which steals
            // focus from the menu bar panel and gets stranded when the panel
            // closes. An overlay lives in the panel, so it always dismisses.
            if let disable = pendingDisable {
                DisableConfirmationView(confirm: disable) { pendingDisable = nil }
            }
        }
        .animation(.default, value: pendingDisable != nil)
    }

    /// The pane's identity: a shield that fills in when protection is on, the
    /// current state in words, and the master switch.
    private var statusRow: some View {
        HStack(spacing: 14) {
            Image(systemName: controller.shieldSymbol)
                .font(.system(size: 32))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(controller.isFilterEnabled ? Color.green : Color.secondary)
                .frame(width: 44, height: 40)
                .contentTransition(.symbolEffect(.replace))
            VStack(alignment: .leading, spacing: 2) {
                Text("AntiRot").font(.headline)
                Text(controller.isFilterEnabled
                     ? "Blocking ^[\(controller.domains.count) site](inflect: true)"
                     : "Off")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("Block distracting sites", isOn: filterEnabled)
                .labelsHidden()
                .toggleStyle(.switch)
        }
        .padding(.vertical, 4)
        .animation(.default, value: controller.isFilterEnabled)
    }

    /// A switch that drives the filter; its read reflects live state. Enabling is
    /// immediate; disabling is gated behind the confirmation, so the switch snaps
    /// back on until the phrase is typed.
    private var filterEnabled: Binding<Bool> {
        Binding(get: { controller.isFilterEnabled },
                set: { on in
                    if on {
                        controller.setFilter(enabled: true)
                    } else {
                        requestDisable { controller.setFilter(enabled: false) }
                    }
                })
    }

    /// Gate any action that stops blocking behind the type-to-confirm overlay.
    private func requestDisable(_ action: @escaping () -> Void) {
        pendingDisable = action
    }

    private func add() {
        controller.addSite(newSite)
        newSite = ""
    }
}

/// The type-to-confirm gate, shown as an overlay card over the panel. Disabling
/// only fires once the app's name is typed exactly, turning an impulse into a
/// deliberate choice. Cancel, the backdrop, and Escape all dismiss it.
private struct DisableConfirmationView: View {
    let confirm: () -> Void
    let dismiss: () -> Void
    @State private var typed = ""
    @FocusState private var focused: Bool

    private var matches: Bool {
        typed.trimmingCharacters(in: .whitespaces) == disablePhrase
    }

    var body: some View {
        ZStack {
            Color.black.opacity(0.2)
                .contentShape(Rectangle())
                .onTapGesture(perform: dismiss)

            VStack(spacing: 16) {
                Image(systemName: "shield.slash")
                    .font(.system(size: 34))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.secondary)

                VStack(spacing: 6) {
                    Text("Disable blocking?").font(.headline)
                    Text("Type \"\(disablePhrase)\" to confirm.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }

                TextField(disablePhrase, text: $typed, prompt: Text(verbatim: ""))
                    .textFieldStyle(.roundedBorder)
                    .multilineTextAlignment(.center)
                    .focused($focused)
                    .onSubmit(attemptConfirm)

                HStack {
                    Button("Cancel", role: .cancel, action: dismiss)
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Disable", role: .destructive, action: attemptConfirm)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!matches)
                }
            }
            .padding(20)
            .frame(width: 280)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
            .shadow(radius: 20)
        }
        // Deferred to the next runloop: a same-cycle set runs before the field is
        // installed as first responder, so the panel's "Site to block" field keeps
        // focus. The next tick lets focus arbitration settle onto this field.
        .onAppear {
            DispatchQueue.main.async { focused = true }
        }
    }

    private func attemptConfirm() {
        guard matches else { return }
        confirm()
        dismiss()
    }
}
