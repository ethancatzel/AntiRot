import SwiftUI

/// Native macOS control panel in the System Settings idiom: a grouped `Form`
/// headed by a status row with the master switch, the way the Firewall and VPN
/// panes work. Blocklist edits apply immediately; there is no Save button.
struct ContentView: View {
    @Environment(FilterController.self) private var controller
    @State private var newSite = ""

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
                Text(verbatim: "Subdomains are blocked too (e.g. x.com also blocks www.x.com).")
                    .foregroundStyle(.secondary)
            }

            Section {
                LabeledContent("System extension") {
                    HStack(spacing: 8) {
                        Button("Activate") { controller.activate() }
                        Button("Deactivate") { controller.deactivate() }
                    }
                }
            } footer: {
                Text("AntiRot filters network traffic with a system extension. You'll approve it once in System Settings.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 480, minHeight: 540)
        .task { await controller.syncEnabledState() }
    }

    /// The pane's identity: a shield that fills in when protection is on, the
    /// current state in words, and the master switch.
    private var statusRow: some View {
        HStack(spacing: 14) {
            Image(systemName: controller.isFilterEnabled ? "shield.lefthalf.filled" : "shield.slash")
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

    /// A switch that drives the two filter actions; its read reflects live state.
    private var filterEnabled: Binding<Bool> {
        Binding(get: { controller.isFilterEnabled },
                set: { $0 ? controller.enableFilter() : controller.disableFilter() })
    }

    private func add() {
        controller.addSite(newSite)
        newSite = ""
    }
}
