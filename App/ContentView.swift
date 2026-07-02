import SwiftUI

/// Native macOS control panel, modeled on the System Settings idiom: a grouped
/// `Form` of system controls. Changes to the blocklist apply immediately (no
/// Save button), as Mac settings conventionally do.
struct ContentView: View {
    @Environment(FilterController.self) private var controller
    @State private var sites: [String] = Blocklist.domains
    @State private var newSite = ""

    var body: some View {
        Form {
            Section {
                LabeledContent("Status") {
                    Label(controller.isFilterEnabled ? "Blocking" : "Idle",
                          systemImage: controller.isFilterEnabled ? "shield.lefthalf.filled" : "shield.slash")
                        .foregroundStyle(controller.isFilterEnabled ? Color.green : .secondary)
                }
                Toggle("Block distracting sites", isOn: filterEnabled)
            } header: {
                Text("Protection")
            } footer: {
                Text(controller.status).foregroundStyle(.secondary)
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

            Section("Blocked Sites") {
                if sites.isEmpty {
                    Text("No sites blocked yet.").foregroundStyle(.secondary)
                }
                ForEach(sites, id: \.self) { site in
                    HStack {
                        Text(site).monospaced()
                        Spacer()
                        Button(role: .destructive) {
                            remove(site)
                        } label: {
                            Image(systemName: "minus.circle.fill")
                        }
                        .buttonStyle(.borderless)
                        .foregroundStyle(.secondary)
                        .help("Remove \(site)")
                    }
                }
                HStack {
                    TextField("Add a site — e.g. example.com", text: $newSite)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(add)
                    Button("Add", action: add).disabled(cleaned.isEmpty)
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 480, minHeight: 540)
        .task { await controller.syncEnabledState() }
    }

    /// A switch that drives the two filter actions; its read reflects live state.
    private var filterEnabled: Binding<Bool> {
        Binding(get: { controller.isFilterEnabled },
                set: { $0 ? controller.enableFilter() : controller.disableFilter() })
    }

    private var cleaned: String {
        newSite.trimmingCharacters(in: .whitespaces).lowercased()
    }

    private func add() {
        let site = cleaned
        guard !site.isEmpty, !sites.contains(site) else { return }
        sites.append(site)
        newSite = ""
        Blocklist.domains = sites
        controller.syncBlocklist()
    }

    private func remove(_ site: String) {
        sites.removeAll { $0 == site }
        Blocklist.domains = sites
        controller.syncBlocklist()
    }
}
