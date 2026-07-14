import Foundation
import SystemExtensions
import NetworkExtension
import os

/// Drives the two-step lifecycle:
///   1. Activate the *system extension* (OSSystemExtensionRequest) — user approves once.
///   2. Enable the *filter configuration* (NEFilterManager) — turns filtering on.
/// Requests are submitted with `queue: .main`, so the delegate callbacks below
/// run on the main actor (asserted via `MainActor.assumeIsolated`).
@Observable
@MainActor
final class FilterController: NSObject {

    var status = ""
    var isFilterEnabled = false

    var shieldSymbol: String {
        isFilterEnabled ? "shield.lefthalf.filled" : "shield.slash"
    }

    /// The blocklist, owned here so the UI stays a plain rendering of it. All
    /// edits go through `addSite`/`removeSite`, which normalize and dedup;
    /// every change persists locally and pushes to the running extension.
    private(set) var domains: [String] = Blocklist.domains {
        didSet {
            Blocklist.domains = domains
            syncBlocklist()
        }
    }

    func addSite(_ raw: String) {
        let site = raw.trimmingCharacters(in: .whitespaces).lowercased()
        guard !site.isEmpty, !domains.contains(site) else { return }
        domains.append(site)
    }

    func removeSite(_ site: String) {
        domains.removeAll { $0 == site }
    }

    private enum Operation: Equatable { case activate, deactivate }
    @ObservationIgnored private var pending: [ObjectIdentifier: Operation] = [:]
    @ObservationIgnored private var isStopping = false
    private let extensionID = "com.ethancatzel.AntiRot.FilterExtension"
    private let log = Logger(subsystem: "com.ethancatzel.AntiRot", category: "controller")

    /// Every `NEFilterManager` mutation is queued here and runs alone. The
    /// manager is a process-wide singleton and each step awaits IPC, so
    /// concurrent callers interleave and the last save silently wins.
    @ObservationIgnored private var work: Task<Void, Never> = Task {}

    @discardableResult
    private func serialized(_ step: @escaping () async -> Void) -> Task<Void, Never> {
        let previous = work
        let task = Task { @MainActor in
            await previous.value
            await step()
        }
        work = task
        return task
    }

    // MARK: Step 1 — system extension

    func activate() {
        submit(.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main),
               operation: .activate, status: "Requesting activation…")
    }

    /// Turn filtering off first, then remove the extension, for a clean teardown.
    func deactivate() {
        serialized {
            await self.applyFilter(enabled: false)
            self.submit(.deactivationRequest(forExtensionWithIdentifier: self.extensionID, queue: .main),
                        operation: .deactivate, status: "Removing extension…")
        }
    }

    /// Keyed by request: an activation awaiting approval can still be in flight
    /// when a deactivation is submitted, so a single slot would misattribute the
    /// results.
    private func submit(_ request: OSSystemExtensionRequest, operation: Operation, status: String) {
        pending[ObjectIdentifier(request)] = operation
        self.status = status
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: Step 2 — filter configuration

    func setFilter(enabled: Bool) {
        guard !(isStopping && enabled) else { return }
        serialized { await self.applyFilter(enabled: enabled) }
    }

    /// The quit path. Queues behind any in-flight work, then waits for the save,
    /// because the process exits as soon as this returns. `isStopping` keeps a
    /// late activation callback from enabling the filter on the way out.
    func stopFiltering() async {
        isStopping = true
        await serialized { await self.applyFilter(enabled: false) }.value
    }

    /// Running means blocking. Activation is idempotent, so asking for it every
    /// launch also heals a missing or stale extension, and its result enables
    /// the filter.
    func enableOnLaunch() async {
        let mgr = NEFilterManager.shared()
        try? await mgr.loadFromPreferences()
        isFilterEnabled = mgr.isEnabled
        activate()
    }

    private func applyFilter(enabled: Bool) async {
        do {
            let mgr = try await configuredManager()
            mgr.isEnabled = enabled
            try await mgr.saveToPreferences()
            isFilterEnabled = enabled
            status = ""
        } catch {
            status = "Filter error: \(error.localizedDescription)"
        }
    }

    /// Push a blocklist edit to the running extension. Saving a changed config
    /// doesn't reload the provider, so bounce `isEnabled` off then on to restart
    /// it with the new list.
    private func syncBlocklist() {
        guard isFilterEnabled else { return }
        serialized {
            do {
                let mgr = try await self.configuredManager()
                mgr.isEnabled = false
                try await mgr.saveToPreferences()
                mgr.isEnabled = true
                try await mgr.saveToPreferences()
            } catch {
                self.status = "Blocklist sync error: \(error.localizedDescription)"
            }
        }
    }

    /// Load the shared filter config and set the blocklist on it. The extension
    /// runs as root and can't read the app's storage, so the list travels
    /// through the config's `vendorConfiguration`. Async/await keeps every
    /// state mutation on the main actor — `await` resumes here because this is
    /// a `@MainActor` type.
    private func configuredManager() async throws -> NEFilterManager {
        let mgr = NEFilterManager.shared()
        try await mgr.loadFromPreferences()
        let config = mgr.providerConfiguration ?? NEFilterProviderConfiguration()
        config.filterSockets = true
        config.filterPackets = false
        config.vendorConfiguration = ["domains": domains]
        mgr.providerConfiguration = config
        mgr.localizedDescription = "AntiRot"
        return mgr
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension FilterController: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        MainActor.assumeIsolated {
            log.info("request result: \(result.rawValue)")
            if pending.removeValue(forKey: ObjectIdentifier(request)) == .deactivate {
                status = "Extension removed"
            } else if result == .completed {
                status = "Extension activated"
                setFilter(enabled: true)
            } else {
                status = "Extension activates after a reboot"
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        MainActor.assumeIsolated {
            let operation = pending.removeValue(forKey: ObjectIdentifier(request))
            let verb = operation == .deactivate ? "Deactivation" : "Activation"
            status = "\(verb) failed: \(error.localizedDescription)"
        }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        MainActor.assumeIsolated {
            status = "Approve in System Settings → General → Login Items & Extensions"
        }
    }

    /// Called when a different version is already installed; replace it.
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
}
