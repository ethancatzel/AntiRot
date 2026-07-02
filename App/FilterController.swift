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

    var status = "Idle"
    var isFilterEnabled = false

    private enum Operation: Equatable { case activate, deactivate }
    @ObservationIgnored private var pending: Operation?
    private let extensionID = "com.ethancatzel.AntiRot.FilterExtension"
    private let log = Logger(subsystem: "com.ethancatzel.AntiRot", category: "controller")

    // MARK: Step 1 — system extension

    func activate() {
        pending = .activate
        submit(.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main),
               status: "Requesting activation…")
    }

    /// Turn filtering off first, then remove the extension, for a clean teardown.
    func deactivate() {
        Task {
            await applyFilter(enabled: false)
            pending = .deactivate
            submit(.deactivationRequest(forExtensionWithIdentifier: extensionID, queue: .main),
                   status: "Removing extension…")
        }
    }

    private func submit(_ request: OSSystemExtensionRequest, status: String) {
        self.status = status
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: Step 2 — filter configuration

    func enableFilter() { Task { await applyFilter(enabled: true) } }
    func disableFilter() { Task { await applyFilter(enabled: false) } }

    /// Reconcile `isFilterEnabled` with the system-persisted filter state on
    /// cold start. `NEFilterManager.saveToPreferences()` already remembers the
    /// enabled state across launches; this just reads it back.
    func syncEnabledState() async {
        let mgr = NEFilterManager.shared()
        try? await mgr.loadFromPreferences()
        isFilterEnabled = mgr.isEnabled
    }

    /// Push the current blocklist to the running extension. The extension runs as
    /// root and can't read the app's storage, so the list travels through the
    /// filter's `vendorConfiguration`. Call this after the user edits the list.
    func syncBlocklist() {
        Task {
            let mgr = NEFilterManager.shared()
            do {
                try await mgr.loadFromPreferences()
                guard mgr.isEnabled, let config = mgr.providerConfiguration else { return }
                config.vendorConfiguration = ["domains": Blocklist.domains]
                mgr.providerConfiguration = config
                // Saving a changed config doesn't reload the running provider, so
                // bounce isEnabled to restart it with the new list (what your
                // manual off/on did).
                mgr.isEnabled = false
                try await mgr.saveToPreferences()
                mgr.isEnabled = true
                try await mgr.saveToPreferences()
            } catch {
                status = "blocklist sync error: \(error.localizedDescription)"
            }
        }
    }

    /// Load the shared filter config, set the blocklist, flip its enabled state,
    /// and save. Using async/await keeps every state mutation on the main actor —
    /// `await` resumes here because this is a `@MainActor` type.
    private func applyFilter(enabled: Bool) async {
        let mgr = NEFilterManager.shared()
        do {
            try await mgr.loadFromPreferences()
            let config = mgr.providerConfiguration ?? NEFilterProviderConfiguration()
            config.filterSockets = true
            config.filterPackets = false
            config.vendorConfiguration = ["domains": Blocklist.domains]
            mgr.providerConfiguration = config
            mgr.localizedDescription = "AntiRot"
            mgr.isEnabled = enabled
            try await mgr.saveToPreferences()
            isFilterEnabled = enabled
            status = enabled ? "Filter enabled" : "Filter disabled"
        } catch {
            status = "filter error: \(error.localizedDescription)"
        }
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension FilterController: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        MainActor.assumeIsolated {
            log.info("request result: \(result.rawValue)")
            if pending == .deactivate {
                isFilterEnabled = false
                status = "Extension removed"
            } else {
                status = "Extension activated — now enable the filter"
                if result == .completed { enableFilter() }
            }
            pending = nil
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        MainActor.assumeIsolated {
            let verb = pending == .deactivate ? "Deactivation" : "Activation"
            status = "\(verb) failed: \(error.localizedDescription)"
            pending = nil
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
