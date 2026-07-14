import AppKit
import SwiftUI

@main
struct AntiRotApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    /// `LSUIElement` keeps the app out of the Dock, so this scene is the only
    /// way in, and it carries its own Quit.
    var body: some Scene {
        MenuBarExtra {
            ContentView()
                .environment(delegate.controller)
        } label: {
            MenuBarIcon()
                .environment(delegate.controller)
        }
        .menuBarExtraStyle(.window)
    }
}

/// A view, not an `Image` inlined into the scene, so `isFilterEnabled` is
/// observed in a view body and the icon repaints.
private struct MenuBarIcon: View {
    @Environment(FilterController.self) private var controller

    var body: some View {
        Image(systemName: controller.shieldSymbol)
    }
}

/// Owns the controller, and drives the lifecycle at both ends: running means
/// blocking, so launching enables the filter and quitting disables it.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let controller = FilterController()
    private var isTerminating = false
    private static let quitTimeout = Duration.seconds(5)

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { await controller.enableOnLaunch() }
    }

    /// The config save is async, so the exit is deferred until it lands, but
    /// never past `quitTimeout`: with no Dock icon there is no Force Quit to
    /// fall back on if the NetworkExtension daemon stalls, and a hung quit would
    /// block logout. The extension itself stays installed.
    func applicationShouldTerminate(_ app: NSApplication) -> NSApplication.TerminateReply {
        guard !isTerminating else { return .terminateLater }
        isTerminating = true
        Task {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await self.controller.stopFiltering() }
                group.addTask { try? await Task.sleep(for: Self.quitTimeout) }
                await group.next()
                group.cancelAll()
            }
            app.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
