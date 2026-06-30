import SwiftUI

@main
struct AntiRotApp: App {
    @State private var controller = FilterController()

    var body: some Scene {
        WindowGroup("AntiRot") {
            ContentView()
                .environment(controller)
        }
        .windowResizability(.contentSize)
    }
}
