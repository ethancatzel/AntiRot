import Foundation
import NetworkExtension

// A NetworkExtension system extension is a plain executable, so it needs an
// explicit entry point (unlike an app extension, which gets one generated).
// `startSystemExtensionMode()` boots the NE runtime, which then instantiates
// the provider class named in Info.plist (FilterDataProvider) to handle flows.
// `dispatchMain()` parks the main thread so the process stays alive.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
