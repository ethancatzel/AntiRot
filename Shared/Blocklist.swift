import Foundation

/// Blocked-domain storage and matching.
///
/// The extension runs as root and can't read the app's files or App Group, so
/// the app does NOT share the list through storage. Instead the app persists the
/// list locally (for the UI) and hands it to the extension through the filter's
/// `vendorConfiguration`. The extension only uses `isBlocked(_:in:)`.
enum Blocklist {
    private static let key = "blockedDomains"

    /// App-local persistence for the UI. Empty until you add sites.
    static var domains: [String] {
        get { UserDefaults.standard.stringArray(forKey: key) ?? [] }
        set { UserDefaults.standard.set(newValue, forKey: key) }
    }

    /// True if `host` equals a domain in `list` or is a subdomain of one
    /// (e.g. "www.x.com" and "api.x.com" both match "x.com").
    static func isBlocked(_ host: String, in list: [String]) -> Bool {
        var h = host.lowercased()
        if h.hasSuffix(".") { h.removeLast() }   // FQDN trailing dot, e.g. "x.com."
        return list.contains { h == $0 || h.hasSuffix("." + $0) }
    }
}
