import NetworkExtension
import os

/// Content filter. For a TCP/443 flow we peek the first outbound bytes — the TLS
/// ClientHello — read the SNI hostname, and drop if it's blocked. Matching on the
/// hostname in the handshake makes this immune to IP rotation, IPv6, and DNS
/// caching, with no DNS proxy and no browser configuration. QUIC (UDP/443) is
/// dropped so browsers fall back to TCP/TLS where we can read the name. The
/// residual blind spot is ECH (encrypted ClientHello); see AGENTS.md.
final class FilterDataProvider: NEFilterDataProvider {

    private let log = Logger(subsystem: "com.ethancatzel.AntiRot", category: "filter")

    /// Enough to hold a TLS ClientHello or a QUIC Initial datagram.
    private let peekBytes = 4096

    /// The blocklist the app handed us through the filter configuration. (The
    /// extension runs as root and can't read the app's storage, so the list
    /// travels via vendorConfiguration.)
    private var blocklist: [String] {
        filterConfiguration.vendorConfiguration?["domains"] as? [String] ?? []
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let rule = NENetworkRule(
            remoteNetwork: nil, remotePrefix: 0,
            localNetwork: nil, localPrefix: 0,
            protocol: .any, direction: .outbound)
        let settings = NEFilterSettings(
            rules: [NEFilterRule(networkRule: rule, action: .filterData)],
            defaultAction: .allow)

        apply(settings) { error in
            if let error { self.log.error("startFilter failed: \(error.localizedDescription)") }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow,
              let endpoint = socketFlow.remoteEndpoint as? NWHostEndpoint,
              endpoint.port == "443" else {
            return .allow()
        }
        // QUIC (UDP/443): its SNI is inside an encrypted Initial we can't reliably
        // read, so drop it. Browsers fall back to TCP/TLS, where we block by SNI.
        if socketFlow.socketProtocol == IPPROTO_UDP {
            return .drop()
        }
        // TCP/443: defer the verdict until we've seen the ClientHello in the
        // first outbound write (see handleOutboundData).
        return .filterDataVerdict(withFilterInbound: false, peekInboundBytes: 0,
                                  filterOutbound: true, peekOutboundBytes: peekBytes)
    }

    override func handleOutboundData(from flow: NEFilterFlow,
                                     readBytesStartOffset offset: Int,
                                     readBytes: Data) -> NEFilterDataVerdict {
        // Only TCP/443 flows reach here (QUIC is dropped in handleNewFlow), so
        // the bytes are a TLS ClientHello.
        if let host = SNIInspector.serverNameFromTLS(readBytes),
           Blocklist.isBlocked(host, in: blocklist) {
            log.info("blocked \(host, privacy: .public)")
            return .drop()
        }
        return .allow()
    }
}
