import Foundation

/// Extracts the SNI `server_name` from a TLS ClientHello. All parsing is
/// bounds-checked; any malformed or non-ClientHello input returns nil
/// (→ the flow is allowed).
enum SNIInspector {

    /// A TLS record (type 0x16, handshake) wrapping the ClientHello.
    static func serverNameFromTLS(_ data: Data) -> String? {
        let b = [UInt8](data)
        guard b.count > 5, b[0] == 0x16 else { return nil }  // handshake record
        return sniFromHandshake(b, start: 5)                 // skip 5-byte record header
    }

    /// Parse a handshake message at `start`: type(1)=0x01 ClientHello, length(3),
    /// then the body, walking to the server_name extension (type 0x0000).
    private static func sniFromHandshake(_ b: [UInt8], start: Int) -> String? {
        var i = start
        guard i + 4 <= b.count, b[i] == 0x01 else { return nil }  // ClientHello
        i += 4                                                     // type(1) + length(3)
        i += 34                                                    // version(2) + random(32)

        guard i < b.count else { return nil }
        i += 1 + Int(b[i])                                         // session_id
        guard i + 2 <= b.count else { return nil }
        i += 2 + be16(b, i)                                        // cipher_suites
        guard i < b.count else { return nil }
        i += 1 + Int(b[i])                                         // compression_methods

        guard i + 2 <= b.count else { return nil }
        let extEnd = min(i + 2 + be16(b, i), b.count)
        i += 2
        while i + 4 <= extEnd {
            let type = be16(b, i)
            let len = be16(b, i + 2)
            i += 4
            if type == 0x0000 { return hostName(b, start: i, len: len) }
            i += len
        }
        return nil
    }

    /// server_name extension: list length(2), entry { name_type(1)=0, length(2), name }.
    private static func hostName(_ b: [UInt8], start: Int, len: Int) -> String? {
        var i = start
        let end = min(start + len, b.count)
        guard i + 2 <= end else { return nil }
        i += 2                                                     // server_name_list length
        guard i + 3 <= end, b[i] == 0 else { return nil }          // name_type == host_name
        i += 1
        let nameLen = be16(b, i)
        i += 2
        guard i + nameLen <= end else { return nil }
        return String(bytes: b[i..<i + nameLen], encoding: .utf8)
    }

    /// Read a big-endian 16-bit field at `i` (a length or extension type). Callers
    /// bounds-check that `i + 2 <= count` before reading.
    private static func be16(_ b: [UInt8], _ i: Int) -> Int {
        Int(b[i]) << 8 | Int(b[i + 1])
    }
}
