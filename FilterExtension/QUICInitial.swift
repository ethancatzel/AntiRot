import Foundation
import CryptoKit
import CommonCrypto

/// Decrypts a QUIC v1 client **Initial** packet (RFC 9000/9001) far enough to
/// recover the TLS ClientHello carried in its CRYPTO frames. The Initial keys
/// are derived from a public salt + the Destination Connection ID, so anyone on
/// the path can read it — that's what lets us see the SNI without MITM.
///
/// Scope: QUIC v1, the first client Initial datagram (the common case where the
/// whole ClientHello fits in one packet's CRYPTO frames). Other versions, ECH,
/// or a ClientHello split across datagrams return nil → the flow is allowed.
enum QUICInitial {

    // RFC 9001 §5.2 — initial salt for QUIC v1.
    private static let initialSalt: [UInt8] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ]

    static func clientHelloHandshake(_ datagram: Data) -> Data? {
        let p = [UInt8](datagram)
        guard p.count > 7 else { return nil }

        // Long header (0x80), fixed bit (0x40), Initial packet type (bits 0x30 == 0).
        let first = p[0]
        guard first & 0x80 != 0, first & 0x30 == 0 else { return nil }

        // Version must be QUIC v1 (0x00000001).
        let version = UInt32(p[1]) << 24 | UInt32(p[2]) << 16 | UInt32(p[3]) << 8 | UInt32(p[4])
        guard version == 1 else { return nil }

        var i = 5
        let dcidLen = Int(p[i]); i += 1
        guard i + dcidLen <= p.count else { return nil }
        let dcid = Array(p[i..<i + dcidLen]); i += dcidLen

        guard i < p.count else { return nil }
        let scidLen = Int(p[i]); i += 1 + scidLen
        guard i <= p.count else { return nil }

        guard let (tokenLen, tlBytes) = varint(p, i) else { return nil }
        i += tlBytes + Int(tokenLen)
        guard let (remLen, lenBytes) = varint(p, i) else { return nil }
        i += lenBytes

        let pnOffset = i
        let payloadEnd = pnOffset + Int(remLen)
        guard payloadEnd <= p.count else { return nil }

        guard let keys = deriveClientInitialKeys(dcid: dcid) else { return nil }

        // Remove header protection: AES-ECB the 16-byte sample at pnOffset+4.
        let sampleStart = pnOffset + 4
        guard sampleStart + 16 <= p.count,
              let mask = aesECB(key: keys.hp, block: Array(p[sampleStart..<sampleStart + 16]))
        else { return nil }

        let firstUnmasked = first ^ (mask[0] & 0x0f)        // long header: low 4 bits
        let pnLen = Int(firstUnmasked & 0x03) + 1
        guard pnOffset + pnLen <= p.count else { return nil }

        var pnBytes = Array(p[pnOffset..<pnOffset + pnLen])
        for j in 0..<pnLen { pnBytes[j] ^= mask[1 + j] }
        var pn: UInt64 = 0
        for byte in pnBytes { pn = (pn << 8) | UInt64(byte) }

        // AAD = header through the (unprotected) packet number.
        var header = Array(p[0..<pnOffset + pnLen])
        header[0] = firstUnmasked
        for j in 0..<pnLen { header[pnOffset + j] = pnBytes[j] }

        // Ciphertext follows the packet number; trailing 16 bytes are the GCM tag.
        let ctStart = pnOffset + pnLen
        guard payloadEnd - ctStart > 16 else { return nil }
        let ct = Array(p[ctStart..<payloadEnd - 16])
        let tag = Array(p[payloadEnd - 16..<payloadEnd])

        // Nonce = iv XOR packet-number (right-aligned in 12 bytes).
        var nonce = keys.iv
        let pnBE = bigEndianBytes(pn)
        for j in 0..<8 { nonce[12 - 8 + j] ^= pnBE[j] }

        guard let plaintext = aesGCMOpen(key: keys.key, nonce: nonce, ct: ct, tag: tag, aad: header)
        else { return nil }

        return reassembleCryptoFrames(plaintext)
    }

    // MARK: - Key derivation (HKDF-SHA256, RFC 9001 §5.1)

    private struct Keys { let key: [UInt8]; let iv: [UInt8]; let hp: [UInt8] }

    private static func deriveClientInitialKeys(dcid: [UInt8]) -> Keys? {
        let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: Data(dcid)),
                                       salt: Data(initialSalt))
        let client = HKDF<SHA256>.expand(pseudoRandomKey: prk,
                                         info: Data(hkdfLabel("client in", 32)),
                                         outputByteCount: 32)
        func derive(_ label: String, _ length: Int) -> [UInt8] {
            HKDF<SHA256>.expand(pseudoRandomKey: client,
                                info: Data(hkdfLabel(label, length)),
                                outputByteCount: length)
                .withUnsafeBytes(Array.init)
        }
        return Keys(key: derive("quic key", 16), iv: derive("quic iv", 12), hp: derive("quic hp", 16))
    }

    /// TLS 1.3 HKDF-Expand-Label structure with an empty context (RFC 8446 §7.1).
    private static func hkdfLabel(_ label: String, _ length: Int) -> [UInt8] {
        let full = Array("tls13 \(label)".utf8)
        var out: [UInt8] = [UInt8(length >> 8), UInt8(length & 0xff), UInt8(full.count)]
        out.append(contentsOf: full)
        out.append(0)                                        // empty context
        return out
    }

    // MARK: - Frame reassembly

    /// Walk the decrypted payload's frames and concatenate CRYPTO data in offset
    /// order. A client's first Initial carries only PADDING/PING/CRYPTO frames,
    /// so an unrecognised frame type ends parsing.
    private static func reassembleCryptoFrames(_ b: [UInt8]) -> Data? {
        var chunks: [(offset: UInt64, data: [UInt8])] = []
        var i = 0
        loop: while i < b.count {
            let type = b[i]
            switch type {
            case 0x00, 0x01:                                 // PADDING, PING
                i += 1
            case 0x06:                                       // CRYPTO
                i += 1
                guard let (offset, ob) = varint(b, i) else { break loop }; i += ob
                guard let (length, lb) = varint(b, i) else { break loop }; i += lb
                let len = Int(length)
                guard i + len <= b.count else { break loop }
                chunks.append((offset, Array(b[i..<i + len])))
                i += len
            default:
                break loop
            }
        }
        guard !chunks.isEmpty else { return nil }

        chunks.sort { $0.offset < $1.offset }
        var out: [UInt8] = []
        for chunk in chunks {
            if Int(chunk.offset) == out.count { out.append(contentsOf: chunk.data) }
            else if Int(chunk.offset) > out.count { break }  // gap — can't continue
        }
        return out.isEmpty ? nil : Data(out)
    }

    // MARK: - Primitives

    /// QUIC variable-length integer: top 2 bits encode the length (1/2/4/8 bytes).
    private static func varint(_ b: [UInt8], _ i: Int) -> (value: UInt64, bytes: Int)? {
        guard i < b.count else { return nil }
        let len = 1 << Int(b[i] >> 6)
        guard i + len <= b.count else { return nil }
        var v = UInt64(b[i] & 0x3f)
        for j in 1..<len { v = (v << 8) | UInt64(b[i + j]) }
        return (v, len)
    }

    /// Single-block AES-128 in ECB mode (CryptoKit has no ECB; CommonCrypto does).
    private static func aesECB(key: [UInt8], block: [UInt8]) -> [UInt8]? {
        guard key.count == 16, block.count == 16 else { return nil }
        var out = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                             CCOptions(kCCOptionECBMode),
                             key, key.count, nil,
                             block, block.count,
                             &out, out.count, &moved)
        return status == kCCSuccess ? out : nil
    }

    private static func aesGCMOpen(key: [UInt8], nonce: [UInt8], ct: [UInt8],
                                   tag: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard let n = try? AES.GCM.Nonce(data: Data(nonce)),
              let box = try? AES.GCM.SealedBox(nonce: n, ciphertext: Data(ct), tag: Data(tag)),
              let pt = try? AES.GCM.open(box, using: SymmetricKey(data: Data(key)),
                                         authenticating: Data(aad))
        else { return nil }
        return [UInt8](pt)
    }

    private static func bigEndianBytes(_ v: UInt64) -> [UInt8] {
        (0..<8).map { UInt8((v >> (8 * (7 - $0))) & 0xff) }
    }
}
