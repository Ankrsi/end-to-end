import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(FoundationNetworking)
import FoundationNetworking // URLSession on Linux
#endif

// Chat photos, videos, voice notes and files are locked on the phone before upload (like WhatsApp):
//   1. every file gets its own new random key
//   2. the file is locked with that key, and only the locked copy is uploaded
//   3. the key goes inside the chat message, which is end-to-end encrypted
// So the server stores files it can't open, and never sees the keys.
//
// Locked file = nonce (24 bytes) + XChaCha20-Poly1305 ciphertext. Same format as the JS package.

/// `data` is uploaded; `key` is sent inside the e2e chat message (e.g. Base64.encode(key)).
public struct EncryptedFile {
    public let key: Data
    public let data: Data
}

/// An unlocked file. `type` is the url's extension, e.g. "mp4", "pdf", "jpeg", "png" ("" if none).
public struct DecryptedFile {
    public let data: Data
    public let type: String
}

public enum MediaError: Error {
    case invalidFile
    case downloadFailed(status: Int)
}

public enum Media {
    private static let nonceLength = 24

    public static func encryptFile(_ fileBytes: Data) throws -> EncryptedFile {
        let key = Data.random(32)
        let nonce = Data.random(nonceLength)
        let box = try ChaChaPoly.seal(fileBytes, using: subKey(key, nonce), nonce: subNonce(nonce))
        return EncryptedFile(key: key, data: nonce + box.ciphertext + box.tag)
    }

    /// Downloads the locked file from `url`, unlocks it, and returns the data plus `type`: the url's
    /// extension (mp4, pdf, jpeg, png, ...), or "" if it has none. `key` is the base64 key from the chat message.
    /// Throws if the download fails, the key is wrong or the file was changed.
    public static func decryptFile(key: String, url: URL) async throws -> DecryptedFile {
        let locked: Data = try await withCheckedThrowingContinuation { cont in
            URLSession.shared.dataTask(with: url) { data, response, error in
                if let error = error { return cont.resume(throwing: error) }
                if let http = response as? HTTPURLResponse, !(200 ..< 300).contains(http.statusCode) {
                    return cont.resume(throwing: MediaError.downloadFailed(status: http.statusCode))
                }
                cont.resume(returning: data ?? Data())
            }.resume()
        }
        return DecryptedFile(data: try unlock(key: Base64.decode(key), data: locked),
                             type: url.pathExtension.lowercased())
    }

    /// Throws if the key is wrong or the file was changed.
    static func unlock(key: Data, data: Data) throws -> Data {
        let data = Data(data) // re-base indices to 0
        guard key.count == 32, data.count >= nonceLength + 16 else { throw MediaError.invalidFile }
        let nonce = data.prefix(nonceLength)
        let box = try ChaChaPoly.SealedBox(
            nonce: subNonce(nonce),
            ciphertext: data[nonceLength ..< data.count - 16],
            tag: data.suffix(16))
        return try ChaChaPoly.open(box, using: subKey(key, nonce))
    }

    // XChaCha20-Poly1305 = ChaCha20-Poly1305 with key HChaCha20(key, nonce[0..16]) and nonce 0000 + nonce[16..24].
    private static func subKey(_ key: Data, _ nonce: Data) -> SymmetricKey {
        SymmetricKey(data: hchacha20(Array(key), Array(nonce.prefix(16))))
    }

    private static func subNonce(_ nonce: Data) throws -> ChaChaPoly.Nonce {
        try ChaChaPoly.Nonce(data: Data(count: 4) + nonce.suffix(8))
    }

    private static func hchacha20(_ key: [UInt8], _ nonce: [UInt8]) -> [UInt8] {
        func le(_ b: [UInt8], _ i: Int) -> UInt32 {
            UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
        }
        func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }
        var s: [UInt32] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        for i in 0 ..< 8 { s.append(le(key, i * 4)) }
        for i in 0 ..< 4 { s.append(le(nonce, i * 4)) }
        func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            s[a] &+= s[b]; s[d] = rotl(s[d] ^ s[a], 16)
            s[c] &+= s[d]; s[b] = rotl(s[b] ^ s[c], 12)
            s[a] &+= s[b]; s[d] = rotl(s[d] ^ s[a], 8)
            s[c] &+= s[d]; s[b] = rotl(s[b] ^ s[c], 7)
        }
        for _ in 0 ..< 10 {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        var out = [UInt8]()
        for w in [0, 1, 2, 3, 12, 13, 14, 15] {
            for k in 0 ..< 4 { out.append(UInt8(truncatingIfNeeded: s[w] >> (8 * k))) }
        }
        return out
    }
}
