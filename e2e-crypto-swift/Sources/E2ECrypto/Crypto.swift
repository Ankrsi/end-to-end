import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Raw 32-byte keys, interchangeable with the JS and Kotlin packages.
public struct KeyPair {
    public let publicKey: Data
    public let privateKey: Data
    public init(publicKey: Data, privateKey: Data) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

/// X25519 key agreement and Ed25519 signatures (CryptoKit).
public enum Curve {
    public static func generateX25519KeyPair() -> KeyPair {
        let k = Curve25519.KeyAgreement.PrivateKey()
        return KeyPair(publicKey: k.publicKey.rawRepresentation, privateKey: k.rawRepresentation)
    }

    public static func x25519PublicKey(privateKey: Data) throws -> Data {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation
    }

    public static func dh(privateKey: Data, publicKey: Data) throws -> Data {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
        return secret.withUnsafeBytes { Data($0) }
    }

    public static func generateEd25519KeyPair() -> KeyPair {
        let k = Curve25519.Signing.PrivateKey()
        return KeyPair(publicKey: k.publicKey.rawRepresentation, privateKey: k.rawRepresentation)
    }

    public static func ed25519PublicKey(privateKey: Data) throws -> Data {
        try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation
    }

    public static func sign(privateKey: Data, data: Data) throws -> Data {
        try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey).signature(for: data)
    }

    /// A malformed key or signature is just an invalid signature.
    public static func verify(publicKey: Data, data: Data, signature: Data) -> Bool {
        guard let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return pk.isValidSignature(signature, for: data)
    }
}

/// HKDF-SHA256 and the Double Ratchet KDFs — same constants as the JS package.
public enum Kdf {
    public static func hmac(key: Data, data: Data) -> Data {
        // An empty HMAC key equals 32 zero bytes (both are zero-padded to the block size).
        let k = key.isEmpty ? Data(count: 32) : key
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: k)))
    }

    public static func hkdf(ikm: Data, salt: Data, info: String, length: Int) -> Data {
        let prk = hmac(key: salt, data: ikm)
        let infoBytes = info.utf8Data
        var out = Data()
        var t = Data()
        var counter: UInt8 = 1
        while out.count < length {
            t = hmac(key: prk, data: t + infoBytes + Data([counter]))
            out.append(t)
            counter += 1
        }
        return out.prefix(length)
    }

    /// KDF_RK: advances the root key with a new DH output.
    public static func rootKey(_ rootKey: Data, _ dhOutput: Data) -> (rootKey: Data, chainKey: Data) {
        let out = hkdf(ikm: dhOutput, salt: rootKey, info: "E2EChat-RootRatchet", length: 64)
        return (Data(out.prefix(32)), Data(out.suffix(32)))
    }

    /// KDF_CK: one symmetric ratchet step (shared by the 1:1 ratchet and Sender Keys).
    public static func chainKey(_ chainKey: Data) -> (chainKey: Data, messageKey: Data) {
        (hmac(key: chainKey, data: Data([0x02])), hmac(key: chainKey, data: Data([0x01])))
    }
}

/// AES-256-GCM with key + IV derived from a single-use message key. Output is ciphertext || 16-byte tag.
public enum Aead {
    private static func derive(_ messageKey: Data) -> (key: Data, iv: Data) {
        let out = Kdf.hkdf(ikm: messageKey, salt: Data(), info: "E2EChat-MsgKey", length: 44)
        return (Data(out.prefix(32)), Data(out.suffix(12)))
    }

    public static func encrypt(messageKey: Data, plaintext: Data, associatedData: Data = Data()) throws -> Data {
        let (key, iv) = derive(messageKey)
        return try seal(key: key, iv: iv, plaintext: plaintext, aad: associatedData)
    }

    /// Throws if the ciphertext, tag or associated data were tampered with.
    public static func decrypt(messageKey: Data, blob: Data, associatedData: Data = Data()) throws -> Data {
        let (key, iv) = derive(messageKey)
        return try open(key: key, iv: iv, blob: blob, aad: associatedData)
    }

    static func seal(key: Data, iv: Data, plaintext: Data, aad: Data = Data()) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: iv), authenticating: aad)
        return box.ciphertext + box.tag
    }

    static func open(key: Data, iv: Data, blob: Data, aad: Data = Data()) throws -> Data {
        guard blob.count >= 16 else { throw E2EError.decryptFailed("ciphertext too short") }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: blob.prefix(blob.count - 16), tag: blob.suffix(16))
        do {
            return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
        } catch {
            throw E2EError.decryptFailed("authentication failed")
        }
    }
}
