import Foundation

/// Private, on-device identity. Persist with `X3DH.serializeIdentity` in the Keychain.
public struct Identity {
    public let identitySign: KeyPair
    public let identityDH: KeyPair
    public let signedPreKey: KeyPair
    public let signedPreKeySig: Data
    public let oneTimePreKeys: [KeyPair]
}

/// Public keys only (base64). This is what the server stores.
public struct PublicBundle: Equatable {
    public let identitySignPub: String
    public let identityDHPub: String
    public let signedPreKeyPub: String
    public let signedPreKeySig: String
    public let oneTimePreKeys: [String]
}

public struct HandshakeResult {
    public let sharedSecret: Data
    /// base64 — sent to the responder with the first message
    public let ephemeralPublicRaw: String
    public let usedOneTimePreKeyIndex: Int?
    public let bobSignedPreKeyPublicRaw: Data
}

public enum X3DH {
    public static func createIdentity(oneTimePreKeyCount: Int = 10) throws -> Identity {
        let sign = Curve.generateEd25519KeyPair()
        let spk = Curve.generateX25519KeyPair()
        return Identity(
            identitySign: sign,
            identityDH: Curve.generateX25519KeyPair(),
            signedPreKey: spk,
            signedPreKeySig: try Curve.sign(privateKey: sign.privateKey, data: spk.publicKey),
            oneTimePreKeys: (0..<oneTimePreKeyCount).map { _ in Curve.generateX25519KeyPair() }
        )
    }

    public static func publicBundle(_ id: Identity) -> PublicBundle {
        PublicBundle(
            identitySignPub: id.identitySign.publicKey.b64,
            identityDHPub: id.identityDH.publicKey.b64,
            signedPreKeyPub: id.signedPreKey.publicKey.b64,
            signedPreKeySig: id.signedPreKeySig.b64,
            oneTimePreKeys: id.oneTimePreKeys.map { $0.publicKey.b64 }
        )
    }

    private static func combineDH(_ parts: [Data]) -> Data {
        Kdf.hkdf(ikm: parts.reduce(Data(repeating: 0xff, count: 32), +), salt: Data(count: 32), info: "E2EChat-X3DH", length: 32)
    }

    /// Initiator: verifies the peer's signed prekey, then derives the shared secret.
    public static func initiateHandshake(my: Identity, their: PublicBundle, usedOneTimePreKeyIndex: Int = 0) throws -> HandshakeResult {
        let spk = try their.signedPreKeyPub.unb64()
        guard Curve.verify(publicKey: try their.identitySignPub.unb64(), data: spk, signature: try their.signedPreKeySig.unb64()) else {
            throw E2EError.invalidSignature("Signed prekey signature invalid — possible tampering")
        }
        let theirIk = try their.identityDHPub.unb64()
        let eph = Curve.generateX25519KeyPair()
        var parts = [
            try Curve.dh(privateKey: my.identityDH.privateKey, publicKey: spk),
            try Curve.dh(privateKey: eph.privateKey, publicKey: theirIk),
            try Curve.dh(privateKey: eph.privateKey, publicKey: spk),
        ]
        var used: Int? = nil
        if their.oneTimePreKeys.count > usedOneTimePreKeyIndex {
            parts.append(try Curve.dh(privateKey: eph.privateKey, publicKey: try their.oneTimePreKeys[usedOneTimePreKeyIndex].unb64()))
            used = usedOneTimePreKeyIndex
        }
        return HandshakeResult(sharedSecret: combineDH(parts), ephemeralPublicRaw: eph.publicKey.b64,
                               usedOneTimePreKeyIndex: used, bobSignedPreKeyPublicRaw: spk)
    }

    /// Responder: rebuilds the same shared secret from the initiator's identity + ephemeral keys (base64).
    public static func respondToHandshake(my: Identity, aliceIdentityDHPub: String, aliceEphemeralPub: String, oneTimePreKeyUsed: Int?) throws -> Data {
        let ik = try aliceIdentityDHPub.unb64()
        let ek = try aliceEphemeralPub.unb64()
        var parts = [
            try Curve.dh(privateKey: my.signedPreKey.privateKey, publicKey: ik),
            try Curve.dh(privateKey: my.identityDH.privateKey, publicKey: ek),
            try Curve.dh(privateKey: my.signedPreKey.privateKey, publicKey: ek),
        ]
        if let i = oneTimePreKeyUsed {
            guard i >= 0, i < my.oneTimePreKeys.count else { throw E2EError.invalidKey("Unknown one-time prekey index \(i)") }
            parts.append(try Curve.dh(privateKey: my.oneTimePreKeys[i].privateKey, publicKey: ek))
        }
        return combineDH(parts)
    }

    // MARK: Persistence (same JSON as the JS package). Contains PRIVATE keys: keep in the Keychain.

    private static func pair(_ k: KeyPair) -> JSON {
        .object([("publicKey", .string(k.publicKey.b64)), ("privateKey", .string(k.privateKey.b64))])
    }

    private static func pair(_ o: [String: Any]) throws -> KeyPair {
        KeyPair(publicKey: try o.str("publicKey").unb64(), privateKey: try o.str("privateKey").unb64())
    }

    public static func serializeIdentity(_ id: Identity) -> String {
        JSON.object([
            ("v", .int(1)),
            ("identitySign", pair(id.identitySign)),
            ("identityDH", pair(id.identityDH)),
            ("signedPreKey", pair(id.signedPreKey)),
            ("signedPreKeySig", .string(id.signedPreKeySig.b64)),
            ("oneTimePreKeys", .array(id.oneTimePreKeys.map(pair))),
        ]).text
    }

    public static func deserializeIdentity(_ json: String) throws -> Identity {
        let j = try JSONRead.object(json)
        guard j.optInt("v") == 1 else { throw E2EError.invalidFormat("Unsupported identity format version") }
        return Identity(
            identitySign: try pair(j.obj("identitySign")),
            identityDH: try pair(j.obj("identityDH")),
            signedPreKey: try pair(j.obj("signedPreKey")),
            signedPreKeySig: try j.str("signedPreKeySig").unb64(),
            oneTimePreKeys: try j.arr("oneTimePreKeys").map { try pair(($0 as? [String: Any]) ?? [:]) }
        )
    }

    static func bundleFields(_ b: PublicBundle) -> [(String, JSON)] {
        [
            ("identitySignPub", .string(b.identitySignPub)),
            ("identityDHPub", .string(b.identityDHPub)),
            ("signedPreKeyPub", .string(b.signedPreKeyPub)),
            ("signedPreKeySig", .string(b.signedPreKeySig)),
            ("oneTimePreKeys", .array(b.oneTimePreKeys.map { .string($0) })),
        ]
    }

    static func bundle(from o: [String: Any]) throws -> PublicBundle {
        PublicBundle(
            identitySignPub: try o.str("identitySignPub"),
            identityDHPub: try o.str("identityDHPub"),
            signedPreKeyPub: try o.str("signedPreKeyPub"),
            signedPreKeySig: try o.str("signedPreKeySig"),
            oneTimePreKeys: (o["oneTimePreKeys"] as? [Any])?.compactMap { $0 as? String } ?? []
        )
    }
}
