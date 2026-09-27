import Foundation

/// One member's sending chain in a group. `signPrivate` is only present on your own state.
public final class SenderKeyState {
    public var chainKey: Data
    public var iteration: Int
    public let signPublic: Data
    public let signPrivate: Data?
    var skipped: [Int: Data] = [:]
    var skippedOrder: [Int] = []

    init(chainKey: Data, iteration: Int, signPublic: Data, signPrivate: Data?) {
        self.chainKey = chainKey
        self.iteration = iteration
        self.signPublic = signPublic
        self.signPrivate = signPrivate
    }
}

/// Sent to each member over their 1:1 session.
public struct SenderKeyDistribution {
    public let chainKey: String
    public let iteration: Int
    public let signPublic: String

    var json: JSON { .object([("chainKey", .string(chainKey)), ("iteration", .int(iteration)), ("signPublic", .string(signPublic))]) }

    static func from(_ o: [String: Any]) throws -> SenderKeyDistribution {
        SenderKeyDistribution(chainKey: try o.str("chainKey"), iteration: try o.int("iteration"), signPublic: try o.str("signPublic"))
    }
}

public struct GroupMessage {
    public let iteration: Int
    public let ciphertext: String
    public let signature: String
}

/// Sender Keys: encrypt once per group message, whatever the group size. Wire-compatible with the JS package.
public enum SenderKey {
    private static let maxSkip = 1000

    public static func create() -> SenderKeyState {
        let sign = Curve.generateEd25519KeyPair()
        return SenderKeyState(chainKey: .random(32), iteration: 0, signPublic: sign.publicKey, signPrivate: sign.privateKey)
    }

    public static func exportDistribution(_ s: SenderKeyState) -> SenderKeyDistribution {
        SenderKeyDistribution(chainKey: s.chainKey.b64, iteration: s.iteration, signPublic: s.signPublic.b64)
    }

    public static func importDistribution(_ d: SenderKeyDistribution) throws -> SenderKeyState {
        SenderKeyState(chainKey: try d.chainKey.unb64(), iteration: d.iteration, signPublic: try d.signPublic.unb64(), signPrivate: nil)
    }

    public static func encrypt(_ s: SenderKeyState, _ plaintext: String) throws -> GroupMessage {
        guard let signPrivate = s.signPrivate else { throw E2EError.invalidKey("This is an imported (receive-only) sender key state") }
        let step = Kdf.chainKey(s.chainKey)
        let iteration = s.iteration
        s.chainKey = step.chainKey
        s.iteration += 1
        let ct = try Aead.encrypt(messageKey: step.messageKey, plaintext: plaintext.utf8Data)
        return GroupMessage(iteration: iteration, ciphertext: ct.b64, signature: try Curve.sign(privateKey: signPrivate, data: ct).b64)
    }

    /// Verifies the Ed25519 signature before touching any state.
    public static func decrypt(_ s: SenderKeyState, _ msg: GroupMessage) throws -> String {
        let ct = try msg.ciphertext.unb64()
        guard Curve.verify(publicKey: s.signPublic, data: ct, signature: try msg.signature.unb64()) else {
            throw E2EError.invalidSignature("Group message signature invalid — possible forgery")
        }
        if let mk = s.skipped[msg.iteration] {
            let pt = try Aead.decrypt(messageKey: mk, blob: ct)
            s.skipped[msg.iteration] = nil
            s.skippedOrder.removeAll { $0 == msg.iteration }
            return pt.utf8String
        }
        if msg.iteration < s.iteration { throw E2EError.replayOrExpired }
        if msg.iteration - s.iteration > maxSkip { throw E2EError.tooManySkipped }

        var ck = s.chainKey
        var messageKey = Data()
        var newSkipped: [(Int, Data)] = []
        for i in s.iteration...msg.iteration {
            let step = Kdf.chainKey(ck)
            ck = step.chainKey
            if i < msg.iteration { newSkipped.append((i, step.messageKey)) } else { messageKey = step.messageKey }
        }
        let pt = try Aead.decrypt(messageKey: messageKey, blob: ct)

        s.chainKey = ck
        s.iteration = msg.iteration + 1
        for (i, mk) in newSkipped {
            if s.skipped[i] == nil { s.skippedOrder.append(i) }
            s.skipped[i] = mk
        }
        while s.skipped.count > maxSkip, let oldest = s.skippedOrder.first {
            s.skippedOrder.removeFirst()
            s.skipped[oldest] = nil
        }
        return pt.utf8String
    }

    public static func serialize(_ s: SenderKeyState) -> String {
        JSON.object([
            ("v", .int(1)),
            ("chainKey", .string(s.chainKey.b64)),
            ("iteration", .int(s.iteration)),
            ("signPublic", .string(s.signPublic.b64)),
            ("signPrivate", JSON.opt(s.signPrivate?.b64)),
            ("skipped", .array(s.skippedOrder.compactMap { i in s.skipped[i].map { .array([.int(i), .string($0.b64)]) } })),
        ]).text
    }

    public static func deserialize(_ json: String) throws -> SenderKeyState {
        let j = try JSONRead.object(json)
        guard j.optInt("v") == 1 else { throw E2EError.invalidFormat("Unsupported sender key format version") }
        let s = SenderKeyState(chainKey: try j.str("chainKey").unb64(), iteration: try j.int("iteration"),
                               signPublic: try j.str("signPublic").unb64(), signPrivate: try j.optStr("signPrivate")?.unb64())
        for e in try j.arr("skipped") {
            guard let p = e as? [Any], p.count == 2, let i = anyInt(p[0]), let mk = p[1] as? String else { continue }
            s.skipped[i] = try mk.unb64()
            s.skippedOrder.append(i)
        }
        return s
    }
}
