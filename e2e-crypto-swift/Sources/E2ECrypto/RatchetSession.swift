import Foundation

/// 1:1 message header: sender's current ratchet public key (base64), previous chain length, message number.
public struct MessageHeader: Equatable {
    public let dh: String
    public let pn: Int
    public let n: Int

    var json: JSON { .object([("dh", .string(dh)), ("pn", .int(pn)), ("n", .int(n))]) }

    static func from(_ o: [String: Any]) throws -> MessageHeader {
        MessageHeader(dh: try o.str("dh"), pn: try o.int("pn"), n: try o.int("n"))
    }
}

public struct EncryptedMessage {
    public let header: MessageHeader
    /// base64
    public let ciphertext: String
}

/// Double Ratchet session (Signal spec). Wire- and storage-compatible with the JS RatchetSession.
public final class RatchetSession {
    private static let maxSkip = 1000
    private static let maxSkippedTotal = 2000

    private var dhs: KeyPair
    private var dhr: Data?
    private var rk: Data
    private var cks: Data?
    private var ckr: Data?
    private var ns = 0
    private var nr = 0
    private var pn = 0
    // "dhB64:n" -> message key; insertion order kept separately for oldest-first eviction
    private var skipped: [String: Data] = [:]
    private var skippedOrder: [String] = []

    private init(dhs: KeyPair, dhr: Data?, rk: Data) {
        self.dhs = dhs
        self.dhr = dhr
        self.rk = rk
    }

    /// Initiator, right after `X3DH.initiateHandshake`.
    public static func initAsSender(sharedSecret: Data, bobRatchetPublicRaw: Data) throws -> RatchetSession {
        let kp = Curve.generateX25519KeyPair()
        let step = Kdf.rootKey(sharedSecret, try Curve.dh(privateKey: kp.privateKey, publicKey: bobRatchetPublicRaw))
        let s = RatchetSession(dhs: kp, dhr: bobRatchetPublicRaw, rk: step.rootKey)
        s.cks = step.chainKey
        return s
    }

    /// Responder, right after `X3DH.respondToHandshake`. Pass `identity.signedPreKey`.
    public static func initAsReceiver(sharedSecret: Data, bobRatchetKeyPair: KeyPair) -> RatchetSession {
        RatchetSession(dhs: bobRatchetKeyPair, dhr: nil, rk: sharedSecret)
    }

    public func encrypt(_ plaintext: String, associatedData: Data = Data()) throws -> EncryptedMessage {
        try encrypt(bytes: plaintext.utf8Data, associatedData: associatedData)
    }

    public func encrypt(bytes plaintext: Data, associatedData: Data = Data()) throws -> EncryptedMessage {
        guard let ck = cks else { throw E2EError.cannotSend }
        let step = Kdf.chainKey(ck)
        cks = step.chainKey
        let header = MessageHeader(dh: dhs.publicKey.b64, pn: pn, n: ns)
        ns += 1
        let ct = try Aead.encrypt(messageKey: step.messageKey, plaintext: plaintext, associatedData: associatedData)
        return EncryptedMessage(header: header, ciphertext: ct.b64)
    }

    /// Returns the UTF-8 plaintext. Throws on tampering/replay; the state is unchanged on failure.
    public func decrypt(header: MessageHeader, ciphertext: String, associatedData: Data = Data()) throws -> String {
        try decryptBytes(header: header, ciphertext: ciphertext, associatedData: associatedData).utf8String
    }

    private struct Draft {
        var dhs: KeyPair; var dhr: Data?; var rk: Data; var cks: Data?; var ckr: Data?
        var ns: Int; var nr: Int; var pn: Int
    }

    public func decryptBytes(header: MessageHeader, ciphertext b64: String, associatedData: Data = Data()) throws -> Data {
        let ciphertext = try b64.unb64()

        // 1. Key already derived for an earlier out-of-order arrival?
        let skippedId = "\(header.dh):\(header.n)"
        if let mk = skipped[skippedId] {
            let pt = try Aead.decrypt(messageKey: mk, blob: ciphertext, associatedData: associatedData)
            skipped[skippedId] = nil   // single-use
            skippedOrder.removeAll { $0 == skippedId }
            return pt
        }

        // 2. Work on a draft; commit only after the message authenticates.
        var st = Draft(dhs: dhs, dhr: dhr, rk: rk, cks: cks, ckr: ckr, ns: ns, nr: nr, pn: pn)
        var newSkipped: [(String, Data)] = []
        let remote = try header.dh.unb64()
        if st.dhr == nil || !constantTimeEqual(remote, st.dhr!) {
            try skipMessageKeys(&st, header.pn, &newSkipped)   // finish the old receiving chain first
            try dhRatchetStep(&st, remote)
        }
        try skipMessageKeys(&st, header.n, &newSkipped)
        if header.n < st.nr { throw E2EError.replayOrExpired }
        guard let ckr0 = st.ckr else { throw E2EError.decryptFailed("no receiving chain") }
        let step = Kdf.chainKey(ckr0)
        st.ckr = step.chainKey
        st.nr += 1

        let plaintext = try Aead.decrypt(messageKey: step.messageKey, blob: ciphertext, associatedData: associatedData)

        dhs = st.dhs; dhr = st.dhr; rk = st.rk; cks = st.cks; ckr = st.ckr; ns = st.ns; nr = st.nr; pn = st.pn
        for (id, mk) in newSkipped {
            if skipped[id] == nil { skippedOrder.append(id) }
            skipped[id] = mk
        }
        while skipped.count > RatchetSession.maxSkippedTotal, let oldest = skippedOrder.first {
            skippedOrder.removeFirst()
            skipped[oldest] = nil
        }
        return plaintext
    }

    private func dhRatchetStep(_ st: inout Draft, _ remote: Data) throws {
        st.pn = st.ns
        st.ns = 0
        st.nr = 0
        st.dhr = remote
        var out = Kdf.rootKey(st.rk, try Curve.dh(privateKey: st.dhs.privateKey, publicKey: remote))
        st.rk = out.rootKey
        st.ckr = out.chainKey
        st.dhs = Curve.generateX25519KeyPair()
        out = Kdf.rootKey(st.rk, try Curve.dh(privateKey: st.dhs.privateKey, publicKey: remote))
        st.rk = out.rootKey
        st.cks = out.chainKey
    }

    private func skipMessageKeys(_ st: inout Draft, _ untilN: Int, _ newSkipped: inout [(String, Data)]) throws {
        guard var ck = st.ckr else { return }
        if st.nr + RatchetSession.maxSkip < untilN { throw E2EError.tooManySkipped }
        let dhB64 = st.dhr!.b64
        while st.nr < untilN {
            let step = Kdf.chainKey(ck)
            ck = step.chainKey
            newSkipped.append(("\(dhB64):\(st.nr)", step.messageKey))
            st.nr += 1
        }
        st.ckr = ck
    }

    /// Save after every encrypt/decrypt — the state advances with each message. Contains secrets.
    public func serialize() -> String {
        JSON.object([
            ("v", .int(1)),
            ("DHs", .object([("publicKey", .string(dhs.publicKey.b64)), ("privateKey", .string(dhs.privateKey.b64))])),
            ("DHr", JSON.opt(dhr?.b64)), ("RK", .string(rk.b64)), ("CKs", JSON.opt(cks?.b64)), ("CKr", JSON.opt(ckr?.b64)),
            ("Ns", .int(ns)), ("Nr", .int(nr)), ("PN", .int(pn)),
            ("skipped", .array(skippedOrder.compactMap { id in skipped[id].map { .array([.string(id), .string($0.b64)]) } })),
        ]).text
    }

    public static func deserialize(_ json: String) throws -> RatchetSession {
        let j = try JSONRead.object(json)
        guard j.optInt("v") == 1 else { throw E2EError.invalidFormat("Unsupported session format version") }
        let d = try j.obj("DHs")
        let s = RatchetSession(
            dhs: KeyPair(publicKey: try d.str("publicKey").unb64(), privateKey: try d.str("privateKey").unb64()),
            dhr: try j.optStr("DHr")?.unb64(),
            rk: try j.str("RK").unb64()
        )
        s.cks = try j.optStr("CKs")?.unb64()
        s.ckr = try j.optStr("CKr")?.unb64()
        s.ns = try j.int("Ns"); s.nr = try j.int("Nr"); s.pn = try j.int("PN")
        for e in try j.arr("skipped") {
            guard let p = e as? [Any], p.count == 2, let id = p[0] as? String, let mk = p[1] as? String else { continue }
            s.skipped[id] = try mk.unb64()
            s.skippedOrder.append(id)
        }
        return s
    }
}
