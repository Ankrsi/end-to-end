import Foundation

/// Async key-value store with string values. Values hold secrets: keep them encrypted at rest (see `E2EEClient`).
public protocol SessionStore: AnyObject {
    func get(_ key: String) async throws -> String?
    func set(_ key: String, _ value: String) async throws
    func del(_ key: String) async throws
}

/// Per-key async mutex. (Actors alone aren't enough: they are re-entrant across `await`.)
actor KeyedLock {
    private var busy = Set<String>()
    private var waiters: [String: [CheckedContinuation<Void, Never>]] = [:]

    func acquire(_ key: String) async {
        if busy.contains(key) {
            await withCheckedContinuation { waiters[key, default: []].append($0) }   // ownership handed over on release
        } else {
            busy.insert(key)
        }
    }

    func release(_ key: String) {
        if var queue = waiters[key], !queue.isEmpty {
            let next = queue.removeFirst()
            waiters[key] = queue.isEmpty ? nil : queue
            next.resume()
        } else {
            busy.remove(key)
        }
    }
}

/// Sent with 1:1 messages until the peer replies, so they can build the session.
public struct Handshake: Equatable {
    public let ik: String
    public let ek: String
    public let otk: Int?

    var json: JSON { .object([("ik", .string(ik)), ("ek", .string(ek)), ("otk", otk.map { .int($0) } ?? .null)]) }

    static func from(_ o: [String: Any]) throws -> Handshake {
        Handshake(ik: try o.str("ik"), ek: try o.str("ek"), otk: o.optInt("otk"))
    }
}

/// Parsed wire envelope. Envelopes travel as JSON strings starting with `{"e2e"`.
public enum Envelope {
    case direct(hs: Handshake?, h: MessageHeader, c: String)
    case group(kid: String, i: Int, c: String, s: String)

    public static func parse(_ value: String?) -> Envelope? {
        guard let value = value, value.hasPrefix("{\"e2e\""), let o = try? JSONRead.object(value) else { return nil }
        switch o["e2e"] as? String {
        case "dr1":
            guard let hObj = o["h"] as? [String: Any], let h = try? MessageHeader.from(hObj), let c = o["c"] as? String else { return nil }
            let hs = (o["hs"] as? [String: Any]).flatMap { try? Handshake.from($0) }
            return .direct(hs: hs, h: h, c: c)
        case "sk1":
            guard let kid = o["kid"] as? String, let i = o.optInt("i"), let c = o["c"] as? String, let s = o["s"] as? String else { return nil }
            return .group(kid: kid, i: i, c: c, s: s)
        default:
            return nil
        }
    }

    public static func isEnvelope(_ value: String?) -> Bool { parse(value) != nil }
}

/// Session manager for chat apps (port of the JS SessionManager): one Double Ratchet session per
/// peer, Sender Keys per group, and the edge cases of real delivery — handshake repeated until the
/// peer replies, crossed handshakes, peer reinstalls, out-of-order and concurrent delivery,
/// sender-key rotation.
public final class SessionManager {
    private static let maxSessions = 3
    private static let maxSenderKeys = 3
    private static let kDirect = "dr."
    private static let kBundle = "bundle."
    private static let kGroupOwn = "go."
    private static let kGroupRecv = "gr."

    private let store: SessionStore
    private let loadIdentity: () async throws -> Identity?
    private let fetchBundle: (String) async throws -> PublicBundle?
    private let locks = KeyedLock()
    private let cacheLock = NSLock()
    private var bundles: [String: PublicBundle] = [:]

    public init(store: SessionStore,
                loadIdentity: @escaping () async throws -> Identity?,
                fetchBundle: @escaping (String) async throws -> PublicBundle?) {
        self.store = store
        self.loadIdentity = loadIdentity
        self.fetchBundle = fetchBundle
    }

    /// Serialises read-modify-write of one record (socket, offline sync and push can race).
    public func withLock<T>(_ key: String, _ body: () async throws -> T) async rethrows -> T {
        await locks.acquire(key)
        do {
            let r = try await body()
            await locks.release(key)
            return r
        } catch {
            await locks.release(key)
            throw error
        }
    }

    private func cached(_ id: String) -> PublicBundle? { cacheLock.lock(); defer { cacheLock.unlock() }; return bundles[id] }
    private func cache(_ id: String, _ b: PublicBundle?) { cacheLock.lock(); bundles[id] = b; cacheLock.unlock() }

    private func readObject(_ key: String) async throws -> [String: Any]? {
        guard let s = try await store.get(key) else { return nil }
        return try JSONRead.object(s)
    }

    private func identity() async throws -> Identity {
        guard let id = try await loadIdentity() else { throw E2EError.notInitialised }
        return id
    }

    // MARK: Bundles

    private func storedBundle(_ userId: String) async throws -> PublicBundle? {
        guard let o = try await readObject(Self.kBundle + userId) else { return nil }
        return try X3DH.bundle(from: o)
    }

    /// Cached bundle; `refresh` re-fetches it (falls back to the cache if offline).
    public func getBundle(_ userId: String, refresh: Bool = false) async throws -> PublicBundle? {
        if !refresh {
            if let b = cached(userId) { return b }
            if let b = try await storedBundle(userId) { cache(userId, b); return b }
        }
        let bundle: PublicBundle?
        do {
            bundle = try await fetchBundle(userId)
        } catch {
            if let b = cached(userId) { return b }
            if let b = try await storedBundle(userId) { return b }
            throw error
        }
        cache(userId, bundle)
        if let b = bundle {
            try await store.set(Self.kBundle + userId, JSON.object(X3DH.bundleFields(b)).text)
        } else {
            try await store.del(Self.kBundle + userId)
        }
        return bundle
    }

    // MARK: 1:1

    private final class Entry {
        let id: String
        var state: String
        let peerIk: String
        var hs: Handshake?
        init(id: String, state: String, peerIk: String, hs: Handshake?) { self.id = id; self.state = state; self.peerIk = peerIk; self.hs = hs }
        var json: JSON {
            var kv: [(String, JSON)] = [("id", .string(id)), ("state", .string(state)), ("peerIk", .string(peerIk))]
            if let hs = hs { kv.append(("hs", hs.json)) }
            return .object(kv)
        }
    }

    private struct DirectRecord {
        var sessions: [Entry]
        var reset: Bool
        var json: JSON {
            var kv: [(String, JSON)] = [("v", .int(1)), ("sessions", .array(sessions.map(\.json)))]
            if reset { kv.append(("reset", .bool(true))) }
            return .object(kv)
        }
    }

    private func readDirect(_ peerId: String) async throws -> DirectRecord {
        guard let j = try await readObject(Self.kDirect + peerId) else { return DirectRecord(sessions: [], reset: false) }
        let sessions: [Entry] = try (j["sessions"] as? [Any] ?? []).compactMap { e in
            guard let o = e as? [String: Any] else { return nil }
            return Entry(id: try o.str("id"), state: try o.str("state"), peerIk: try o.str("peerIk"),
                         hs: try (o["hs"] as? [String: Any]).map(Handshake.from))
        }
        return DirectRecord(sessions: sessions, reset: (j["reset"] as? Bool) ?? false)
    }

    /// Returns the envelope string, or nil if the peer has no bundle (can't encrypt to them).
    public func encryptDirect(_ peerId: String, _ plaintext: String) async throws -> String? {
        try await withLock(Self.kDirect + peerId) { () async throws -> String? in
            let identity = try await self.identity()
            var rec = try await readDirect(peerId)
            var entry = rec.sessions.first
            let bundle = try await getBundle(peerId)

            let needNew = entry == nil || rec.reset || (bundle != nil && entry!.peerIk != bundle!.identityDHPub)
            if needNew {
                guard let bundle = bundle else { return nil }
                let otkIndex = bundle.oneTimePreKeys.isEmpty ? 0 : Int.random(in: 0..<bundle.oneTimePreKeys.count)
                let hs = try X3DH.initiateHandshake(my: identity, their: bundle, usedOneTimePreKeyIndex: otkIndex)
                let session = try RatchetSession.initAsSender(sharedSecret: hs.sharedSecret, bobRatchetPublicRaw: hs.bobSignedPreKeyPublicRaw)
                let e = Entry(id: hs.ephemeralPublicRaw, state: session.serialize(), peerIk: bundle.identityDHPub,
                              hs: Handshake(ik: identity.identityDH.publicKey.b64, ek: hs.ephemeralPublicRaw, otk: hs.usedOneTimePreKeyIndex))
                rec.sessions = Array(([e] + rec.sessions).prefix(Self.maxSessions))
                rec.reset = false
                entry = e
            }

            let session = try RatchetSession.deserialize(entry!.state)
            let msg = try session.encrypt(plaintext)
            entry!.state = session.serialize()
            try await store.set(Self.kDirect + peerId, rec.json.text)

            var kv: [(String, JSON)] = [("e2e", .string("dr1")), ("h", msg.header.json), ("c", .string(msg.ciphertext))]
            if let hs = entry!.hs { kv.append(("hs", hs.json)) }
            return JSON.object(kv).text
        }
    }

    /// Non-envelope input is returned unchanged (plaintext from clients without E2EE). Throws if it can't decrypt.
    public func decryptDirect(_ senderId: String, _ value: String) async throws -> String {
        guard let env = Envelope.parse(value) else { return value }
        guard case let .direct(hs, h, c) = env else { throw E2EError.invalidFormat("Expected a 1:1 envelope") }

        return try await withLock(Self.kDirect + senderId) { () async throws -> String in
            var rec = try await readDirect(senderId)
            var isNew = false
            let candidates: [Entry]
            if let hs = hs {
                if let existing = rec.sessions.first(where: { $0.id == hs.ek }) {
                    candidates = [existing]
                } else {
                    let identity = try await self.identity()
                    let secret = try X3DH.respondToHandshake(my: identity, aliceIdentityDHPub: hs.ik, aliceEphemeralPub: hs.ek, oneTimePreKeyUsed: hs.otk)
                    let session = RatchetSession.initAsReceiver(sharedSecret: secret, bobRatchetKeyPair: identity.signedPreKey)
                    candidates = [Entry(id: hs.ek, state: session.serialize(), peerIk: hs.ik, hs: nil)]
                    isNew = true
                }
            } else {
                candidates = rec.sessions
            }

            for entry in candidates {
                let session = try RatchetSession.deserialize(entry.state)
                guard let plaintext = try? session.decrypt(header: h, ciphertext: c) else { continue }   // state unchanged on failure
                entry.state = session.serialize()
                entry.hs = nil   // the peer has this session now; stop sending the handshake
                rec.sessions = Array(([entry] + rec.sessions.filter { $0 !== entry }).prefix(Self.maxSessions))
                try await store.set(Self.kDirect + senderId, rec.json.text)

                // Peer reinstalled / new identity: our cached bundle is stale.
                if isNew {
                    var cachedBundle = cached(senderId)
                    if cachedBundle == nil { cachedBundle = try await storedBundle(senderId) }
                    if let b = cachedBundle, b.identityDHPub != entry.peerIk {
                        cache(senderId, nil)
                        try await store.del(Self.kBundle + senderId)
                    }
                }
                return plaintext
            }
            throw E2EError.decryptFailed("Unable to decrypt message from \(senderId)")
        }
    }

    public func hasDirectSession(_ peerId: String) async throws -> Bool {
        !(try await readDirect(peerId).sessions.isEmpty)
    }

    /// Next message to this peer starts a fresh handshake. Existing sessions still decrypt.
    public func resetDirect(_ peerId: String) async throws {
        try await withLock(Self.kDirect + peerId) { () async throws -> Void in
            guard try await store.get(Self.kDirect + peerId) != nil else { return }
            var rec = try await readDirect(peerId)
            rec.reset = true
            try await store.set(Self.kDirect + peerId, rec.json.text)
        }
    }

    // MARK: Groups

    /// Encrypts once for the whole group. Our sender key is first sent (over 1:1 sessions) to members
    /// who don't have it yet, via `distribute`. Returns nil if a member has no bundle.
    public func encryptGroup(_ conversationId: String, memberIds: [String], _ plaintext: String,
                             distribute: (_ to: String, _ envelope: String) async throws -> Void) async throws -> String? {
        try await withLock(Self.kGroupOwn + conversationId) { () async throws -> String? in
            var memberBundles: [String: PublicBundle] = [:]
            for m in memberIds {
                guard let b = try await getBundle(m) else { return nil }
                memberBundles[m] = b
            }

            let existing = try await readObject(Self.kGroupOwn + conversationId)
            let kid = existing?.optStr("kid") ?? Data.random(12).b64
            let state = try existing.map { try SenderKey.deserialize($0.str("state")) } ?? SenderKey.create()
            var to = (existing?["to"] as? [String: String]) ?? [:]
            var toOrder = Array(to.keys)

            let missing = memberIds.filter { to[$0] != memberBundles[$0]!.identityDHPub }
            if !missing.isEmpty {
                let body = JSON.object([
                    ("t", .string("skdm")), ("conversationId", .string(conversationId)), ("kid", .string(kid)),
                    ("dist", SenderKey.exportDistribution(state).json),
                ]).text
                for m in missing {
                    guard let env = try await encryptDirect(m, body) else { return nil }
                    try await distribute(m, env)
                    if to[m] == nil { toOrder.append(m) }
                    to[m] = memberBundles[m]!.identityDHPub
                }
            }

            let msg = try SenderKey.encrypt(state, plaintext)
            try await store.set(Self.kGroupOwn + conversationId, JSON.object([
                ("v", .int(1)), ("kid", .string(kid)), ("state", .string(SenderKey.serialize(state))),
                ("to", .object(toOrder.compactMap { k in to[k].map { (k, .string($0)) } })),
            ]).text)

            return JSON.object([
                ("e2e", .string("sk1")), ("kid", .string(kid)), ("i", .int(msg.iteration)),
                ("c", .string(msg.ciphertext)), ("s", .string(msg.signature)),
            ]).text
        }
    }

    private func readKeys(_ key: String) async throws -> [[String: Any]] {
        (try await readObject(key)?["keys"] as? [Any])?.compactMap { $0 as? [String: Any] } ?? []
    }

    private func keysJSON(_ keys: [[String: Any]]) throws -> String {
        JSON.object([("v", .int(1)), ("keys", .array(try keys.map { .object([("kid", .string(try $0.str("kid"))), ("state", .string(try $0.str("state")))]) }))]).text
    }

    /// Handles a sender-key distribution received over a 1:1 session. Returns its conversation id.
    @discardableResult
    public func acceptSenderKey(_ senderId: String, _ envelope: String) async throws -> String {
        let packet = try JSONRead.object(try await decryptDirect(senderId, envelope))
        guard packet["t"] as? String == "skdm" else { throw E2EError.invalidFormat("Not a sender key packet") }
        let conversationId = try packet.str("conversationId")
        let kid = try packet.str("kid")
        let key = "\(Self.kGroupRecv)\(conversationId).\(senderId)"
        try await withLock(key) { () async throws -> Void in
            let keys = try await readKeys(key)
            if keys.contains(where: { $0["kid"] as? String == kid }) { return }   // duplicate delivery
            let state = try SenderKey.importDistribution(try SenderKeyDistribution.from(try packet.obj("dist")))
            let entry: [String: Any] = ["kid": kid, "state": SenderKey.serialize(state)]
            try await store.set(key, try keysJSON(Array(([entry] + keys).prefix(Self.maxSenderKeys))))
        }
        return conversationId
    }

    /// Non-envelope input is returned unchanged. Throws `E2EError.missingSenderKey` if the sender's key hasn't arrived.
    public func decryptGroup(_ conversationId: String, _ senderId: String, _ value: String) async throws -> String {
        guard let env = Envelope.parse(value) else { return value }
        guard case let .group(kid, i, c, s) = env else { throw E2EError.invalidFormat("Expected a group envelope") }
        let key = "\(Self.kGroupRecv)\(conversationId).\(senderId)"
        return try await withLock(key) { () async throws -> String in
            var keys = try await readKeys(key)
            guard let idx = keys.firstIndex(where: { $0["kid"] as? String == kid }) else {
                throw E2EError.missingSenderKey(conversationId: conversationId, senderId: senderId)
            }
            let state = try SenderKey.deserialize(try keys[idx].str("state"))
            let plaintext = try SenderKey.decrypt(state, GroupMessage(iteration: i, ciphertext: c, signature: s))
            keys[idx] = ["kid": kid, "state": SenderKey.serialize(state)]
            try await store.set(key, try keysJSON(keys))
            return plaintext
        }
    }

    public func hasGroupKey(_ conversationId: String) async throws -> Bool {
        try await store.get(Self.kGroupOwn + conversationId) != nil
    }

    /// Drop our sender key so the next send rotates it (someone left / was removed).
    public func resetGroup(_ conversationId: String) async throws {
        try await withLock(Self.kGroupOwn + conversationId) { () async throws -> Void in try await store.del(Self.kGroupOwn + conversationId) }
    }
}
