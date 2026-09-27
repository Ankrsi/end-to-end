import Foundation

/// In-memory store (tests, or state you don't need to keep).
public final class MemoryStore: SessionStore {
    private var map: [String: String] = [:]
    private let lock = NSLock()
    public init() {}
    public func get(_ key: String) async throws -> String? { lock.lock(); defer { lock.unlock() }; return map[key] }
    public func set(_ key: String, _ value: String) async throws { lock.lock(); map[key] = value; lock.unlock() }
    public func del(_ key: String) async throws { lock.lock(); map[key] = nil; lock.unlock() }
    public var keys: [String] { lock.lock(); defer { lock.unlock() }; return Array(map.keys) }
}

public final class PrefixStore: SessionStore {
    private let base: SessionStore
    private let prefix: String
    public init(_ base: SessionStore, prefix: String) { self.base = base; self.prefix = prefix }
    public func get(_ key: String) async throws -> String? { try await base.get(prefix + key) }
    public func set(_ key: String, _ value: String) async throws { try await base.set(prefix + key, value) }
    public func del(_ key: String) async throws { try await base.del(prefix + key) }
}

/// Encrypts every value with AES-256-GCM before it reaches `base`.
/// Format: base64(nonce(12) || ciphertext+tag) — same as the JS package.
public final class EncryptedStore: SessionStore {
    private let base: SessionStore
    private let key: () async throws -> Data

    public init(_ base: SessionStore, key: @escaping () async throws -> Data) {
        self.base = base
        self.key = key
    }

    public func get(_ k: String) async throws -> String? {
        guard let s = try await base.get(k) else { return nil }
        let raw = try s.unb64()
        guard raw.count >= 28 else { throw E2EError.decryptFailed("stored value too short") }
        return try Aead.open(key: try await key(), iv: raw.prefix(12), blob: raw.dropFirst(12)).utf8String
    }

    public func set(_ k: String, _ value: String) async throws {
        let nonce = Data.random(12)
        let ct = try Aead.seal(key: try await key(), iv: nonce, plaintext: value.utf8Data)
        try await base.set(k, (nonce + ct).b64)
    }

    public func del(_ k: String) async throws { try await base.del(k) }

    /// A 32-byte key kept in `secureStore` under `name`, created on first use.
    public static func masterKey(from secureStore: SessionStore, name: String = "e2e_master_key") -> () async throws -> Data {
        let holder = KeyHolder()
        return {
            if let k = await holder.value { return k }
            return try await holder.load {
                if let s = try await secureStore.get(name) { return try s.unb64() }
                let k = Data.random(32)
                try await secureStore.set(name, k.b64)
                return k
            }
        }
    }
}

private actor KeyHolder {
    var value: Data?
    private var loading: Task<Data, Error>?

    func load(_ make: @escaping () async throws -> Data) async throws -> Data {
        if let v = value { return v }
        if let t = loading { return try await t.value }
        let t = Task { try await make() }
        loading = t
        do {
            let v = try await t.value
            value = v
            return v
        } catch {
            loading = nil
            throw error
        }
    }
}

/// Everything a chat app needs, behind one object (port of the JS E2EEClient).
///
/// You provide `secureStore` (Keychain-backed, small), `store` (bulk; encrypted for you),
/// `uploadBundle` and `fetchBundle` for your server. Call `initialize()` once after login, then
/// encrypt/decrypt strings. How envelope strings travel is up to you.
public final class E2EEClient {
    public enum GroupResult: Equatable {
        case ok(String)
        case pending
    }

    public static let bundleTag = "x3dh1"
    private static let kPending = "pending"
    private static let maxPending = 500

    private let secureStore: SessionStore
    private let uploadBundle: (String) async throws -> Void
    private let onPendingDecrypted: ((String?, String) async -> Void)?
    private let identityKey: String
    private let oneTimePreKeyCount: Int
    private let initLock = KeyedLock()
    private var initialized = false
    private var identityCache: Identity?

    /// Encrypted view of the bulk store; sessions, sender keys and the pending queue live here.
    public let store: SessionStore
    public private(set) var sessions: SessionManager!

    public init(secureStore: SessionStore,
                store: SessionStore,
                uploadBundle: @escaping (_ bundle: String) async throws -> Void,
                fetchBundle: @escaping (_ userId: String) async throws -> String?,
                onPendingDecrypted: ((_ meta: String?, _ plaintext: String) async -> Void)? = nil,
                identityKey: String = "e2e_identity",
                masterKeyName: String = "e2e_master_key",
                oneTimePreKeyCount: Int = 10) {
        self.secureStore = secureStore
        self.uploadBundle = uploadBundle
        self.onPendingDecrypted = onPendingDecrypted
        self.identityKey = identityKey
        self.oneTimePreKeyCount = oneTimePreKeyCount
        self.store = EncryptedStore(store, key: EncryptedStore.masterKey(from: secureStore, name: masterKeyName))
        self.sessions = SessionManager(
            store: self.store,
            loadIdentity: { [unowned self] in try await self.loadIdentity() },
            fetchBundle: { E2EEClient.parseBundle(try await fetchBundle($0)) }
        )
    }

    public func loadIdentity() async throws -> Identity? {
        if let id = identityCache { return id }
        guard let s = try await secureStore.get(identityKey) else { return nil }
        let id = try X3DH.deserializeIdentity(s)
        identityCache = id
        return id
    }

    /// Creates this device's identity on first run and uploads its public bundle. Safe to call repeatedly.
    public func initialize() async throws {
        await initLock.acquire("init")
        do {
            if !initialized {
                var identity = try await loadIdentity()
                if identity == nil {
                    let created = try X3DH.createIdentity(oneTimePreKeyCount: oneTimePreKeyCount)
                    try await secureStore.set(identityKey, X3DH.serializeIdentity(created))
                    identityCache = created
                    identity = created
                }
                try await uploadBundle(E2EEClient.serializeBundle(X3DH.publicBundle(identity!)))   // public keys only
                initialized = true
            }
            await initLock.release("init")
        } catch {
            await initLock.release("init")
            throw error
        }
    }

    // MARK: 1:1
    public func encryptDirect(_ peerId: String, _ plaintext: String) async throws -> String? { try await sessions.encryptDirect(peerId, plaintext) }
    public func decryptDirect(_ senderId: String, _ value: String) async throws -> String { try await sessions.decryptDirect(senderId, value) }
    public func hasDirectSession(_ peerId: String) async throws -> Bool { try await sessions.hasDirectSession(peerId) }
    public func resetDirect(_ peerId: String) async throws { try await sessions.resetDirect(peerId) }
    /// Re-fetch a peer's bundle (e.g. when opening their chat) so a reinstall is noticed.
    @discardableResult
    public func refreshBundle(_ userId: String) async throws -> PublicBundle? { try await sessions.getBundle(userId, refresh: true) }

    // MARK: Groups
    public func encryptGroup(_ conversationId: String, memberIds: [String], _ plaintext: String,
                             distribute: (String, String) async throws -> Void) async throws -> String? {
        try await sessions.encryptGroup(conversationId, memberIds: memberIds, plaintext, distribute: distribute)
    }
    public func decryptGroup(_ conversationId: String, _ senderId: String, _ value: String) async throws -> String {
        try await sessions.decryptGroup(conversationId, senderId, value)
    }
    public func hasGroupKey(_ conversationId: String) async throws -> Bool { try await sessions.hasGroupKey(conversationId) }
    public func resetGroup(_ conversationId: String) async throws { try await sessions.resetGroup(conversationId) }

    /// Like `decryptGroup`, but a message that arrives before its sender's key is queued: returns `.pending`,
    /// and once the key arrives (`acceptSenderKey`) the plaintext goes to `onPendingDecrypted(meta, plaintext)`.
    public func decryptGroupOrQueue(_ conversationId: String, _ senderId: String, _ value: String, meta: String? = nil) async throws -> GroupResult {
        do {
            return .ok(try await sessions.decryptGroup(conversationId, senderId, value))
        } catch E2EError.missingSenderKey {
            try await sessions.withLock(Self.kPending) { () async throws -> Void in
                var list = try await readPending()
                if !list.contains(where: { $0.value == value }) {
                    list.append(Pending(conversationId: conversationId, senderId: senderId, value: value, meta: meta))
                    try await writePending(Array(list.suffix(Self.maxPending)))
                }
            }
            return .pending
        }
    }

    /// A sender-key packet from a group member. Decrypts queued messages it unlocks. Returns the conversation id.
    @discardableResult
    public func acceptSenderKey(_ senderId: String, _ envelope: String) async throws -> String {
        let conversationId = try await sessions.acceptSenderKey(senderId, envelope)
        try await retryPending(conversationId, senderId)
        return conversationId
    }

    private struct Pending {
        let conversationId: String
        let senderId: String
        let value: String
        let meta: String?
    }

    private func readPending() async throws -> [Pending] {
        guard let s = try await store.get(Self.kPending) else { return [] }
        return try JSONRead.array(s).compactMap { e in
            guard let o = e as? [String: Any] else { return nil }
            return Pending(conversationId: try o.str("conversationId"), senderId: try o.str("senderId"), value: try o.str("value"), meta: o.optStr("meta"))
        }
    }

    private func writePending(_ list: [Pending]) async throws {
        try await store.set(Self.kPending, JSON.array(list.map {
            .object([("conversationId", .string($0.conversationId)), ("senderId", .string($0.senderId)),
                     ("value", .string($0.value)), ("meta", JSON.opt($0.meta))])
        }).text)
    }

    private func retryPending(_ conversationId: String, _ senderId: String) async throws {
        let done: [(String?, String)] = try await sessions.withLock(Self.kPending) { () async throws -> [(String?, String)] in
            let list = try await readPending()
            var keep: [Pending] = []
            var out: [(String?, String)] = []
            for p in list {
                guard p.conversationId == conversationId, p.senderId == senderId else { keep.append(p); continue }
                do {
                    out.append((p.meta, try await sessions.decryptGroup(conversationId, senderId, p.value)))
                } catch E2EError.missingSenderKey {
                    keep.append(p)   // needs a newer key
                } catch {
                    // undecryptable: drop
                }
            }
            if keep.count != list.count { try await writePending(keep) }
            return out
        }
        // Outside the lock, so the callback may queue/decrypt more messages.
        for (meta, text) in done { await onPendingDecrypted?(meta, text) }
    }

    /// Public bundle -> one string for your server (same format as the JS package).
    public static func serializeBundle(_ b: PublicBundle) -> String {
        JSON.object([("v", .string(bundleTag))] + X3DH.bundleFields(b)).text
    }

    /// Server value -> bundle, or nil if missing / not an e2e-crypto bundle.
    public static func parseBundle(_ value: String?) -> PublicBundle? {
        guard let value = value, !value.isEmpty, let o = try? JSONRead.object(value),
              o["v"] as? String == bundleTag, o["identityDHPub"] != nil else { return nil }
        return try? X3DH.bundle(from: o)
    }
}
