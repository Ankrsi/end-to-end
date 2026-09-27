import XCTest
@testable import E2ECrypto

/// Same scenarios as the JS runSelfTest: out-of-order, concurrent, crossed handshakes, replay, groups.
final class SessionTests: XCTestCase {
    private var server: [String: PublicBundle] = [:]

    private func user(_ name: String) throws -> SessionManager {
        let id = try X3DH.createIdentity()
        server[name] = X3DH.publicBundle(id)
        let snapshot = { [unowned self] (u: String) -> PublicBundle? in self.server[u] }
        return SessionManager(store: MemoryStore(), loadIdentity: { id }, fetchBundle: { snapshot($0) })
    }

    func testOutOfOrder() async throws {
        let a = try user("a1"), b = try user("b1")
        var sent: [(String, String)] = []
        for i in 0..<50 { sent.append((try await a.encryptDirect("b1", "m\(i)")!, "m\(i)")) }
        for (env, text) in sent.shuffled() {
            let got = try await b.decryptDirect("a1", env)
            XCTAssertEqual(got, text)
        }
    }

    func testConcurrentDecrypts() async throws {
        let a = try user("a2"), b = try user("b2")
        var sent: [(String, String)] = []
        for i in 0..<50 { sent.append((try await a.encryptDirect("b2", "m\(i)")!, "m\(i)")) }
        sent.shuffle()
        let got = try await withThrowingTaskGroup(of: (Int, String).self) { group -> [Int: String] in
            for (i, (env, _)) in sent.enumerated() { group.addTask { (i, try await b.decryptDirect("a2", env)) } }
            var r: [Int: String] = [:]
            for try await (i, t) in group { r[i] = t }
            return r
        }
        for (i, (_, text)) in sent.enumerated() { XCTAssertEqual(got[i], text) }
    }

    func testCrossedHandshakes() async throws {
        let a = try user("a3"), b = try user("b3")
        async let fa: [String] = { var r: [String] = []; for i in 0..<10 { r.append(try await a.encryptDirect("b3", "a\(i)")!) }; return r }()
        async let fb: [String] = { var r: [String] = []; for i in 0..<10 { r.append(try await b.encryptDirect("a3", "b\(i)")!) }; return r }()
        let (fromA, fromB) = try await (fa, fb)
        for (i, e) in fromA.enumerated().shuffled() { let t = try await b.decryptDirect("a3", e); XCTAssertEqual(t, "a\(i)") }
        for (i, e) in fromB.enumerated().shuffled() { let t = try await a.decryptDirect("b3", e); XCTAssertEqual(t, "b\(i)") }
        for i in 0..<5 {
            let x = try await b.decryptDirect("a3", try await a.encryptDirect("b3", "x\(i)")!)
            XCTAssertEqual(x, "x\(i)")
            let y = try await a.decryptDirect("b3", try await b.encryptDirect("a3", "y\(i)")!)
            XCTAssertEqual(y, "y\(i)")
        }
    }

    func testReplayRejected() async throws {
        let a = try user("a4"), b = try user("b4")
        let e = try await a.encryptDirect("b4", "once")!
        let first = try await b.decryptDirect("a4", e)
        XCTAssertEqual(first, "once")
        do { _ = try await b.decryptDirect("a4", e); XCTFail("replay accepted") } catch {}
        let next = try await b.decryptDirect("a4", try await a.encryptDirect("b4", "next")!)
        XCTAssertEqual(next, "next")
    }

    func testHandshakeStopsAndPlaintextPassesThrough() async throws {
        let a = try user("a5"), b = try user("b5")
        let first = try await a.encryptDirect("b5", "hi")!
        guard case let .direct(hs1, _, _) = Envelope.parse(first)! else { return XCTFail() }
        XCTAssertNotNil(hs1)
        _ = try await b.decryptDirect("a5", first)
        _ = try await a.decryptDirect("b5", try await b.encryptDirect("a5", "back")!)
        guard case let .direct(hs2, _, _) = Envelope.parse(try await a.encryptDirect("b5", "again")!)! else { return XCTFail() }
        XCTAssertNil(hs2)
        let plain = try await b.decryptDirect("a5", "plain")
        XCTAssertEqual(plain, "plain")
        let none = try await a.encryptDirect("nobody", "x")
        XCTAssertNil(none)
    }

    func testGroups() async throws {
        let a = try user("ga"), b = try user("gb"), c = try user("gc")
        let users = ["gb": b, "gc": c]
        var packets: [(String, String)] = []
        var sent: [(String, String)] = []
        for i in 0..<50 {
            let env = try await a.encryptGroup("g", memberIds: ["gb", "gc"], "g\(i)") { to, env in packets.append((to, env)) }!
            sent.append((env, "g\(i)"))
        }
        do { _ = try await b.decryptGroup("g", "ga", sent[0].0); XCTFail("expected missingSenderKey") }
        catch E2EError.missingSenderKey {}
        for (to, env) in packets { try await users[to]!.acceptSenderKey("ga", env) }
        for u in [b, c] {
            let order = sent.shuffled()
            let got = try await withThrowingTaskGroup(of: (Int, String).self) { group -> [Int: String] in
                for (i, (env, _)) in order.enumerated() { group.addTask { (i, try await u.decryptGroup("g", "ga", env)) } }
                var r: [Int: String] = [:]
                for try await (i, t) in group { r[i] = t }
                return r
            }
            for (i, (_, text)) in order.enumerated() { XCTAssertEqual(got[i], text) }
        }
        packets.removeAll()
        try await a.resetGroup("g")
        let rotated = try await a.encryptGroup("g", memberIds: ["gb"], "carol gone") { to, env in packets.append((to, env)) }!
        XCTAssertEqual(packets.count, 1)
        try await b.acceptSenderKey("ga", packets[0].1)
        let r = try await b.decryptGroup("g", "ga", rotated)
        XCTAssertEqual(r, "carol gone")
        do { _ = try await c.decryptGroup("g", "ga", rotated); XCTFail("removed member decrypted") } catch E2EError.missingSenderKey {}
    }

    func testClient() async throws {
        final class Box { var bundles: [String: String] = [:]; var delivered: [(String?, String)] = [] }
        let box = Box()
        func client(_ name: String, _ sec: SessionStore, _ bulk: SessionStore, pending: ((String?, String) async -> Void)? = nil) -> E2EEClient {
            E2EEClient(secureStore: sec, store: bulk,
                       uploadBundle: { box.bundles[name] = $0 },
                       fetchBundle: { box.bundles[$0] },
                       onPendingDecrypted: pending)
        }
        let aSec = MemoryStore(), aBulk = MemoryStore()
        let a = client("ca", aSec, aBulk)
        let b = client("cb", MemoryStore(), MemoryStore()) { meta, text in box.delivered.append((meta, text)) }
        async let i1: Void = a.initialize()
        async let i2: Void = a.initialize()
        async let i3: Void = b.initialize()
        _ = try await (i1, i2, i3)

        let hello = try await b.decryptDirect("ca", try await a.encryptDirect("cb", "hello")!)
        XCTAssertEqual(hello, "hello")
        let before = box.bundles["ca"]
        let a2 = client("ca", aSec, aBulk)   // app restart
        try await a2.initialize()
        XCTAssertEqual(box.bundles["ca"], before)
        let two = try await b.decryptDirect("ca", try await a2.encryptDirect("cb", "two")!)
        XCTAssertEqual(two, "two")
        XCTAssertFalse(aBulk.keys.isEmpty)
        for k in aBulk.keys {
            let v = try await aBulk.get(k)!
            XCTAssertFalse(v.hasPrefix("{"), "stored in clear: \(k)")
        }

        var keyPackets: [String] = []
        let m1 = try await a2.encryptGroup("grp", memberIds: ["cb"], "first") { _, env in keyPackets.append(env) }!
        let m2 = try await a2.encryptGroup("grp", memberIds: ["cb"], "second") { _, _ in }!
        let p2 = try await b.decryptGroupOrQueue("grp", "ca", m2, meta: "2")
        let p1 = try await b.decryptGroupOrQueue("grp", "ca", m1, meta: "1")
        XCTAssertEqual(p2, .pending)
        XCTAssertEqual(p1, .pending)
        let conv = try await b.acceptSenderKey("ca", keyPackets[0])
        XCTAssertEqual(conv, "grp")
        let delivered = box.delivered.sorted { ($0.0 ?? "") < ($1.0 ?? "") }
        XCTAssertEqual(delivered.map { $0.0 }, ["1", "2"])
        XCTAssertEqual(delivered.map { $0.1 }, ["first", "second"])
    }

    func testBundleFormat() throws {
        let b = X3DH.publicBundle(try X3DH.createIdentity())
        XCTAssertEqual(E2EEClient.parseBundle(E2EEClient.serializeBundle(b)), b)
        XCTAssertNil(E2EEClient.parseBundle("bGVnYWN5LWRoLWtleQ=="))
        XCTAssertNil(E2EEClient.parseBundle(nil))
        XCTAssertNil(E2EEClient.parseBundle("{\"v\":\"other\"}"))
        XCTAssertTrue(E2EEClient.serializeBundle(b).hasPrefix("{\"v\":\"x3dh1\""))
    }
}
