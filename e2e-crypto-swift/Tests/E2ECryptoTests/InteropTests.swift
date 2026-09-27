import XCTest
import Foundation
@testable import E2ECrypto

/// Cross-language test against vectors from the JS package (../testing/interop/gen-vectors.js).
/// Set INTEROP_VECTORS=<vectors.json> and INTEROP_REPLIES=<out.json>; skipped otherwise.
final class InteropTests: XCTestCase {
    private func vectors() throws -> [String: Any]? {
        guard let path = ProcessInfo.processInfo.environment["INTEROP_VECTORS"], !path.isEmpty,
              let data = FileManager.default.contents(atPath: path) else { return nil }
        return try JSONRead.object(String(decoding: data, as: UTF8.self))
    }

    func testPrimitives() throws {
        guard let v = try vectors() else { throw XCTSkip("interop vectors not provided") }
        let p = try v.obj("primitives")
        for e in try p.arr("base64") {
            let o = e as! [String: Any]
            let n = try o.int("len")
            let bytes = Data((0..<n).map { UInt8((250 + $0) & 0xff) })
            XCTAssertEqual(Base64.encode(bytes), try o.str("bytes"), "base64 len \(n)")
            XCTAssertEqual(try Base64.decode(try o.str("bytes")), bytes)
        }
        for e in try p.arr("hkdf") {
            let o = e as! [String: Any]
            let info = try o.str("info")
            let out = Kdf.hkdf(ikm: try o.str("ikm").unb64(), salt: try o.str("salt").unb64(), info: info, length: try o.int("length"))
            XCTAssertEqual(out.b64, try o.str("out"), "hkdf \(info)")
        }
        let c = try p.obj("chain")
        let step = Kdf.chainKey(try c.str("chainKey").unb64())
        XCTAssertEqual(step.chainKey.b64, try c.str("nextChainKey"))
        XCTAssertEqual(step.messageKey.b64, try c.str("messageKey"))
        let a = try p.obj("aead")
        let ct = try Aead.encrypt(messageKey: try a.str("messageKey").unb64(), plaintext: try a.str("plaintext").utf8Data)
        XCTAssertEqual(ct.b64, try a.str("ciphertext"))
        XCTAssertEqual(try Aead.decrypt(messageKey: try a.str("messageKey").unb64(), blob: try a.str("ciphertext").unb64()).utf8String, try a.str("plaintext"))
        let x = try p.obj("x25519")
        XCTAssertEqual(try Curve.x25519PublicKey(privateKey: try x.str("privA").unb64()).b64, try x.str("pubA"))
        XCTAssertEqual(try Curve.dh(privateKey: try x.str("privA").unb64(), publicKey: try x.str("pubB").unb64()).b64, try x.str("shared"))
        let ed = try p.obj("ed25519")
        let seed = try ed.str("seed").unb64(), msg = try ed.str("message").unb64()
        let pub = try Curve.ed25519PublicKey(privateKey: seed)
        XCTAssertEqual(pub.b64, try ed.str("publicKey"))
        XCTAssertTrue(Curve.verify(publicKey: pub, data: msg, signature: try ed.str("signature").unb64()))
        // CryptoKit signatures may be randomized on Apple platforms; they must still verify.
        XCTAssertTrue(Curve.verify(publicKey: pub, data: msg, signature: try Curve.sign(privateKey: seed, data: msg)))
    }

    func testProtocol() async throws {
        guard let v = try vectors() else { throw XCTSkip("interop vectors not provided") }
        let bundles = (v["bundles"] as? [String: String]) ?? [:]
        var allBundles = bundles
        let bob = try X3DH.deserializeIdentity(try v.str("bobIdentity"))
        let sm = SessionManager(store: MemoryStore(), loadIdentity: { bob }, fetchBundle: { E2EEClient.parseBundle(bundles[$0]) })

        // JS -> Swift, delivered out of order
        let d = try v.obj("direct")
        let envs = try d.arr("envelopes") as! [String]
        let texts = try d.arr("plaintexts") as! [String]
        for i in (try d.arr("order")).compactMap(anyInt) {
            let t = try await sm.decryptDirect("alice", envs[i])
            XCTAssertEqual(t, texts[i])
        }
        let g = try v.obj("group")
        for pkt in try g.arr("keyPackets") as! [String] {
            let conv = try await sm.acceptSenderKey("alice", pkt)
            XCTAssertEqual(conv, "g1")
        }
        let genvs = try g.arr("envelopes") as! [String]
        let gtexts = try g.arr("plaintexts") as! [String]
        for i in (try g.arr("order")).compactMap(anyInt) {
            let t = try await sm.decryptGroup("g1", "alice", genvs[i])
            XCTAssertEqual(t, gtexts[i])
        }

        // Swift -> JS (checked by verify-replies.js)
        guard let out = ProcessInfo.processInfo.environment["INTEROP_REPLIES"], !out.isEmpty else { return }
        var direct: [(String, String)] = []
        for i in 0..<6 { let t = "bob(swift)→alice #\(i) ✅ 你好"; direct.append((t, try await sm.encryptDirect("alice", t)!)) }
        var keyPackets: [String] = []
        var group: [(String, String)] = []
        for i in 0..<5 {
            let t = "bob(swift) group #\(i)"
            group.append((t, try await sm.encryptGroup("g1", memberIds: ["alice"], t) { _, env in keyPackets.append(env) }!))
        }
        let carolId = try X3DH.createIdentity()
        allBundles["carol"] = E2EEClient.serializeBundle(X3DH.publicBundle(carolId))
        let carol = SessionManager(store: MemoryStore(), loadIdentity: { carolId }, fetchBundle: { E2EEClient.parseBundle(bundles[$0]) })
        var carolMsgs: [(String, String)] = []
        for i in 0..<3 { let t = "carol(swift)→alice #\(i)"; carolMsgs.append((t, try await carol.encryptDirect("alice", t)!)) }

        func list(_ xs: [(String, String)]) -> JSON { .array(xs.map { .object([("text", .string($0.0)), ("env", .string($0.1))]) }) }
        let json = JSON.object([
            ("implementation", .string("swift")),
            ("direct", list(direct)),
            ("groupKeyPackets", .array(keyPackets.map { .string($0) })),
            ("group", list(group)),
            ("carol", .object([("bundle", .string(allBundles["carol"]!)), ("messages", list(carolMsgs))])),
        ]).text
        try json.write(toFile: out, atomically: true, encoding: .utf8)
        print("replies written to \(out)")
    }
}
