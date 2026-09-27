# E2ECrypto (Swift)

Swift port of [`e2e-crypto`](../e2e-crypto): **X3DH**, **Double Ratchet** (1:1) and **Sender
Keys** (groups), plus the same `SessionManager` and `E2EEClient`. It uses the same wire format as
the JS and Kotlin libraries, so iOS, Android and React Native users can chat with each other.
`npm run test:interop` in the server project checks this.

- iOS 13+, macOS 10.15+, tvOS 13+, watchOS 6+. Uses Apple **CryptoKit**; no third-party code on Apple platforms.
- Linux (servers/CI): uses Apple's `swift-crypto`, which has the same API.
- `async`/`await` API; concurrent calls for the same chat are serialized for you.

## Install

Swift Package Manager: in Xcode, choose **File → Add Package Dependencies…** and add this folder
(or your git URL), or in `Package.swift`:

```swift
.package(path: "../e2e-crypto-swift")      // or .package(url: "<your git url>", from: "1.2.0")
// target dependency: .product(name: "E2ECrypto", package: "E2ECrypto")
```

## Use

```swift
import E2ECrypto

let e2e = E2EEClient(
    secureStore: KeychainStore(),                    // small secrets: identity + storage key
    store: FileStore(),                              // bulk, encrypted by the library
    uploadBundle: { bundle in try await api.uploadKeys(bundle) },   // one string per user on your server
    fetchBundle: { userId in try await api.getKeys(userId) },       // that string, or nil
    onPendingDecrypted: { meta, text in await db.updateMessage(meta!, text) }   // late group messages
)

try await e2e.initialize()                           // after login

// 1:1
let env = try await e2e.encryptDirect(peerId, messageJSON)          // nil => peer has no keys yet
socket.send(env ?? messageJSON)
let text = try await e2e.decryptDirect(senderId, incoming)          // plaintext passes through unchanged

// groups
let genv = try await e2e.encryptGroup(groupId, memberIds: otherMemberIds, messageJSON) { to, keyEnvelope in
    socket.sendGroupKey(to: to, groupId: groupId, keyEnvelope)
}
try await e2e.acceptSenderKey(from, keyEnvelope)                    // on a group-key packet
switch try await e2e.decryptGroupOrQueue(groupId, from, incoming, meta: messageId) {
case .ok(let text): show(text)
case .pending: show("Waiting for this message…")
}
try await e2e.resetGroup(groupId)        // a member left: rotate your sender key
try await e2e.refreshBundle(peerId)      // opening a chat: notice a reinstall
```

### Storage on iOS

`SessionStore` is three async methods. The library encrypts everything in `store` with a key it
keeps in `secureStore`, so only `secureStore` needs the Keychain. Example adapters (these are not
included in the library; adapt them to your app):

```swift
import Security

final class KeychainStore: SessionStore {
    private let service = "e2e-crypto"
    private func query(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key]
    }
    func get(_ key: String) async throws -> String? {
        var q = query(key); q[kSecReturnData as String] = true
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(decoding: d, as: UTF8.self)
    }
    func set(_ key: String, _ value: String) async throws {
        SecItemDelete(query(key) as CFDictionary)
        var q = query(key)
        q[kSecValueData as String] = Data(value.utf8)
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(q as CFDictionary, nil)
    }
    func del(_ key: String) async throws { SecItemDelete(query(key) as CFDictionary) }
}

/// Bulk state as files in Application Support (the library encrypts the contents).
final class FileStore: SessionStore {
    private let dir: URL = {
        let d = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("e2e")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }()
    private func url(_ key: String) -> URL { dir.appendingPathComponent(Data(key.utf8).base64EncodedString().replacingOccurrences(of: "/", with: "_")) }
    func get(_ key: String) async throws -> String? { try? String(contentsOf: url(key), encoding: .utf8) }
    func set(_ key: String, _ value: String) async throws { try value.write(to: url(key), atomically: true, encoding: .utf8) }
    func del(_ key: String) async throws { try? FileManager.default.removeItem(at: url(key)) }
}
```

## Lower-level API

`SessionManager`, `X3DH`, `RatchetSession`, `SenderKey`, `Curve`, `Kdf`, `Aead`, `Base64` and
`Envelope.parse` / `Envelope.isEnvelope` are public for custom designs. Behaviour and limits match
the JS package's README (one device per account, no safety-number UI, and so on).

Note: CryptoKit's Ed25519 signatures are randomized, so they differ byte for byte from the JS and
Kotlin libraries, but they are valid Ed25519 signatures and verify everywhere. The tests check this.

## Test

```bash
swift test                                   # macOS / Linux
cd .. && npm run test:interop                # + cross-language test against JS (and Kotlin); uses Docker if no Swift
```
