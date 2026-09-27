# e2e-crypto-kotlin

Kotlin/JVM port of [`e2e-crypto`](../e2e-crypto): **X3DH**, **Double Ratchet** (1:1) and **Sender
Keys** (groups), plus the same `SessionManager` and `E2EEClient`. It uses the same wire format as
the JS and Swift libraries, so Android, iOS and React Native users can chat with each other.
`npm run test:interop` in the server project checks this.

- Android (minSdk 21+, AGP 7+) and any JVM 11+ (servers, bots).
- Crypto: Bouncy Castle for X25519/Ed25519; the platform's AES-GCM and HMAC-SHA256.
- Coroutine-based (`suspend`) API; concurrent calls for the same chat are serialized for you.

## Install

Build and publish it once (local Maven or your company repository):

```bash
cd e2e-crypto-kotlin
./gradlew publishToMavenLocal            # or configure a repository in build.gradle.kts
```

```kotlin
// app/build.gradle.kts
repositories { mavenLocal() }
dependencies { implementation("com.e2ecrypto:e2e-crypto-kotlin:1.2.0") }
```

Or copy `build/libs/e2e-crypto-kotlin-1.2.0.jar` (run `./gradlew jar`) into `app/libs` and add
its dependencies (`bcprov-jdk18on`, `kotlinx-serialization-json`, `kotlinx-coroutines-core`).

## Use

```kotlin
val e2e = E2EEClient(
    secureStore = KeystoreStore(context),                 // small secrets: identity + storage key
    store = PrefsStore(context.getSharedPreferences("e2e", MODE_PRIVATE)),   // bulk, encrypted by the library
    uploadBundle = { bundle -> api.uploadKeys(bundle) },  // store one string per user on your server
    fetchBundle = { userId -> api.getKeys(userId) },      // that string, or null
    onPendingDecrypted = { meta, text -> db.updateMessage(meta!!, text) },   // late group messages
)

// after login
e2e.init()

// 1:1
val env = e2e.encryptDirect(peerId, messageJson)          // null => peer has no keys yet
socket.send(env ?: messageJson)
val text = e2e.decryptDirect(senderId, incoming)          // plaintext passes through unchanged

// groups
val genv = e2e.encryptGroup(groupId, otherMemberIds, messageJson) { to, keyEnvelope ->
    socket.sendGroupKey(to, groupId, keyEnvelope)
}
e2e.acceptSenderKey(from, keyEnvelope)                    // on a group-key packet
when (val r = e2e.decryptGroupOrQueue(groupId, from, incoming, meta = messageId)) {
    is E2EEClient.GroupResult.Ok -> show(r.plaintext)
    E2EEClient.GroupResult.Pending -> show("Waiting for this message…")
}
e2e.resetGroup(groupId)          // a member left: rotate your sender key
e2e.refreshBundle(peerId)        // opening a chat: notice a reinstall
```

### Storage on Android

`SessionStore` is three suspend functions. The library encrypts everything in `store` with a key
it keeps in `secureStore`, so only `secureStore` needs hardware protection. Example adapters
(these are not included in the library; adapt them to your app):

```kotlin
class PrefsStore(private val prefs: SharedPreferences) : SessionStore {
    override suspend fun get(key: String) = prefs.getString(key, null)
    override suspend fun set(key: String, value: String) { prefs.edit().putString(key, value).apply() }
    override suspend fun del(key: String) { prefs.edit().remove(key).apply() }
}

/** Values encrypted with an AES key that never leaves the Android Keystore. */
class KeystoreStore(context: Context) : SessionStore {
    private val prefs = context.getSharedPreferences("e2e_secure", Context.MODE_PRIVATE)
    private val alias = "e2e_keystore_key"
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        return gen.generateKey()
    }
    override suspend fun get(key: String): String? {
        val raw = android.util.Base64.decode(prefs.getString(key, null) ?: return null, 0)
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw, 0, 12)) }
        return String(c.doFinal(raw, 12, raw.size - 12))
    }
    override suspend fun set(key: String, value: String) {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        prefs.edit().putString(key, android.util.Base64.encodeToString(c.iv + c.doFinal(value.toByteArray()), 0)).apply()
    }
    override suspend fun del(key: String) { prefs.edit().remove(key).apply() }
}
```

## Lower-level API

`SessionManager`, `X3dh`, `RatchetSession`, `SenderKey`, `Curve`, `Kdf`, `Aead`, `Base64` and
`Envelope.parse` / `Envelope.isEnvelope` are public for custom designs. Behaviour and limits match
the JS package's README (one device per account, no safety-number UI, and so on).

## Test

```bash
./gradlew test                               # unit tests
cd .. && npm run test:interop                # + cross-language test against JS (and Swift)
```
