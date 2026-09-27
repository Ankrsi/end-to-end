package com.e2ecrypto

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher

/** In-memory store (tests, or state you don't need to keep). */
class MemoryStore : SessionStore {
    private val map = ConcurrentHashMap<String, String>()
    override suspend fun get(key: String) = map[key]
    override suspend fun set(key: String, value: String) { map[key] = value }
    override suspend fun del(key: String) { map.remove(key) }
    val keys: Set<String> get() = map.keys
}

class PrefixStore(private val base: SessionStore, private val prefix: String) : SessionStore {
    override suspend fun get(key: String) = base.get(prefix + key)
    override suspend fun set(key: String, value: String) = base.set(prefix + key, value)
    override suspend fun del(key: String) = base.del(prefix + key)
}

/**
 * Encrypts every value with AES-256-GCM before it reaches [base].
 * Format: base64(nonce(12) || ciphertext+tag) — same as the JS package.
 */
class EncryptedStore(private val base: SessionStore, private val key: suspend () -> ByteArray) : SessionStore {
    override suspend fun get(key: String): String? {
        val raw = (base.get(key) ?: return null).unb64()
        val cipher = Aead.gcm(Cipher.DECRYPT_MODE, this.key(), raw.copyOfRange(0, 12))
        return Bytes.utf8(cipher.doFinal(raw, 12, raw.size - 12))
    }

    override suspend fun set(key: String, value: String) {
        val nonce = Bytes.random(12)
        val ct = Aead.gcm(Cipher.ENCRYPT_MODE, this.key(), nonce).doFinal(Bytes.utf8(value))
        base.set(key, Bytes.concat(nonce, ct).b64())
    }

    override suspend fun del(key: String) = base.del(key)

    companion object {
        /** A 32-byte key kept in [secureStore] under [name], created on first use. */
        fun masterKeyFrom(secureStore: SessionStore, name: String = "e2e_master_key"): suspend () -> ByteArray {
            val mutex = Mutex()
            var cached: ByteArray? = null
            return {
                cached ?: mutex.withLock {
                    cached ?: (secureStore.get(name)?.unb64() ?: Bytes.random(32).also { secureStore.set(name, it.b64()) })
                        .also { cached = it }
                }
            }
        }
    }
}

/**
 * Everything a chat app needs, behind one object (port of the JS E2EEClient).
 *
 * You provide: [secureStore] (Keystore/Keychain-backed, small), [store] (bulk; encrypted for you),
 * [uploadBundle] and [fetchBundle] for your server. Call [init] once after login, then
 * encrypt/decrypt strings. How envelope strings travel is up to you.
 */
class E2EEClient(
    private val secureStore: SessionStore,
    store: SessionStore,
    private val uploadBundle: suspend (bundle: String) -> Unit,
    fetchBundle: suspend (userId: String) -> String?,
    /** A queued group message was decrypted after its sender key arrived. `meta` is what you passed in. */
    private val onPendingDecrypted: (suspend (meta: String?, plaintext: String) -> Unit)? = null,
    private val identityKey: String = "e2e_identity",
    masterKeyName: String = "e2e_master_key",
    private val oneTimePreKeyCount: Int = 10,
) {
    /** Encrypted view of the bulk store; sessions, sender keys and the pending queue live here. */
    val store: SessionStore = EncryptedStore(store, EncryptedStore.masterKeyFrom(secureStore, masterKeyName))
    val sessions = SessionManager(this.store, ::loadIdentity) { parseBundle(fetchBundle(it)) }

    private val initMutex = Mutex()
    private var initialized = false
    @Volatile private var identityCache: Identity? = null

    suspend fun loadIdentity(): Identity? =
        identityCache ?: secureStore.get(identityKey)?.let { X3dh.deserializeIdentity(it) }?.also { identityCache = it }

    /** Creates this device's identity on first run and uploads its public bundle. Safe to call repeatedly. */
    suspend fun init() = initMutex.withLock {
        if (initialized) return@withLock
        val identity = loadIdentity() ?: X3dh.createIdentity(oneTimePreKeyCount).also {
            secureStore.set(identityKey, X3dh.serializeIdentity(it))
            identityCache = it
        }
        uploadBundle(serializeBundle(X3dh.publicBundle(identity)))   // public keys only
        initialized = true
    }

    // 1:1
    suspend fun encryptDirect(peerId: String, plaintext: String) = sessions.encryptDirect(peerId, plaintext)
    suspend fun decryptDirect(senderId: String, value: String) = sessions.decryptDirect(senderId, value)
    suspend fun hasDirectSession(peerId: String) = sessions.hasDirectSession(peerId)
    suspend fun resetDirect(peerId: String) = sessions.resetDirect(peerId)
    /** Re-fetch a peer's bundle (e.g. when opening their chat) so a reinstall is noticed. */
    suspend fun refreshBundle(userId: String) = sessions.getBundle(userId, refresh = true)

    // Groups
    suspend fun encryptGroup(conversationId: String, memberIds: List<String>, plaintext: String, distribute: suspend (String, String) -> Unit) =
        sessions.encryptGroup(conversationId, memberIds, plaintext, distribute)
    suspend fun decryptGroup(conversationId: String, senderId: String, value: String) = sessions.decryptGroup(conversationId, senderId, value)
    suspend fun hasGroupKey(conversationId: String) = sessions.hasGroupKey(conversationId)
    suspend fun resetGroup(conversationId: String) = sessions.resetGroup(conversationId)

    sealed class GroupResult {
        data class Ok(val plaintext: String) : GroupResult()
        object Pending : GroupResult()
    }

    /**
     * Like [decryptGroup], but a message that arrives before its sender's key is queued: returns
     * [GroupResult.Pending], and once the key arrives ([acceptSenderKey]) the plaintext is passed to
     * onPendingDecrypted(meta, plaintext).
     */
    suspend fun decryptGroupOrQueue(conversationId: String, senderId: String, value: String, meta: String? = null): GroupResult =
        try {
            GroupResult.Ok(sessions.decryptGroup(conversationId, senderId, value))
        } catch (e: MissingSenderKeyException) {
            sessions.withLock(K_PENDING) {
                val list = readPending()
                if (list.none { it.value == value }) {
                    writePending((list + Pending(conversationId, senderId, value, meta)).takeLast(MAX_PENDING))
                }
            }
            GroupResult.Pending
        }

    /** A sender-key packet from a group member. Decrypts queued messages it unlocks. Returns the conversation id. */
    suspend fun acceptSenderKey(senderId: String, envelope: String): String {
        val conversationId = sessions.acceptSenderKey(senderId, envelope)
        retryPending(conversationId, senderId)
        return conversationId
    }

    private data class Pending(val conversationId: String, val senderId: String, val value: String, val meta: String?)

    private suspend fun readPending(): List<Pending> =
        store.get(K_PENDING)?.let { s ->
            Json.parseToJsonElement(s).jsonArray.map {
                val o = it.jsonObject
                Pending(o.str("conversationId"), o.str("senderId"), o.str("value"), o["meta"]?.takeIf { m -> m !is JsonNull }?.jsonPrimitive?.content)
            }
        } ?: emptyList()

    private suspend fun writePending(list: List<Pending>) = store.set(K_PENDING, buildJsonArray {
        list.forEach { p ->
            add(buildJsonObject {
                put("conversationId", p.conversationId); put("senderId", p.senderId); put("value", p.value)
                put("meta", p.meta?.let { JsonPrimitive(it) } ?: JsonNull)
            })
        }
    }.toString())

    private suspend fun retryPending(conversationId: String, senderId: String) {
        val done = sessions.withLock(K_PENDING) {
            val list = readPending()
            val keep = ArrayList<Pending>()
            val out = ArrayList<Pair<String?, String>>()
            for (p in list) {
                if (p.conversationId != conversationId || p.senderId != senderId) { keep.add(p); continue }
                try {
                    out.add(p.meta to sessions.decryptGroup(conversationId, senderId, p.value))
                } catch (e: MissingSenderKeyException) {
                    keep.add(p)   // needs a newer key
                } catch (e: Exception) {
                    // undecryptable: drop
                }
            }
            if (keep.size != list.size) writePending(keep)
            out
        }
        // Outside the lock, so the callback may queue/decrypt more messages.
        for ((meta, text) in done) runCatching { onPendingDecrypted?.invoke(meta, text) }
    }

    companion object {
        private const val BUNDLE_TAG = "x3dh1"
        private const val K_PENDING = "pending"
        private const val MAX_PENDING = 500

        /** Public bundle -> one string for your server (same format as the JS package). */
        fun serializeBundle(bundle: PublicBundle): String = buildJsonObject {
            put("v", BUNDLE_TAG)
            X3dh.bundleJson(bundle).forEach { (k, v) -> put(k, v) }
        }.toString()

        /** Server value -> bundle, or null if missing / not an e2e-crypto bundle. */
        fun parseBundle(value: String?): PublicBundle? {
            if (value.isNullOrEmpty()) return null
            return try {
                val o = Json.parseToJsonElement(value).jsonObject
                if (o["v"]?.jsonPrimitive?.content != BUNDLE_TAG || o["identityDHPub"] == null) null else X3dh.bundleFrom(o)
            } catch (e: Exception) {
                null
            }
        }
    }
}
