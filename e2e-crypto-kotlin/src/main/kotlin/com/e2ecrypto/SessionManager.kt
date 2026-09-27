package com.e2ecrypto

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap

/** Async key-value store with string values. Values hold secrets: keep them encrypted at rest (see [E2EEClient]). */
interface SessionStore {
    suspend fun get(key: String): String?
    suspend fun set(key: String, value: String)
    suspend fun del(key: String)
}

class MissingSenderKeyException(val conversationId: String, val senderId: String) :
    Exception("No sender key from $senderId for $conversationId")

/** Sent with 1:1 messages until the peer replies, so they can build the session. */
data class Handshake(val ik: String, val ek: String, val otk: Int?)

/** Parsed wire envelope. Envelopes travel as JSON strings starting with `{"e2e"`. */
sealed class Envelope {
    data class Direct(val hs: Handshake?, val h: MessageHeader, val c: String) : Envelope()
    data class Group(val kid: String, val i: Int, val c: String, val s: String) : Envelope()

    companion object {
        fun parse(value: String?): Envelope? {
            if (value == null || !value.startsWith("{\"e2e\"")) return null
            return try {
                val o = Json.parseToJsonElement(value).jsonObject
                when (o["e2e"]?.jsonPrimitive?.content) {
                    "dr1" -> Direct(
                        o["hs"]?.takeIf { it !is JsonNull }?.jsonObject?.let {
                            Handshake(it.str("ik"), it.str("ek"), it["otk"]?.takeIf { v -> v !is JsonNull }?.jsonPrimitive?.intOrNull)
                        },
                        MessageHeader.from(o.obj("h")),
                        o.str("c"),
                    )
                    "sk1" -> Group(o.str("kid"), o["i"]!!.jsonPrimitive.int, o.str("c"), o.str("s"))
                    else -> null
                }
            } catch (e: Exception) {
                null
            }
        }

        fun isEnvelope(value: String?) = parse(value) != null
    }
}

/**
 * Session manager for chat apps (port of the JS SessionManager): one Double Ratchet session per
 * peer, Sender Keys per group, and the edge cases of real delivery — handshake repeated until the
 * peer replies, crossed handshakes, peer reinstalls, out-of-order and concurrent delivery,
 * sender-key rotation.
 */
class SessionManager(
    private val store: SessionStore,
    private val loadIdentity: suspend () -> Identity?,
    private val fetchBundle: suspend (String) -> PublicBundle?,
) {
    private val locks = ConcurrentHashMap<String, Mutex>()
    private val bundles = ConcurrentHashMap<String, PublicBundle>()

    /** Serialises read-modify-write of one record (socket, offline sync and push can race). */
    suspend fun <T> withLock(key: String, block: suspend () -> T): T =
        locks.getOrPut(key) { Mutex() }.withLock { block() }

    private suspend fun readJson(key: String): JsonObject? = store.get(key)?.let { Json.parseToJsonElement(it).jsonObject }

    private suspend fun identity(): Identity = loadIdentity() ?: throw IllegalStateException("E2EE identity not initialised")

    // ─── Bundles ───

    /** Cached bundle; `refresh` re-fetches it (falls back to the cache if offline). */
    suspend fun getBundle(userId: String, refresh: Boolean = false): PublicBundle? {
        if (!refresh) {
            bundles[userId]?.let { return it }
            readJson(K_BUNDLE + userId)?.let { X3dh.bundleFrom(it) }?.let { bundles[userId] = it; return it }
        }
        val bundle = try {
            fetchBundle(userId)
        } catch (e: Exception) {
            return bundles[userId] ?: readJson(K_BUNDLE + userId)?.let { X3dh.bundleFrom(it) } ?: throw e
        }
        if (bundle != null) {
            bundles[userId] = bundle
            store.set(K_BUNDLE + userId, X3dh.bundleJson(bundle).toString())
        } else {
            bundles.remove(userId)
            store.del(K_BUNDLE + userId)
        }
        return bundle
    }

    private suspend fun forgetBundle(userId: String) {
        bundles.remove(userId)
        store.del(K_BUNDLE + userId)
    }

    // ─── 1:1 ───

    private class Entry(val id: String, var state: String, val peerIk: String, var hs: Handshake?) {
        fun toJson() = buildJsonObject {
            put("id", id); put("state", state); put("peerIk", peerIk)
            hs?.let { put("hs", handshakeJson(it)) }
        }
    }

    private class DirectRecord(var sessions: MutableList<Entry>, var reset: Boolean) {
        fun toJson() = buildJsonObject {
            put("v", 1)
            put("sessions", buildJsonArray { sessions.forEach { add(it.toJson()) } })
            if (reset) put("reset", true)
        }
    }

    private suspend fun readDirect(peerId: String): DirectRecord {
        val j = readJson(K_DIRECT + peerId) ?: return DirectRecord(mutableListOf(), false)
        val sessions = j["sessions"]!!.jsonArray.map { e ->
            val o = e.jsonObject
            Entry(o.str("id"), o.str("state"), o.str("peerIk"), o["hs"]?.takeIf { it !is JsonNull }?.jsonObject?.let { handshakeFrom(it) })
        }.toMutableList()
        return DirectRecord(sessions, j["reset"]?.jsonPrimitive?.content == "true")
    }

    /** Returns the envelope string, or null if the peer has no bundle (can't encrypt to them). */
    suspend fun encryptDirect(peerId: String, plaintext: String): String? = withLock(K_DIRECT + peerId) {
        val identity = identity()
        val rec = readDirect(peerId)
        var entry = rec.sessions.firstOrNull()
        val bundle = getBundle(peerId)

        val needNew = entry == null || rec.reset || (bundle != null && entry.peerIk != bundle.identityDHPub)
        if (needNew) {
            if (bundle == null) return@withLock null
            val otkIndex = if (bundle.oneTimePreKeys.isEmpty()) 0 else (0 until bundle.oneTimePreKeys.size).random()
            val hs = X3dh.initiateHandshake(identity, bundle, otkIndex)   // verifies the signed prekey
            val session = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw)
            entry = Entry(
                hs.ephemeralPublicRaw, session.serialize(), bundle.identityDHPub,
                Handshake(identity.identityDH.publicKey.b64(), hs.ephemeralPublicRaw, hs.usedOneTimePreKeyIndex),
            )
            rec.sessions = (listOf(entry) + rec.sessions).take(MAX_SESSIONS).toMutableList()
            rec.reset = false
        }

        val session = RatchetSession.deserialize(entry!!.state)
        val msg = session.encrypt(plaintext)
        entry.state = session.serialize()
        store.set(K_DIRECT + peerId, rec.toJson().toString())

        buildJsonObject {
            put("e2e", "dr1")
            put("h", msg.header.toJson())
            put("c", msg.ciphertext)
            entry.hs?.let { put("hs", handshakeJson(it)) }
        }.toString()
    }

    /** Non-envelope input is returned unchanged (plaintext from clients without E2EE). Throws if it can't decrypt. */
    suspend fun decryptDirect(senderId: String, value: String): String {
        val env = Envelope.parse(value) ?: return value
        if (env !is Envelope.Direct) throw IllegalArgumentException("Expected a 1:1 envelope")

        return withLock(K_DIRECT + senderId) {
            val rec = readDirect(senderId)
            var isNew = false
            val candidates: List<Entry> = if (env.hs != null) {
                val existing = rec.sessions.firstOrNull { it.id == env.hs.ek }
                if (existing != null) listOf(existing) else {
                    val identity = identity()
                    val secret = X3dh.respondToHandshake(identity, env.hs.ik, env.hs.ek, env.hs.otk)
                    val session = RatchetSession.initAsReceiver(secret, identity.signedPreKey)
                    isNew = true
                    listOf(Entry(env.hs.ek, session.serialize(), env.hs.ik, null))
                }
            } else rec.sessions.toList()

            for (entry in candidates) {
                val session = RatchetSession.deserialize(entry.state)
                val plaintext = try {
                    session.decrypt(env.h, env.c)   // state unchanged on failure
                } catch (e: Exception) {
                    continue
                }
                entry.state = session.serialize()
                entry.hs = null   // the peer has this session now; stop sending the handshake
                rec.sessions = (listOf(entry) + rec.sessions.filter { it !== entry }).take(MAX_SESSIONS).toMutableList()
                store.set(K_DIRECT + senderId, rec.toJson().toString())

                // Peer reinstalled / new identity: our cached bundle is stale.
                if (isNew) {
                    val cached = bundles[senderId] ?: readJson(K_BUNDLE + senderId)?.let { X3dh.bundleFrom(it) }
                    if (cached != null && cached.identityDHPub != entry.peerIk) forgetBundle(senderId)
                }
                return@withLock plaintext
            }
            throw SecurityException("Unable to decrypt message from $senderId")
        }
    }

    suspend fun hasDirectSession(peerId: String): Boolean = readDirect(peerId).sessions.isNotEmpty()

    /** Next message to this peer starts a fresh handshake. Existing sessions still decrypt. */
    suspend fun resetDirect(peerId: String) = withLock(K_DIRECT + peerId) {
        if (store.get(K_DIRECT + peerId) == null) return@withLock
        val rec = readDirect(peerId)
        rec.reset = true
        store.set(K_DIRECT + peerId, rec.toJson().toString())
    }

    // ─── Groups ───

    /**
     * Encrypts once for the whole group. Our sender key is first sent (over 1:1 sessions) to
     * members who don't have it yet, via [distribute]. Returns null if a member has no bundle.
     */
    suspend fun encryptGroup(
        conversationId: String,
        memberIds: List<String>,
        plaintext: String,
        distribute: suspend (to: String, envelope: String) -> Unit,
    ): String? = withLock(K_GROUP_OWN + conversationId) {
        val memberBundles = LinkedHashMap<String, PublicBundle>()
        for (m in memberIds) memberBundles[m] = getBundle(m) ?: return@withLock null

        val existing = readJson(K_GROUP_OWN + conversationId)
        val kid = existing?.str("kid") ?: Bytes.random(12).b64()
        val state = existing?.let { SenderKey.deserialize(it.str("state")) } ?: SenderKey.create()
        val to = LinkedHashMap<String, String>()
        existing?.get("to")?.jsonObject?.forEach { (k, v) -> to[k] = v.jsonPrimitive.content }

        val missing = memberIds.filter { to[it] != memberBundles[it]!!.identityDHPub }
        if (missing.isNotEmpty()) {
            val body = buildJsonObject {
                put("t", "skdm"); put("conversationId", conversationId); put("kid", kid)
                put("dist", SenderKey.exportDistribution(state).toJson())
            }.toString()
            for (m in missing) {
                val env = encryptDirect(m, body) ?: return@withLock null
                distribute(m, env)
                to[m] = memberBundles[m]!!.identityDHPub
            }
        }

        val msg = SenderKey.encrypt(state, plaintext)
        store.set(K_GROUP_OWN + conversationId, buildJsonObject {
            put("v", 1); put("kid", kid); put("state", SenderKey.serialize(state))
            put("to", JsonObject(to.mapValues { JsonPrimitive(it.value) }))
        }.toString())

        buildJsonObject {
            put("e2e", "sk1"); put("kid", kid); put("i", msg.iteration); put("c", msg.ciphertext); put("s", msg.signature)
        }.toString()
    }

    /** Handles a sender-key distribution received over a 1:1 session. Returns its conversation id. */
    suspend fun acceptSenderKey(senderId: String, envelope: String): String {
        val packet = Json.parseToJsonElement(decryptDirect(senderId, envelope)).jsonObject
        if (packet["t"]?.jsonPrimitive?.content != "skdm") throw IllegalArgumentException("Not a sender key packet")
        val conversationId = packet.str("conversationId")
        val kid = packet.str("kid")
        val key = "$K_GROUP_RECV$conversationId.$senderId"
        withLock(key) {
            val keys = readJson(key)?.get("keys")?.jsonArray?.map { it.jsonObject }?.toMutableList() ?: mutableListOf()
            if (keys.any { it.str("kid") == kid }) return@withLock   // duplicate delivery
            val state = SenderKey.import(SenderKeyDistribution.from(packet.obj("dist")))
            val entry = buildJsonObject { put("kid", kid); put("state", SenderKey.serialize(state)) }
            store.set(key, buildJsonObject {
                put("v", 1)
                put("keys", buildJsonArray { (listOf(entry) + keys).take(MAX_SENDER_KEYS).forEach { add(it) } })
            }.toString())
        }
        return conversationId
    }

    /** Non-envelope input is returned unchanged. Throws [MissingSenderKeyException] if the sender's key hasn't arrived. */
    suspend fun decryptGroup(conversationId: String, senderId: String, value: String): String {
        val env = Envelope.parse(value) ?: return value
        if (env !is Envelope.Group) throw IllegalArgumentException("Expected a group envelope")
        val key = "$K_GROUP_RECV$conversationId.$senderId"
        return withLock(key) {
            val keys = readJson(key)?.get("keys")?.jsonArray?.map { it.jsonObject }?.toMutableList()
            val idx = keys?.indexOfFirst { it.str("kid") == env.kid } ?: -1
            if (keys == null || idx < 0) throw MissingSenderKeyException(conversationId, senderId)
            val state = SenderKey.deserialize(keys[idx].str("state"))
            val plaintext = SenderKey.decrypt(state, GroupMessage(env.i, env.c, env.s))
            keys[idx] = buildJsonObject { put("kid", env.kid); put("state", SenderKey.serialize(state)) }
            store.set(key, buildJsonObject { put("v", 1); put("keys", buildJsonArray { keys.forEach { add(it) } }) }.toString())
            plaintext
        }
    }

    suspend fun hasGroupKey(conversationId: String): Boolean = store.get(K_GROUP_OWN + conversationId) != null

    /** Drop our sender key so the next send rotates it (someone left / was removed). */
    suspend fun resetGroup(conversationId: String) = withLock(K_GROUP_OWN + conversationId) { store.del(K_GROUP_OWN + conversationId) }

    companion object {
        private const val MAX_SESSIONS = 3
        private const val MAX_SENDER_KEYS = 3
        private const val K_DIRECT = "dr."
        private const val K_BUNDLE = "bundle."
        private const val K_GROUP_OWN = "go."
        private const val K_GROUP_RECV = "gr."

        private fun handshakeJson(h: Handshake) = buildJsonObject {
            put("ik", h.ik); put("ek", h.ek); put("otk", h.otk?.let { JsonPrimitive(it) } ?: JsonNull)
        }

        private fun handshakeFrom(o: JsonObject) =
            Handshake(o.str("ik"), o.str("ek"), o["otk"]?.takeIf { it !is JsonNull }?.jsonPrimitive?.intOrNull)
    }
}

@Suppress("unused")
private fun JsonElement.isNull() = this is JsonNull
