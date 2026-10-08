package com.e2ecrypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** 1:1 message header: sender's current ratchet public key (base64), previous chain length, message number. */
data class MessageHeader(val dh: String, val pn: Int, val n: Int) {
    fun toJson() = buildJsonObject { put("dh", dh); put("pn", pn); put("n", n) }

    companion object {
        fun from(o: JsonObject) = MessageHeader(o.str("dh"), o["pn"]!!.jsonPrimitive.int, o["n"]!!.jsonPrimitive.int)
    }
}

class EncryptedMessage(val header: MessageHeader, /** base64 */ val ciphertext: String)

/** Double Ratchet session (Signal spec). Wire- and storage-compatible with the JS RatchetSession. */
class RatchetSession private constructor() {
    private var dhs: KeyPair? = null
    private var dhr: ByteArray? = null
    private var rk: ByteArray? = null
    private var cks: ByteArray? = null
    private var ckr: ByteArray? = null
    private var ns = 0
    private var nr = 0
    private var pn = 0
    private val skipped = LinkedHashMap<String, ByteArray>()   // "dhB64:n" -> message key, oldest first

    companion object {
        private const val MAX_SKIP = 1000
        private const val MAX_SKIPPED_TOTAL = 2000

        /** Initiator, right after [X3dh.initiateHandshake]. */
        fun initAsSender(sharedSecret: ByteArray, bobRatchetPublicRaw: ByteArray) = RatchetSession().apply {
            dhs = Curve.generateX25519KeyPair()
            dhr = bobRatchetPublicRaw
            val step = Kdf.rootKey(sharedSecret, Curve.dh(dhs!!.privateKey, bobRatchetPublicRaw))
            rk = step.rootKey
            cks = step.chainKey
        }

        /** Responder, right after [X3dh.respondToHandshake]. Pass identity.signedPreKey. */
        fun initAsReceiver(sharedSecret: ByteArray, bobRatchetKeyPair: KeyPair) = RatchetSession().apply {
            dhs = bobRatchetKeyPair
            rk = sharedSecret
        }

        fun deserialize(json: String): RatchetSession {
            val j = Json.parseToJsonElement(json).jsonObject
            require(j["v"]?.jsonPrimitive?.int == 1) { "Unsupported session format version" }
            fun raw(k: String): ByteArray? = j[k].let { if (it == null || it is JsonNull) null else it.jsonPrimitive.content.unb64() }
            return RatchetSession().apply {
                val d = j.obj("DHs")
                dhs = KeyPair(d.str("publicKey").unb64(), d.str("privateKey").unb64())
                dhr = raw("DHr"); rk = raw("RK"); cks = raw("CKs"); ckr = raw("CKr")
                ns = j["Ns"]!!.jsonPrimitive.int; nr = j["Nr"]!!.jsonPrimitive.int; pn = j["PN"]!!.jsonPrimitive.int
                for (e in j["skipped"]!!.jsonArray) {
                    val pair = e.jsonArray
                    skipped[pair[0].jsonPrimitive.content] = pair[1].jsonPrimitive.content.unb64()
                }
            }
        }
    }

    fun encrypt(plaintext: String, associatedData: ByteArray = ByteArray(0)) = encrypt(Bytes.utf8(plaintext), associatedData)

    fun encrypt(plaintext: ByteArray, associatedData: ByteArray = ByteArray(0)): EncryptedMessage {
        val ck = cks ?: throw IllegalStateException("Session cannot send yet — wait for the first message from the initiator")
        val step = Kdf.chainKey(ck)
        cks = step.chainKey
        val header = MessageHeader(dhs!!.publicKey.b64(), pn, ns)
        ns += 1
        return EncryptedMessage(header, Aead.encrypt(step.messageKey, plaintext, associatedData).b64())
    }

    /** Returns the UTF-8 plaintext. Throws on tampering/replay; the state is unchanged on failure. */
    fun decrypt(header: MessageHeader, ciphertextB64: String, associatedData: ByteArray = ByteArray(0)): String =
        Bytes.utf8(decryptBytes(header, ciphertextB64, associatedData))

    fun decryptBytes(header: MessageHeader, ciphertextB64: String, associatedData: ByteArray = ByteArray(0)): ByteArray {
        val ciphertext = ciphertextB64.unb64()

        // 1. Key already derived for an earlier out-of-order arrival?
        val skippedId = "${header.dh}:${header.n}"
        skipped[skippedId]?.let { mk ->
            val pt = Aead.decrypt(mk, ciphertext, associatedData)
            skipped.remove(skippedId)   // single-use
            return pt
        }

        // 2. Work on a draft; commit only after the message authenticates.
        val st = Draft(dhs!!, dhr, rk!!, cks, ckr, ns, nr, pn)
        val newSkipped = ArrayList<Pair<String, ByteArray>>()
        val remote = header.dh.unb64()
        if (st.dhr == null || !Bytes.equal(remote, st.dhr!!)) {
            skipMessageKeys(st, header.pn, newSkipped)   // finish the old receiving chain first
            dhRatchetStep(st, remote)
        }
        skipMessageKeys(st, header.n, newSkipped)
        if (header.n < st.nr) throw SecurityException("Message key already used/expired (replay?) — rejecting")
        val step = Kdf.chainKey(st.ckr!!)
        st.ckr = step.chainKey
        st.nr += 1

        val plaintext = Aead.decrypt(step.messageKey, ciphertext, associatedData)   // throws on tamper

        dhs = st.dhs; dhr = st.dhr; rk = st.rk; cks = st.cks; ckr = st.ckr; ns = st.ns; nr = st.nr; pn = st.pn
        for ((id, mk) in newSkipped) skipped[id] = mk
        val it = skipped.keys.iterator()
        while (skipped.size > MAX_SKIPPED_TOTAL && it.hasNext()) { it.next(); it.remove() }
        return plaintext
    }

    private class Draft(
        var dhs: KeyPair, var dhr: ByteArray?, var rk: ByteArray, var cks: ByteArray?, var ckr: ByteArray?,
        var ns: Int, var nr: Int, var pn: Int,
    )

    private fun dhRatchetStep(st: Draft, remote: ByteArray) {
        st.pn = st.ns
        st.ns = 0
        st.nr = 0
        st.dhr = remote
        var out = Kdf.rootKey(st.rk, Curve.dh(st.dhs.privateKey, remote))
        st.rk = out.rootKey
        st.ckr = out.chainKey
        st.dhs = Curve.generateX25519KeyPair()
        out = Kdf.rootKey(st.rk, Curve.dh(st.dhs.privateKey, remote))
        st.rk = out.rootKey
        st.cks = out.chainKey
    }

    private fun skipMessageKeys(st: Draft, untilN: Int, newSkipped: MutableList<Pair<String, ByteArray>>) {
        var ck = st.ckr ?: return
        if (st.nr + MAX_SKIP < untilN) throw SecurityException("Too many skipped messages")
        val dhB64 = st.dhr!!.b64()
        while (st.nr < untilN) {
            val step = Kdf.chainKey(ck)
            ck = step.chainKey
            newSkipped.add("$dhB64:${st.nr}" to step.messageKey)
            st.nr += 1
        }
        st.ckr = ck
    }

    /** Save after every encrypt/decrypt — the state advances with each message. Contains secrets. */
    fun serialize(): String = buildJsonObject {
        fun b64(x: ByteArray?) = x?.let { JsonPrimitive(it.b64()) } ?: JsonNull
        put("v", 1)
        put("DHs", buildJsonObject { put("publicKey", dhs!!.publicKey.b64()); put("privateKey", dhs!!.privateKey.b64()) })
        put("DHr", b64(dhr)); put("RK", b64(rk)); put("CKs", b64(cks)); put("CKr", b64(ckr))
        put("Ns", ns); put("Nr", nr); put("PN", pn)
        put("skipped", buildJsonArray { skipped.forEach { (id, mk) -> add(buildJsonArray { add(JsonPrimitive(id)); add(JsonPrimitive(mk.b64())) }) } })
    }.toString()
}
