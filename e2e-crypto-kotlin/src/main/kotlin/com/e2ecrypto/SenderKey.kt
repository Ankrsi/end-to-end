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

/** One member's sending chain in a group. `signPrivate` is only present on your own state. */
class SenderKeyState(
    var chainKey: ByteArray,
    var iteration: Int,
    val signPublic: ByteArray,
    val signPrivate: ByteArray? = null,
    val skipped: LinkedHashMap<Int, ByteArray> = LinkedHashMap(),
)

/** Sent to each member over their 1:1 session. */
data class SenderKeyDistribution(val chainKey: String, val iteration: Int, val signPublic: String) {
    fun toJson() = buildJsonObject { put("chainKey", chainKey); put("iteration", iteration); put("signPublic", signPublic) }

    companion object {
        fun from(o: JsonObject) = SenderKeyDistribution(o.str("chainKey"), o["iteration"]!!.jsonPrimitive.int, o.str("signPublic"))
    }
}

data class GroupMessage(val iteration: Int, /** base64 */ val ciphertext: String, /** base64 */ val signature: String)

/** Sender Keys: encrypt once per group message, whatever the group size. Wire-compatible with the JS package. */
object SenderKey {
    private const val MAX_SKIP = 1000

    fun create(): SenderKeyState {
        val sign = Curve.generateEd25519KeyPair()
        return SenderKeyState(Bytes.random(32), 0, sign.publicKey, sign.privateKey)
    }

    fun exportDistribution(state: SenderKeyState) =
        SenderKeyDistribution(state.chainKey.b64(), state.iteration, state.signPublic.b64())

    fun import(dist: SenderKeyDistribution) =
        SenderKeyState(dist.chainKey.unb64(), dist.iteration, dist.signPublic.unb64())

    fun encrypt(state: SenderKeyState, plaintext: String) = encrypt(state, Bytes.utf8(plaintext))

    fun encrypt(state: SenderKeyState, plaintext: ByteArray): GroupMessage {
        val signPrivate = state.signPrivate ?: throw IllegalStateException("This is an imported (receive-only) sender key state")
        val step = Kdf.chainKey(state.chainKey)
        val iteration = state.iteration
        state.chainKey = step.chainKey
        state.iteration += 1
        val ciphertext = Aead.encrypt(step.messageKey, plaintext)
        return GroupMessage(iteration, ciphertext.b64(), Curve.sign(signPrivate, ciphertext).b64())
    }

    fun decrypt(state: SenderKeyState, msg: GroupMessage): String = Bytes.utf8(decryptBytes(state, msg))

    /** Verifies the Ed25519 signature before touching any state. */
    fun decryptBytes(state: SenderKeyState, msg: GroupMessage): ByteArray {
        val ciphertext = msg.ciphertext.unb64()
        if (!Curve.verify(state.signPublic, ciphertext, msg.signature.unb64())) {
            throw SecurityException("Group message signature invalid — possible forgery")
        }
        state.skipped[msg.iteration]?.let { mk ->
            val pt = Aead.decrypt(mk, ciphertext)
            state.skipped.remove(msg.iteration)
            return pt
        }
        if (msg.iteration < state.iteration) throw SecurityException("Message key already used/expired (replay?) — rejecting")
        if (msg.iteration - state.iteration > MAX_SKIP) throw SecurityException("Too many skipped group messages")

        var ck = state.chainKey
        var messageKey: ByteArray? = null
        val newSkipped = ArrayList<Pair<Int, ByteArray>>()
        for (i in state.iteration..msg.iteration) {
            val step = Kdf.chainKey(ck)
            ck = step.chainKey
            if (i < msg.iteration) newSkipped.add(i to step.messageKey) else messageKey = step.messageKey
        }
        val plaintext = Aead.decrypt(messageKey!!, ciphertext)

        state.chainKey = ck
        state.iteration = msg.iteration + 1
        for ((i, mk) in newSkipped) state.skipped[i] = mk
        val it = state.skipped.keys.iterator()
        while (state.skipped.size > MAX_SKIP && it.hasNext()) { it.next(); it.remove() }
        return plaintext
    }

    fun serialize(state: SenderKeyState): String = buildJsonObject {
        put("v", 1)
        put("chainKey", state.chainKey.b64())
        put("iteration", state.iteration)
        put("signPublic", state.signPublic.b64())
        put("signPrivate", state.signPrivate?.let { JsonPrimitive(it.b64()) } ?: JsonNull)
        put("skipped", buildJsonArray { state.skipped.forEach { (i, mk) -> add(buildJsonArray { add(JsonPrimitive(i)); add(JsonPrimitive(mk.b64())) }) } })
    }.toString()

    fun deserialize(json: String): SenderKeyState {
        val j = Json.parseToJsonElement(json).jsonObject
        require(j["v"]?.jsonPrimitive?.int == 1) { "Unsupported sender key format version" }
        val skipped = LinkedHashMap<Int, ByteArray>()
        for (e in j["skipped"]!!.jsonArray) {
            val p = e.jsonArray
            skipped[p[0].jsonPrimitive.int] = p[1].jsonPrimitive.content.unb64()
        }
        val sp = j["signPrivate"]
        return SenderKeyState(
            j.str("chainKey").unb64(), j["iteration"]!!.jsonPrimitive.int, j.str("signPublic").unb64(),
            if (sp == null || sp is JsonNull) null else sp.jsonPrimitive.content.unb64(), skipped,
        )
    }
}
