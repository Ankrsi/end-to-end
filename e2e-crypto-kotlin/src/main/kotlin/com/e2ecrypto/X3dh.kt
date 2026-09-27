package com.e2ecrypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Private, on-device identity. Persist with [X3dh.serializeIdentity] in secure storage. */
class Identity(
    val identitySign: KeyPair,
    val identityDH: KeyPair,
    val signedPreKey: KeyPair,
    val signedPreKeySig: ByteArray,
    val oneTimePreKeys: List<KeyPair>,
)

/** Public keys only (base64). This is what the server stores. */
data class PublicBundle(
    val identitySignPub: String,
    val identityDHPub: String,
    val signedPreKeyPub: String,
    val signedPreKeySig: String,
    val oneTimePreKeys: List<String>,
)

class HandshakeResult(
    val sharedSecret: ByteArray,
    /** base64 — sent to the responder with the first message */
    val ephemeralPublicRaw: String,
    val usedOneTimePreKeyIndex: Int?,
    val bobSignedPreKeyPublicRaw: ByteArray,
)

object X3dh {
    fun createIdentity(oneTimePreKeyCount: Int = 10): Identity {
        val identitySign = Curve.generateEd25519KeyPair()
        val signedPreKey = Curve.generateX25519KeyPair()
        return Identity(
            identitySign = identitySign,
            identityDH = Curve.generateX25519KeyPair(),
            signedPreKey = signedPreKey,
            signedPreKeySig = Curve.sign(identitySign.privateKey, signedPreKey.publicKey),
            oneTimePreKeys = List(oneTimePreKeyCount) { Curve.generateX25519KeyPair() },
        )
    }

    fun publicBundle(identity: Identity) = PublicBundle(
        identitySignPub = identity.identitySign.publicKey.b64(),
        identityDHPub = identity.identityDH.publicKey.b64(),
        signedPreKeyPub = identity.signedPreKey.publicKey.b64(),
        signedPreKeySig = identity.signedPreKeySig.b64(),
        oneTimePreKeys = identity.oneTimePreKeys.map { it.publicKey.b64() },
    )

    private fun combineDH(vararg parts: ByteArray): ByteArray =
        Kdf.hkdf(Bytes.concat(ByteArray(32) { 0xff.toByte() }, *parts), ByteArray(32), "E2EChat-X3DH", 32)

    /** Initiator: verifies the peer's signed prekey, then derives the shared secret. */
    fun initiateHandshake(my: Identity, their: PublicBundle, usedOneTimePreKeyIndex: Int = 0): HandshakeResult {
        val spk = their.signedPreKeyPub.unb64()
        if (!Curve.verify(their.identitySignPub.unb64(), spk, their.signedPreKeySig.unb64())) {
            throw SecurityException("Signed prekey signature invalid — possible tampering")
        }
        val theirIdentityDH = their.identityDHPub.unb64()
        val ephemeral = Curve.generateX25519KeyPair()
        val dh1 = Curve.dh(my.identityDH.privateKey, spk)
        val dh2 = Curve.dh(ephemeral.privateKey, theirIdentityDH)
        val dh3 = Curve.dh(ephemeral.privateKey, spk)
        var dh4 = ByteArray(0)
        var used: Int? = null
        if (their.oneTimePreKeys.size > usedOneTimePreKeyIndex) {
            dh4 = Curve.dh(ephemeral.privateKey, their.oneTimePreKeys[usedOneTimePreKeyIndex].unb64())
            used = usedOneTimePreKeyIndex
        }
        return HandshakeResult(combineDH(dh1, dh2, dh3, dh4), ephemeral.publicKey.b64(), used, spk)
    }

    /** Responder: rebuilds the same shared secret from the initiator's identity + ephemeral keys (base64). */
    fun respondToHandshake(my: Identity, aliceIdentityDHPub: String, aliceEphemeralPub: String, oneTimePreKeyUsed: Int?): ByteArray {
        val aliceIk = aliceIdentityDHPub.unb64()
        val aliceEk = aliceEphemeralPub.unb64()
        val dh1 = Curve.dh(my.signedPreKey.privateKey, aliceIk)
        val dh2 = Curve.dh(my.identityDH.privateKey, aliceEk)
        val dh3 = Curve.dh(my.signedPreKey.privateKey, aliceEk)
        var dh4 = ByteArray(0)
        if (oneTimePreKeyUsed != null) {
            val otk = my.oneTimePreKeys.getOrNull(oneTimePreKeyUsed)
                ?: throw IllegalArgumentException("Unknown one-time prekey index $oneTimePreKeyUsed")
            dh4 = Curve.dh(otk.privateKey, aliceEk)
        }
        return combineDH(dh1, dh2, dh3, dh4)
    }

    // ─── Persistence (same JSON as the JS package). Contains PRIVATE keys: keep in secure storage. ───

    private fun pairJson(kp: KeyPair) = buildJsonObject {
        put("publicKey", kp.publicKey.b64()); put("privateKey", kp.privateKey.b64())
    }

    private fun pairFrom(o: JsonObject) =
        KeyPair(o.str("publicKey").unb64(), o.str("privateKey").unb64())

    fun serializeIdentity(identity: Identity): String = buildJsonObject {
        put("v", 1)
        put("identitySign", pairJson(identity.identitySign))
        put("identityDH", pairJson(identity.identityDH))
        put("signedPreKey", pairJson(identity.signedPreKey))
        put("signedPreKeySig", identity.signedPreKeySig.b64())
        put("oneTimePreKeys", buildJsonArray { identity.oneTimePreKeys.forEach { add(pairJson(it)) } })
    }.toString()

    fun deserializeIdentity(json: String): Identity {
        val j = Json.parseToJsonElement(json).jsonObject
        require(j["v"]?.jsonPrimitive?.int == 1) { "Unsupported identity format version" }
        return Identity(
            identitySign = pairFrom(j.obj("identitySign")),
            identityDH = pairFrom(j.obj("identityDH")),
            signedPreKey = pairFrom(j.obj("signedPreKey")),
            signedPreKeySig = j.str("signedPreKeySig").unb64(),
            oneTimePreKeys = j["oneTimePreKeys"]!!.jsonArray.map { pairFrom(it.jsonObject) },
        )
    }

    /** Bundle <-> JSON object (without the version tag; see [E2EEClient.serializeBundle]). */
    internal fun bundleJson(b: PublicBundle) = buildJsonObject {
        put("identitySignPub", b.identitySignPub)
        put("identityDHPub", b.identityDHPub)
        put("signedPreKeyPub", b.signedPreKeyPub)
        put("signedPreKeySig", b.signedPreKeySig)
        put("oneTimePreKeys", JsonArray(b.oneTimePreKeys.map { kotlinx.serialization.json.JsonPrimitive(it) }))
    }

    internal fun bundleFrom(o: JsonObject) = PublicBundle(
        identitySignPub = o.str("identitySignPub"),
        identityDHPub = o.str("identityDHPub"),
        signedPreKeyPub = o.str("signedPreKeyPub"),
        signedPreKeySig = o.str("signedPreKeySig"),
        oneTimePreKeys = o["oneTimePreKeys"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList(),
    )
}

internal fun JsonObject.str(key: String): String =
    this[key]?.jsonPrimitive?.content ?: throw IllegalArgumentException("missing $key")

internal fun JsonObject.obj(key: String): JsonObject =
    this[key]?.jsonObject ?: throw IllegalArgumentException("missing $key")
