package com.e2ecrypto

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Cross-language test against vectors from the JS package (../testing/interop/gen-vectors.js).
 * Run with -Dinterop.vectors=<vectors.json> -Dinterop.replies=<out.json>; skipped otherwise.
 */
class InteropTest {
    private val vectorsPath = System.getProperty("interop.vectors").orEmpty()
    private val v: JsonObject? = vectorsPath.takeIf { it.isNotEmpty() && File(it).exists() }
        ?.let { Json.parseToJsonElement(File(it).readText()).jsonObject }

    private fun JsonObject.b(key: String) = this[key]!!.jsonPrimitive.content.unb64()
    private fun JsonObject.s(key: String) = this[key]!!.jsonPrimitive.content

    @Test fun primitives() {
        val p = (v ?: return println("interop vectors not provided — skipped")).obj("primitives")
        for (e in p["base64"]!!.jsonArray) {
            val o = e.jsonObject
            val n = o["len"]!!.jsonPrimitive.int
            val bytes = ByteArray(n) { ((250 + it) and 0xff).toByte() }
            assertEquals(o.s("bytes"), Base64.encode(bytes), "base64 len $n")
            assertContentEquals(bytes, Base64.decode(o.s("bytes")))
        }
        for (e in p["hkdf"]!!.jsonArray) {
            val o = e.jsonObject
            assertEquals(o.s("out"), Kdf.hkdf(o.b("ikm"), o.b("salt"), o.s("info"), o["length"]!!.jsonPrimitive.int).b64(), "hkdf ${o.s("info")}")
        }
        val c = p.obj("chain")
        val step = Kdf.chainKey(c.b("chainKey"))
        assertEquals(c.s("nextChainKey"), step.chainKey.b64())
        assertEquals(c.s("messageKey"), step.messageKey.b64())
        val a = p.obj("aead")
        assertEquals(a.s("ciphertext"), Aead.encrypt(a.b("messageKey"), Bytes.utf8(a.s("plaintext"))).b64())
        assertEquals(a.s("plaintext"), Bytes.utf8(Aead.decrypt(a.b("messageKey"), a.b("ciphertext"))))
        val x = p.obj("x25519")
        val pubA = ByteArray(32).also { org.bouncycastle.math.ec.rfc7748.X25519.scalarMultBase(x.b("privA"), 0, it, 0) }
        assertEquals(x.s("pubA"), pubA.b64())
        assertEquals(x.s("shared"), Curve.dh(x.b("privA"), x.b("pubB")).b64())
        val ed = p.obj("ed25519")
        val edPub = ByteArray(32).also { org.bouncycastle.math.ec.rfc8032.Ed25519.generatePublicKey(ed.b("seed"), 0, it, 0) }
        assertEquals(ed.s("publicKey"), edPub.b64())
        assertEquals(ed.s("signature"), Curve.sign(ed.b("seed"), ed.b("message")).b64())
        assertTrue(Curve.verify(edPub, ed.b("message"), ed.b("signature")))
    }

    @Test fun protocol(): Unit = runBlocking {
        val v = v ?: return@runBlocking println("interop vectors not provided — skipped")
        val bundles = v.obj("bundles").mapValues { it.value.jsonPrimitive.content }.toMutableMap()
        val bob = X3dh.deserializeIdentity(v.s("bobIdentity"))
        val sm = SessionManager(MemoryStore(), { bob }, { E2EEClient.parseBundle(bundles[it]) })

        // JS -> Kotlin, delivered out of order
        val d = v.obj("direct")
        val envs = d["envelopes"]!!.jsonArray.map { it.jsonPrimitive.content }
        val texts = d["plaintexts"]!!.jsonArray.map { it.jsonPrimitive.content }
        for (i in d["order"]!!.jsonArray.map { it.jsonPrimitive.int }) assertEquals(texts[i], sm.decryptDirect("alice", envs[i]))

        val g = v.obj("group")
        for (pkt in g["keyPackets"]!!.jsonArray) assertEquals("g1", sm.acceptSenderKey("alice", pkt.jsonPrimitive.content))
        val genvs = g["envelopes"]!!.jsonArray.map { it.jsonPrimitive.content }
        val gtexts = g["plaintexts"]!!.jsonArray.map { it.jsonPrimitive.content }
        for (i in g["order"]!!.jsonArray.map { it.jsonPrimitive.int }) assertEquals(gtexts[i], sm.decryptGroup("g1", "alice", genvs[i]))

        // Kotlin -> JS (checked by verify-replies.js)
        val out = System.getProperty("interop.replies").orEmpty()
        if (out.isEmpty()) return@runBlocking
        val direct = (0 until 6).map { "bob(kotlin)→alice #$it ✅ 你好" }.map { it to sm.encryptDirect("alice", it)!! }
        val keyPackets = ArrayList<String>()
        val group = (0 until 5).map { "bob(kotlin) group #$it" }.map { t -> t to sm.encryptGroup("g1", listOf("alice"), t) { _, env -> keyPackets.add(env) }!! }

        val carolId = X3dh.createIdentity()
        val carol = SessionManager(MemoryStore(), { carolId }, { E2EEClient.parseBundle(bundles[it]) })
        val carolMsgs = (0 until 3).map { "carol(kotlin)→alice #$it" }.map { it to carol.encryptDirect("alice", it)!! }

        fun list(xs: List<Pair<String, String>>) = buildJsonArray { xs.forEach { (t, e) -> add(buildJsonObject { put("text", t); put("env", e) }) } }
        File(out).writeText(buildJsonObject {
            put("implementation", "kotlin")
            put("direct", list(direct))
            put("groupKeyPackets", buildJsonArray { keyPackets.forEach { add(kotlinx.serialization.json.JsonPrimitive(it)) } })
            put("group", list(group))
            put("carol", buildJsonObject {
                put("bundle", E2EEClient.serializeBundle(X3dh.publicBundle(carolId)))
                put("messages", list(carolMsgs))
            })
        }.toString())
        println("replies written to $out")
    }
}
