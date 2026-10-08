package com.e2ecrypto

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Same scenarios as the JS runSelfTest: out-of-order, concurrent, crossed handshakes, replay, groups. */
class SessionTest {
    private val server = HashMap<String, PublicBundle>()

    private fun user(name: String): SessionManager {
        val id = X3dh.createIdentity()
        server[name] = X3dh.publicBundle(id)
        return SessionManager(MemoryStore(), { id }, { server[it] })
    }

    @Test fun `1to1 out of order`(): Unit = runBlocking {
        val a = user("a1"); val b = user("b1")
        val sent = (0 until 50).map { a.encryptDirect("b1", "m$it")!! to "m$it" }
        for ((env, text) in sent.shuffled()) assertEquals(text, b.decryptDirect("a1", env))
    }

    @Test fun `1to1 concurrent decrypts`(): Unit = runBlocking {
        val a = user("a2"); val b = user("b2")
        val sent = (0 until 50).map { a.encryptDirect("b2", "m$it")!! to "m$it" }.shuffled()
        val got = sent.map { (env, _) -> async(kotlinx.coroutines.Dispatchers.Default) { b.decryptDirect("a2", env) } }.awaitAll()
        sent.forEachIndexed { i, (_, text) -> assertEquals(text, got[i]) }
    }

    @Test fun `crossed handshakes converge`(): Unit = runBlocking {
        val a = user("a3"); val b = user("b3")
        val fromA = (0 until 10).map { async { a.encryptDirect("b3", "a$it")!! } }.awaitAll()
        val fromB = (0 until 10).map { async { b.encryptDirect("a3", "b$it")!! } }.awaitAll()
        fromA.withIndex().shuffled().forEach { (i, e) -> assertEquals("a$i", b.decryptDirect("a3", e)) }
        fromB.withIndex().shuffled().forEach { (i, e) -> assertEquals("b$i", a.decryptDirect("b3", e)) }
        repeat(5) {
            assertEquals("x$it", b.decryptDirect("a3", a.encryptDirect("b3", "x$it")!!))
            assertEquals("y$it", a.decryptDirect("b3", b.encryptDirect("a3", "y$it")!!))
        }
    }

    @Test fun `replay rejected and session survives`(): Unit = runBlocking {
        val a = user("a4"); val b = user("b4")
        val e = a.encryptDirect("b4", "once")!!
        assertEquals("once", b.decryptDirect("a4", e))
        assertFailsWith<Exception> { b.decryptDirect("a4", e) }
        assertEquals("next", b.decryptDirect("a4", a.encryptDirect("b4", "next")!!))
    }

    @Test fun `handshake stops after reply and plaintext passes through`(): Unit = runBlocking {
        val a = user("a5"); val b = user("b5")
        val first = a.encryptDirect("b5", "hi")!!
        assertNotNull((Envelope.parse(first) as Envelope.Direct).hs)
        b.decryptDirect("a5", first)
        a.decryptDirect("b5", b.encryptDirect("a5", "back")!!)
        assertNull((Envelope.parse(a.encryptDirect("b5", "again")!!) as Envelope.Direct).hs)
        assertEquals("plain", b.decryptDirect("a5", "plain"))
        assertNull(a.encryptDirect("nobody", "x"))
    }

    @Test fun `groups out of order, late key, rotation`(): Unit = runBlocking {
        val a = user("ga"); val b = user("gb"); val c = user("gc")
        val users = mapOf("gb" to b, "gc" to c)
        val packets = ArrayList<Pair<String, String>>()
        val sent = (0 until 50).map { a.encryptGroup("g", listOf("gb", "gc"), "g$it") { to, env -> packets.add(to to env) }!! to "g$it" }
        assertFailsWith<MissingSenderKeyException> { b.decryptGroup("g", "ga", sent[0].first) }
        for ((to, env) in packets) users[to]!!.acceptSenderKey("ga", env)
        for (u in listOf(b, c)) {
            val order = sent.shuffled()
            val got = order.map { (env, _) -> async(kotlinx.coroutines.Dispatchers.Default) { u.decryptGroup("g", "ga", env) } }.awaitAll()
            order.forEachIndexed { i, (_, text) -> assertEquals(text, got[i]) }
        }
        packets.clear()
        a.resetGroup("g")
        val rotated = a.encryptGroup("g", listOf("gb"), "carol gone") { to, env -> packets.add(to to env) }!!
        assertEquals(1, packets.size)
        b.acceptSenderKey("ga", packets[0].second)
        assertEquals("carol gone", b.decryptGroup("g", "ga", rotated))
        assertFailsWith<MissingSenderKeyException> { c.decryptGroup("g", "ga", rotated) }
    }

    @Test fun `client - identity persists, store encrypted, pending queue`(): Unit = runBlocking {
        val bundles = HashMap<String, String>()
        fun client(name: String, sec: SessionStore, bulk: SessionStore, onPending: (suspend (String?, String) -> Unit)? = null) =
            E2EEClient(sec, bulk, { bundles[name] = it }, { bundles[it] }, onPending)
        val aSec = MemoryStore(); val aBulk = MemoryStore()
        val delivered = ArrayList<Pair<String?, String>>()
        val a = client("ca", aSec, aBulk)
        val b = client("cb", MemoryStore(), MemoryStore()) { meta, text -> delivered.add(meta to text) }
        listOf(async { a.init() }, async { a.init() }, async { b.init() }).awaitAll()

        assertEquals("hello", b.decryptDirect("ca", a.encryptDirect("cb", "hello")!!))
        val before = bundles["ca"]
        val a2 = client("ca", aSec, aBulk)   // app restart
        a2.init()
        assertEquals(before, bundles["ca"])
        assertEquals("two", b.decryptDirect("ca", a2.encryptDirect("cb", "two")!!))
        assertTrue(aBulk.keys.isNotEmpty())
        for (k in aBulk.keys) assertTrue(!aBulk.get(k)!!.contains("identityDH") && !aBulk.get(k)!!.startsWith("{"), "stored in clear: $k")

        val keyPackets = ArrayList<String>()
        val m1 = a2.encryptGroup("grp", listOf("cb"), "first") { _, env -> keyPackets.add(env) }!!
        val m2 = a2.encryptGroup("grp", listOf("cb"), "second") { _, _ -> }!!
        assertEquals(E2EEClient.GroupResult.Pending, b.decryptGroupOrQueue("grp", "ca", m2, "2"))
        assertEquals(E2EEClient.GroupResult.Pending, b.decryptGroupOrQueue("grp", "ca", m1, "1"))
        assertEquals("grp", b.acceptSenderKey("ca", keyPackets[0]))
        assertEquals(listOf<Pair<String?, String>>("1" to "first", "2" to "second"), delivered.sortedBy { it.first })
    }

    @Test fun `bundle format`() {
        val b = X3dh.publicBundle(X3dh.createIdentity())
        assertEquals(b, E2EEClient.parseBundle(E2EEClient.serializeBundle(b)))
        assertNull(E2EEClient.parseBundle("bGVnYWN5LWRoLWtleQ=="))
        assertNull(E2EEClient.parseBundle(null))
        assertNull(E2EEClient.parseBundle("{\"v\":\"other\"}"))
        assertTrue(E2EEClient.serializeBundle(b).startsWith("{\"v\":\"x3dh1\""))
    }
}
