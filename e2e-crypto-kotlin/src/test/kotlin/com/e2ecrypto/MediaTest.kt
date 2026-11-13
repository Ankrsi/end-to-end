package com.e2ecrypto

import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import java.net.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MediaTest {
    /** Serves [body] over local HTTP and passes the server's base url to [block]. */
    private fun serve(body: ByteArray, block: suspend (String) -> Unit) {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { ex ->
            if (ex.requestURI.path.contains("missing")) { ex.sendResponseHeaders(404, -1); ex.close(); return@createContext }
            ex.sendResponseHeaders(200, body.size.toLong()); ex.responseBody.use { it.write(body) }
        }
        server.start()
        try { runBlocking { block("http://127.0.0.1:${server.address.port}") } } finally { server.stop(0) }
    }

    @Test fun `round trip, type and tamper`() {
        val f = Media.encryptFile(Bytes.utf8("hello photo"))
        serve(f.data) { base ->
            val out = Media.decryptFile(Base64.encode(f.key), "$base/media/photo.JPEG?token=abc")
            assertEquals("hello photo", Bytes.utf8(out.data))
            assertEquals("jpeg", out.type)
            assertFailsWith<Exception> { Media.decryptFile(Base64.encode(ByteArray(32)), "$base/x.png") }
            assertFailsWith<Exception> { Media.decryptFile(Base64.encode(f.key), "$base/missing.png") }
        }
    }

    @Test fun `decrypts a file locked by the JS package`() {
        val data = Base64.decode("nTdjzZ3jGmJsIwuVMdu2MNI4q+vnsbQEd30lGKENj9JGHoa6nkSXbzK0rxxdtJIV9hbZMus=")
        serve(data) { base ->
            val out = Media.decryptFile("MPoOv4q5P9T2Wkr9su3y64NegtUg8Ff7b84jgnsFCV0=", "$base/clip.mp4")
            assertEquals("hello from js", Bytes.utf8(out.data))
            assertEquals("mp4", out.type)
        }
    }
}
