package com.e2ecrypto

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.security.GeneralSecurityException

// Chat photos, videos, voice notes and files are locked on the phone before upload (like WhatsApp):
//   1. every file gets its own new random key
//   2. the file is locked with that key, and only the locked copy is uploaded
//   3. the key goes inside the chat message, which is end-to-end encrypted
// So the server stores files it can't open, and never sees the keys.
//
// Locked file = nonce (24 bytes) + XChaCha20-Poly1305 ciphertext. Same format as the JS package.

/** [data] is uploaded; [key] is sent inside the e2e chat message (e.g. Base64.encode(key)). */
class EncryptedFile(val key: ByteArray, val data: ByteArray)

/** An unlocked file. [type] is the url's extension, e.g. "mp4", "pdf", "jpeg", "png" ("" if none). */
class DecryptedFile(val data: ByteArray, val type: String)

object Media {
    private const val NONCE_LENGTH = 24

    fun encryptFile(fileBytes: ByteArray): EncryptedFile {
        val key = Bytes.random(32)
        val nonce = Bytes.random(NONCE_LENGTH)
        return EncryptedFile(key, nonce + xchacha(true, key, nonce, fileBytes))
    }

    /**
     * Downloads the locked file from [url], unlocks it, and returns the data plus its type (the url's
     * extension). [key] is the base64 key from the chat message.
     * Throws if the download fails, the key is wrong or the file was changed.
     */
    suspend fun decryptFile(key: String, url: String): DecryptedFile = withContext(Dispatchers.IO) {
        val conn = URI(url).toURL().openConnection()
        if (conn is HttpURLConnection && conn.responseCode !in 200..299) {
            conn.disconnect()
            throw IOException("File download failed (${conn.responseCode})")
        }
        val locked = conn.getInputStream().use { it.readBytes() }
        DecryptedFile(unlock(Base64.decode(key), locked), fileType(url))
    }

    // "https://cdn/x/photo.JPEG?token=1#a" -> "jpeg"
    private fun fileType(url: String): String {
        val name = url.substringBefore('#').substringBefore('?').substringAfterLast('/')
        val dot = name.lastIndexOf('.')
        return if (dot > 0) name.substring(dot + 1).lowercase() else ""
    }

    /** Throws if the key is wrong or the file was changed. */
    internal fun unlock(key: ByteArray, data: ByteArray): ByteArray {
        if (data.size < NONCE_LENGTH + 16) throw GeneralSecurityException("Encrypted file is too short")
        val nonce = data.copyOfRange(0, NONCE_LENGTH)
        return xchacha(false, key, nonce, data.copyOfRange(NONCE_LENGTH, data.size))
    }

    // XChaCha20-Poly1305 = ChaCha20-Poly1305 with key HChaCha20(key, nonce[0..16]) and nonce 0000 + nonce[16..24].
    private fun xchacha(encrypt: Boolean, key: ByteArray, nonce: ByteArray, input: ByteArray): ByteArray {
        require(key.size == 32) { "File key must be 32 bytes" }
        val subKey = hchacha20(key, nonce)
        val subNonce = ByteArray(4) + nonce.copyOfRange(16, 24)
        val cipher = ChaCha20Poly1305()
        cipher.init(encrypt, AEADParameters(KeyParameter(subKey), 128, subNonce))
        val out = ByteArray(cipher.getOutputSize(input.size))
        return try {
            val n = cipher.processBytes(input, 0, input.size, out, 0)
            cipher.doFinal(out, n)
            out
        } catch (e: Exception) {
            throw GeneralSecurityException("Could not decrypt file: wrong key or file was changed", e)
        }
    }

    private fun hchacha20(key: ByteArray, nonce: ByteArray): ByteArray {
        fun le(b: ByteArray, i: Int) = (b[i].toInt() and 0xff) or ((b[i + 1].toInt() and 0xff) shl 8) or
            ((b[i + 2].toInt() and 0xff) shl 16) or ((b[i + 3].toInt() and 0xff) shl 24)
        val s = IntArray(16)
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574
        for (i in 0 until 8) s[4 + i] = le(key, i * 4)
        for (i in 0 until 4) s[12 + i] = le(nonce, i * 4)
        fun qr(a: Int, b: Int, c: Int, d: Int) {
            s[a] += s[b]; s[d] = (s[d] xor s[a]).rotateLeft(16)
            s[c] += s[d]; s[b] = (s[b] xor s[c]).rotateLeft(12)
            s[a] += s[b]; s[d] = (s[d] xor s[a]).rotateLeft(8)
            s[c] += s[d]; s[b] = (s[b] xor s[c]).rotateLeft(7)
        }
        repeat(10) {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        val out = ByteArray(32)
        intArrayOf(0, 1, 2, 3, 12, 13, 14, 15).forEachIndexed { j, w ->
            for (k in 0 until 4) out[j * 4 + k] = (s[w] ushr (8 * k)).toByte()
        }
        return out
    }
}
