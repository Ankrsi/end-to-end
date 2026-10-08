package com.e2ecrypto

import java.security.SecureRandom

/** Byte helpers matching the JS package exactly (standard base64 with padding, UTF-8). */
object Bytes {
    private val rng = SecureRandom()

    fun random(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var off = 0
        for (p in parts) {
            p.copyInto(out, off)
            off += p.size
        }
        return out
    }

    /** Constant-time comparison (length is not secret). */
    fun equal(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)
    fun utf8(b: ByteArray): String = String(b, Charsets.UTF_8)
}

/** Standard base64 (not URL-safe). Own implementation so it works on Android < 26. */
object Base64 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private val LOOKUP = IntArray(128) { -1 }.also { t -> ALPHABET.forEachIndexed { i, c -> t[c.code] = i } }

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i + 2 < bytes.size) {
            val n = (bytes[i].toInt() and 0xff shl 16) or (bytes[i + 1].toInt() and 0xff shl 8) or (bytes[i + 2].toInt() and 0xff)
            sb.append(ALPHABET[n shr 18]).append(ALPHABET[n shr 12 and 63]).append(ALPHABET[n shr 6 and 63]).append(ALPHABET[n and 63])
            i += 3
        }
        when (bytes.size - i) {
            1 -> {
                val n = bytes[i].toInt() and 0xff shl 16
                sb.append(ALPHABET[n shr 18]).append(ALPHABET[n shr 12 and 63]).append("==")
            }
            2 -> {
                val n = (bytes[i].toInt() and 0xff shl 16) or (bytes[i + 1].toInt() and 0xff shl 8)
                sb.append(ALPHABET[n shr 18]).append(ALPHABET[n shr 12 and 63]).append(ALPHABET[n shr 6 and 63]).append('=')
            }
        }
        return sb.toString()
    }

    fun decode(str: String): ByteArray {
        val clean = str.trimEnd('=')
        if (clean.length % 4 == 1) throw IllegalArgumentException("e2e-crypto: invalid base64")
        val out = ByteArray(clean.length * 3 / 4)
        var buffer = 0
        var bits = 0
        var o = 0
        for (ch in clean) {
            val v = if (ch.code < 128) LOOKUP[ch.code] else -1
            if (v < 0) throw IllegalArgumentException("e2e-crypto: invalid base64")
            buffer = (buffer shl 6 or v) and 0xffffff
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = (buffer shr bits and 0xff).toByte()
            }
        }
        return out
    }
}

internal fun ByteArray.b64(): String = Base64.encode(this)
internal fun String.unb64(): ByteArray = Base64.decode(this)
