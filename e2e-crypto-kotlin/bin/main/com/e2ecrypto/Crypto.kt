package com.e2ecrypto

import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Raw 32-byte keys, interchangeable with the JS package (noble / node-crypto backends). */
class KeyPair(val publicKey: ByteArray, val privateKey: ByteArray)

/** X25519 key agreement and Ed25519 signatures. */
object Curve {
    fun generateX25519KeyPair(): KeyPair {
        val priv = Bytes.random(32)
        val pub = ByteArray(32)
        X25519.scalarMultBase(priv, 0, pub, 0)
        return KeyPair(pub, priv)
    }

    fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        require(publicKey.size == 32) { "X25519 public key must be 32 bytes" }
        val out = ByteArray(32)
        if (!X25519.calculateAgreement(privateKey, 0, publicKey, 0, out, 0)) {
            throw GeneralSecurityException("X25519 agreement produced an all-zero secret")
        }
        return out
    }

    fun generateEd25519KeyPair(): KeyPair {
        val seed = Bytes.random(32)
        val pub = ByteArray(32)
        Ed25519.generatePublicKey(seed, 0, pub, 0)
        return KeyPair(pub, seed)
    }

    fun sign(privateKey: ByteArray, data: ByteArray): ByteArray =
        ByteArray(64).also { Ed25519.sign(privateKey, 0, data, 0, data.size, it, 0) }

    /** A malformed key or signature is just an invalid signature. */
    fun verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean = try {
        publicKey.size == 32 && signature.size == 64 &&
            Ed25519.verify(signature, 0, publicKey, 0, data, 0, data.size)
    } catch (e: Exception) {
        false
    }
}

/** HKDF-SHA256, the Double Ratchet KDFs and per-message AES-256-GCM — same constants as the JS package. */
object Kdf {
    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // An empty HMAC key is equivalent to 32 zero bytes (both are zero-padded to the block size),
        // and SecretKeySpec rejects empty keys.
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun hkdf(ikm: ByteArray, salt: ByteArray, info: String, length: Int): ByteArray {
        val prk = hmac(salt, ikm)
        val infoBytes = Bytes.utf8(info)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var off = 0
        var counter = 1
        while (off < length) {
            t = hmac(prk, Bytes.concat(t, infoBytes, byteArrayOf(counter.toByte())))
            val n = minOf(t.size, length - off)
            t.copyInto(out, off, 0, n)
            off += n
            counter++
        }
        return out
    }

    class RootStep(val rootKey: ByteArray, val chainKey: ByteArray)
    class ChainStep(val chainKey: ByteArray, val messageKey: ByteArray)

    /** KDF_RK: advances the root key with a new DH output. */
    fun rootKey(rootKey: ByteArray, dhOutput: ByteArray): RootStep {
        val out = hkdf(dhOutput, rootKey, "E2EChat-RootRatchet", 64)
        return RootStep(out.copyOfRange(0, 32), out.copyOfRange(32, 64))
    }

    private val MSG_KEY_CONST = byteArrayOf(0x01)
    private val CHAIN_KEY_CONST = byteArrayOf(0x02)

    /** KDF_CK: one symmetric ratchet step (shared by the 1:1 ratchet and Sender Keys). */
    fun chainKey(chainKey: ByteArray) = ChainStep(hmac(chainKey, CHAIN_KEY_CONST), hmac(chainKey, MSG_KEY_CONST))
}

/** AES-256-GCM with key + IV derived from a single-use message key. Output is ciphertext || 16-byte tag. */
object Aead {
    private fun derive(messageKey: ByteArray): Pair<ByteArray, ByteArray> {
        val out = Kdf.hkdf(messageKey, ByteArray(0), "E2EChat-MsgKey", 44)
        return out.copyOfRange(0, 32) to out.copyOfRange(32, 44)
    }

    fun encrypt(messageKey: ByteArray, plaintext: ByteArray, associatedData: ByteArray = ByteArray(0)): ByteArray {
        val (key, iv) = derive(messageKey)
        return gcm(Cipher.ENCRYPT_MODE, key, iv, associatedData).doFinal(plaintext)
    }

    /** Throws if the ciphertext, tag or associated data were tampered with. */
    fun decrypt(messageKey: ByteArray, blob: ByteArray, associatedData: ByteArray = ByteArray(0)): ByteArray {
        val (key, iv) = derive(messageKey)
        return gcm(Cipher.DECRYPT_MODE, key, iv, associatedData).doFinal(blob)
    }

    /** Raw AES-256-GCM with an explicit IV (used by the encrypted store). */
    internal fun gcm(mode: Int, key: ByteArray, iv: ByteArray, aad: ByteArray = ByteArray(0)): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            if (aad.isNotEmpty()) updateAAD(aad)
        }
}
