'use strict';
const { gcm } = require('@noble/ciphers/aes');
const { hkdf } = require('./kdf');

const EMPTY = new Uint8Array(0);

// Derive a separate AES key + IV from the 32-byte message key, so raw chain output is
// never used directly as a cipher key. Every message key is used exactly once, so a
// deterministic IV is safe here.
function deriveEncKeyAndIv(messageKey) {
  const out = hkdf(messageKey, EMPTY, 'E2EChat-MsgKey', 44);
  return { encKey: out.slice(0, 32), iv: out.slice(32, 44) };
}

// AES-256-GCM. Output is ciphertext || 16-byte tag.
function encrypt(messageKey, plaintext, associatedData = EMPTY) {
  const { encKey, iv } = deriveEncKeyAndIv(messageKey);
  return gcm(encKey, iv, associatedData).encrypt(plaintext);
}

// Throws if the ciphertext, tag or associated data were tampered with.
function decrypt(messageKey, blob, associatedData = EMPTY) {
  const { encKey, iv } = deriveEncKeyAndIv(messageKey);
  return gcm(encKey, iv, associatedData).decrypt(blob);
}

module.exports = { encrypt, decrypt };
