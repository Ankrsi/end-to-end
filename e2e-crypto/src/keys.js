'use strict';
const nobleBackend = require('./backends/noble');

// Key pairs are plain { publicKey, privateKey } objects of raw 32-byte Uint8Arrays, so they
// can be serialized and stored (e.g. in the device keychain) directly — and so every
// backend produces interchangeable keys.
//
// Only the curve operations go through the backend; hashing, HMAC, HKDF and AES-GCM are
// always the pure-JS implementations (already fast enough per message).

let backend = nobleBackend;

const REQUIRED = ['generateX25519KeyPair', 'dh', 'generateEd25519KeyPair', 'sign', 'verify'];

function setCryptoBackend(b) {
  for (const fn of REQUIRED) {
    if (typeof b?.[fn] !== 'function') throw new TypeError(`e2e-crypto: backend is missing ${fn}()`);
  }
  backend = b;
}

function getCryptoBackend() {
  return backend;
}

// --- X25519 (Diffie-Hellman key exchange) ---

const generateX25519KeyPair = () => backend.generateX25519KeyPair();
const dh = (privateKey, publicKey) => backend.dh(privateKey, publicKey);

// --- Ed25519 (signing prekeys and group messages, for authenticity) ---

const generateEd25519KeyPair = () => backend.generateEd25519KeyPair();
const sign = (privateKey, data) => backend.sign(privateKey, data);

function verify(publicKey, data, signature) {
  try {
    return backend.verify(publicKey, data, signature);
  } catch {
    return false; // a malformed key/signature is just an invalid signature
  }
}

module.exports = {
  generateX25519KeyPair, dh, generateEd25519KeyPair, sign, verify,
  setCryptoBackend, getCryptoBackend, nobleBackend,
};
