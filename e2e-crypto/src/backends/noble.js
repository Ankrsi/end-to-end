'use strict';
const { x25519, ed25519 } = require('@noble/curves/ed25519');
const { randomBytes } = require('../bytes');

// Pure-JS backend (audited @noble libraries). Runs anywhere — Node, React Native/Hermes,
// browsers — with no native modules. Slower than native for the curve operations.
module.exports = {
  name: 'noble',
  generateX25519KeyPair() {
    const privateKey = randomBytes(32);
    return { publicKey: x25519.getPublicKey(privateKey), privateKey };
  },
  dh(privateKey, publicKey) {
    return x25519.getSharedSecret(privateKey, publicKey);
  },
  generateEd25519KeyPair() {
    const privateKey = randomBytes(32);
    return { publicKey: ed25519.getPublicKey(privateKey), privateKey };
  },
  sign(privateKey, data) {
    return ed25519.sign(data, privateKey);
  },
  verify(publicKey, data, signature) {
    return ed25519.verify(signature, data, publicKey);
  },
};
