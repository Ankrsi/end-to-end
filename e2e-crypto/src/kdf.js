'use strict';
const { hkdf: nobleHkdf } = require('@noble/hashes/hkdf');
const { hmac } = require('@noble/hashes/hmac');
const { sha256 } = require('@noble/hashes/sha2');
const { utf8Encode } = require('./bytes');

// HKDF-SHA256
function hkdf(ikm, salt, info, length) {
  return nobleHkdf(sha256, ikm, salt, typeof info === 'string' ? utf8Encode(info) : info, length);
}

// KDF_RK: advances the Double Ratchet's root key using a new DH output.
function kdfRootKey(rootKey, dhOutput) {
  const out = hkdf(dhOutput, rootKey, 'E2EChat-RootRatchet', 64);
  return { rootKey: out.slice(0, 32), chainKey: out.slice(32, 64) };
}

const MSG_KEY_CONST = new Uint8Array([0x01]);
const CHAIN_KEY_CONST = new Uint8Array([0x02]);

// KDF_CK: advances a chain key by one step (symmetric ratchet). Two HMACs, no DH —
// this is what keeps per-message encryption cheap. Shared by the 1:1 ratchet and Sender Keys.
function kdfChainKey(chainKey) {
  return {
    chainKey: hmac(sha256, chainKey, CHAIN_KEY_CONST),
    messageKey: hmac(sha256, chainKey, MSG_KEY_CONST),
  };
}

module.exports = { hkdf, kdfRootKey, kdfChainKey };
