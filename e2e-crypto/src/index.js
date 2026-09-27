'use strict';
const x3dh = require('./x3dh');
const { RatchetSession } = require('./doubleRatchet');
const senderKey = require('./senderKey');
const bytes = require('./bytes');
const { setCryptoBackend, getCryptoBackend, nobleBackend } = require('./keys');
const { createNodeCryptoBackend } = require('./backends/nodeCrypto');
const { checkCryptoBackend } = require('./backends/check');
const { SessionManager, MissingSenderKeyError, parseEnvelope, isEnvelope } = require('./session');
const { runSelfTest } = require('./selfTest');
const { E2EEClient, serializeBundle, parseBundle } = require('./client');
const storage = require('./storage');

module.exports = {
  // namespaced
  x3dh,
  senderKey,
  RatchetSession,
  // flat, for convenience: import { createIdentity, RatchetSession } from 'e2e-crypto'
  ...x3dh,
  ...senderKey,
  // encoding helpers (Buffer-free)
  toBase64: bytes.toBase64,
  fromBase64: bytes.fromBase64,
  utf8Encode: bytes.utf8Encode,
  utf8Decode: bytes.utf8Decode,
  // pluggable curve implementation (default: pure-JS noble)
  setCryptoBackend,
  getCryptoBackend,
  nobleBackend,
  createNodeCryptoBackend,
  checkCryptoBackend,
  // chat session manager (1:1 sessions per peer + group sender keys)
  SessionManager,
  MissingSenderKeyError,
  parseEnvelope,
  isEnvelope,
  runSelfTest,
  // high-level client: identity + encrypted storage + sessions + late group-key queue
  E2EEClient,
  serializeBundle,
  parseBundle,
  // storage helpers / platform adapters
  memoryStore: storage.memoryStore,
  prefixStore: storage.prefixStore,
  createEncryptedStore: storage.createEncryptedStore,
  masterKeyFrom: storage.masterKeyFrom,
  reactNativeStores: storage.reactNativeStores,
};
