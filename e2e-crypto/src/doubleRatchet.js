'use strict';
const keys = require('./keys');
const { kdfRootKey, kdfChainKey } = require('./kdf');
const aead = require('./aead');
const { equal, toBase64, fromBase64, toBytes, utf8Decode } = require('./bytes');

const MAX_SKIP = 1000;          // max message keys we'll derive ahead in one chain for out-of-order delivery
const MAX_SKIPPED_TOTAL = 2000; // cap on cached keys across all chains; oldest are evicted first
const EMPTY = new Uint8Array(0);

class RatchetSession {
  constructor() {
    this.DHs = null;        // { publicKey, privateKey } our current ratchet key pair
    this.DHr = null;        // Uint8Array, remote's current ratchet public key (raw)
    this.RK = null;         // root key
    this.CKs = null;        // sending chain key
    this.CKr = null;        // receiving chain key
    this.Ns = 0;            // sent message count in current sending chain
    this.Nr = 0;            // received message count in current receiving chain
    this.PN = 0;            // number of messages in previous sending chain
    this.skipped = new Map(); // `${dhPubBase64}:${n}` -> messageKey, for out-of-order delivery
  }

  // Alice: called right after X3DH, using Bob's signed prekey as his initial ratchet key
  static initAsSender(sharedSecret, bobRatchetPublicRaw) {
    const s = new RatchetSession();
    s.DHs = keys.generateX25519KeyPair();
    s.DHr = bobRatchetPublicRaw;
    const { rootKey, chainKey } = kdfRootKey(sharedSecret, keys.dh(s.DHs.privateKey, bobRatchetPublicRaw));
    s.RK = rootKey;
    s.CKs = chainKey;
    return s;
  }

  // Bob: called right after X3DH; he doesn't ratchet forward until Alice's first message arrives
  static initAsReceiver(sharedSecret, bobRatchetKeyPair) {
    const s = new RatchetSession();
    s.DHs = bobRatchetKeyPair;
    s.RK = sharedSecret;
    return s;
  }

  // plaintext: string or Uint8Array. Returns { header, ciphertext } ready to send over the wire.
  encrypt(plaintext, associatedData = EMPTY) {
    if (!this.CKs) throw new Error('Session cannot send yet — wait for the first message from the initiator');
    const { chainKey, messageKey } = kdfChainKey(this.CKs);
    this.CKs = chainKey;
    const header = { dh: toBase64(this.DHs.publicKey), pn: this.PN, n: this.Ns };
    this.Ns += 1;
    const ciphertext = aead.encrypt(messageKey, toBytes(plaintext), associatedData);
    return { header, ciphertext: toBase64(ciphertext) };
  }

  // header: { dh (base64), pn, n }, ciphertext: base64 string. Returns the UTF-8 plaintext.
  decrypt(header, ciphertextB64, associatedData = EMPTY) {
    return utf8Decode(this.decryptBytes(header, ciphertextB64, associatedData));
  }

  // Same as decrypt() but returns raw bytes (for binary payloads).
  // Transactional: if authentication fails, the session state is left untouched, so a
  // corrupted or forged message can't desync the conversation.
  decryptBytes(header, ciphertextB64, associatedData = EMPTY) {
    const ciphertext = fromBase64(ciphertextB64);

    // 1. Key already derived from an earlier out-of-order arrival?
    const skippedId = `${header.dh}:${header.n}`;
    const skippedKey = this.skipped.get(skippedId);
    if (skippedKey) {
      const plaintext = aead.decrypt(skippedKey, ciphertext, associatedData);
      this.skipped.delete(skippedId); // single-use
      return plaintext;
    }

    // 2. Work on a draft of the state; commit only after the message authenticates.
    const st = {
      DHs: this.DHs, DHr: this.DHr, RK: this.RK, CKs: this.CKs, CKr: this.CKr,
      Ns: this.Ns, Nr: this.Nr, PN: this.PN,
    };
    const newSkipped = [];

    const remotePublicRaw = fromBase64(header.dh);
    if (!st.DHr || !equal(remotePublicRaw, st.DHr)) {
      skipMessageKeys(st, header.pn, newSkipped); // finish the OLD receiving chain first
      dhRatchetStep(st, remotePublicRaw);
    }
    skipMessageKeys(st, header.n, newSkipped);

    if (header.n < st.Nr) throw new Error('Message key already used/expired (replay?) — rejecting');
    const { chainKey, messageKey } = kdfChainKey(st.CKr);
    st.CKr = chainKey;
    st.Nr += 1;

    const plaintext = aead.decrypt(messageKey, ciphertext, associatedData); // throws on tamper

    Object.assign(this, st);
    for (const [id, mk] of newSkipped) this.skipped.set(id, mk);
    while (this.skipped.size > MAX_SKIPPED_TOTAL) this.skipped.delete(this.skipped.keys().next().value);
    return plaintext;
  }

  // --- Persistence. Contains secret keys: store in secure storage, and save after every
  // encrypt/decrypt (the state advances with each message).

  toJSON() {
    const b64 = (x) => (x ? toBase64(x) : null);
    return {
      v: 1,
      DHs: { publicKey: toBase64(this.DHs.publicKey), privateKey: toBase64(this.DHs.privateKey) },
      DHr: b64(this.DHr), RK: b64(this.RK), CKs: b64(this.CKs), CKr: b64(this.CKr),
      Ns: this.Ns, Nr: this.Nr, PN: this.PN,
      skipped: [...this.skipped].map(([id, mk]) => [id, toBase64(mk)]),
    };
  }

  serialize() {
    return JSON.stringify(this.toJSON());
  }

  static deserialize(json) {
    const j = typeof json === 'string' ? JSON.parse(json) : json;
    if (j.v !== 1) throw new Error(`Unsupported session format version: ${j.v}`);
    const raw = (x) => (x ? fromBase64(x) : null);
    const s = new RatchetSession();
    s.DHs = { publicKey: fromBase64(j.DHs.publicKey), privateKey: fromBase64(j.DHs.privateKey) };
    s.DHr = raw(j.DHr); s.RK = raw(j.RK); s.CKs = raw(j.CKs); s.CKr = raw(j.CKr);
    s.Ns = j.Ns; s.Nr = j.Nr; s.PN = j.PN;
    s.skipped = new Map(j.skipped.map(([id, mk]) => [id, fromBase64(mk)]));
    return s;
  }
}

function dhRatchetStep(st, remotePublicRaw) {
  st.PN = st.Ns;
  st.Ns = 0;
  st.Nr = 0;
  st.DHr = remotePublicRaw;

  // receiving chain from the new DH output
  let out = kdfRootKey(st.RK, keys.dh(st.DHs.privateKey, remotePublicRaw));
  st.RK = out.rootKey;
  st.CKr = out.chainKey;

  // fresh ratchet key pair -> next sending chain
  st.DHs = keys.generateX25519KeyPair();
  out = kdfRootKey(st.RK, keys.dh(st.DHs.privateKey, remotePublicRaw));
  st.RK = out.rootKey;
  st.CKs = out.chainKey;
}

function skipMessageKeys(st, untilN, newSkipped) {
  if (st.CKr === null) return;
  if (st.Nr + MAX_SKIP < untilN) throw new Error('Too many skipped messages');
  const dhB64 = toBase64(st.DHr);
  while (st.Nr < untilN) {
    const { chainKey, messageKey } = kdfChainKey(st.CKr);
    st.CKr = chainKey;
    newSkipped.push([`${dhB64}:${st.Nr}`, messageKey]);
    st.Nr += 1;
  }
}

module.exports = { RatchetSession };
