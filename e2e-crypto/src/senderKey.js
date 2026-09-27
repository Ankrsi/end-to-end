'use strict';
const keys = require('./keys');
const { kdfChainKey } = require('./kdf');
const aead = require('./aead');
const { randomBytes, toBase64, fromBase64, toBytes, utf8Decode } = require('./bytes');

// Each group member owns ONE sender key chain that they use to encrypt everything
// they send to the group. They distribute the current chain key to each member
// individually (once, via the 1:1 Double Ratchet), then every group message after
// that is a single symmetric-key operation, fanned out to N recipients —
// O(1) encryption instead of O(n) even as the group grows.

const MAX_SKIP = 1000; // cap on cached out-of-order group message keys, same rationale as the 1:1 ratchet

function createSenderKeyState() {
  const sign = keys.generateEd25519KeyPair(); // proves messages really came from this sender
  return {
    chainKey: randomBytes(32), iteration: 0,
    signPrivate: sign.privateKey, signPublic: sign.publicKey,
    skipped: new Map(),
  };
}

// What you distribute to other group members (over a private 1:1 ratchet session)
function exportDistributionMessage(state) {
  return {
    chainKey: toBase64(state.chainKey),
    iteration: state.iteration,
    signPublic: toBase64(state.signPublic),
  };
}

function importSenderKeyState(distMsg) {
  return {
    chainKey: fromBase64(distMsg.chainKey),
    iteration: distMsg.iteration,
    signPublic: fromBase64(distMsg.signPublic),
    skipped: new Map(),
  };
}

// Sender: encrypt once, everyone in the group decrypts with the distributed chain key.
// plaintext: string or Uint8Array.
function encryptGroupMessage(senderState, plaintext) {
  if (!senderState.signPrivate) throw new Error('This is an imported (receive-only) sender key state');
  const { chainKey, messageKey } = kdfChainKey(senderState.chainKey);
  const iteration = senderState.iteration;
  senderState.chainKey = chainKey;
  senderState.iteration += 1;

  const ciphertext = aead.encrypt(messageKey, toBytes(plaintext));
  const signature = keys.sign(senderState.signPrivate, ciphertext);

  return { iteration, ciphertext: toBase64(ciphertext), signature: toBase64(signature) };
}

// Receiver: returns the UTF-8 plaintext.
function decryptGroupMessage(senderKeyState, msg) {
  return utf8Decode(decryptGroupMessageBytes(senderKeyState, msg));
}

// Receiver: holds the sender's distributed chain state and ratchets forward to match the
// message's iteration. Out-of-order arrivals decrypt from cached skipped keys.
function decryptGroupMessageBytes(senderKeyState, msg) {
  const ciphertext = fromBase64(msg.ciphertext);
  const signature = fromBase64(msg.signature);
  // Verify before touching any state, so a forged message can't burn a cached key
  // or advance the chain past a legitimate message.
  if (!keys.verify(senderKeyState.signPublic, ciphertext, signature)) {
    throw new Error('Group message signature invalid — possible forgery');
  }

  if (senderKeyState.skipped.has(msg.iteration)) {
    const plaintext = aead.decrypt(senderKeyState.skipped.get(msg.iteration), ciphertext);
    senderKeyState.skipped.delete(msg.iteration);
    return plaintext;
  }

  if (msg.iteration < senderKeyState.iteration) {
    throw new Error('Message key already used/expired (replay?) — rejecting');
  }
  if (msg.iteration - senderKeyState.iteration > MAX_SKIP) {
    throw new Error('Too many skipped group messages');
  }

  let ck = senderKeyState.chainKey;
  let messageKey;
  const newSkipped = [];
  for (let i = senderKeyState.iteration; i <= msg.iteration; i++) {
    const step = kdfChainKey(ck);
    ck = step.chainKey;
    if (i < msg.iteration) newSkipped.push([i, step.messageKey]); // for a later out-of-order arrival
    else messageKey = step.messageKey;
  }
  const plaintext = aead.decrypt(messageKey, ciphertext);

  senderKeyState.chainKey = ck;
  senderKeyState.iteration = msg.iteration + 1;
  for (const [i, mk] of newSkipped) senderKeyState.skipped.set(i, mk);
  while (senderKeyState.skipped.size > MAX_SKIP) {
    senderKeyState.skipped.delete(senderKeyState.skipped.keys().next().value);
  }
  return plaintext;
}

// --- Persistence (works for both your own sending state and imported receive states).
// Contains secret keys: store in secure storage.

function serializeSenderKeyState(state) {
  return JSON.stringify({
    v: 1,
    chainKey: toBase64(state.chainKey),
    iteration: state.iteration,
    signPublic: toBase64(state.signPublic),
    signPrivate: state.signPrivate ? toBase64(state.signPrivate) : null,
    skipped: [...state.skipped].map(([i, mk]) => [i, toBase64(mk)]),
  });
}

function deserializeSenderKeyState(json) {
  const j = typeof json === 'string' ? JSON.parse(json) : json;
  if (j.v !== 1) throw new Error(`Unsupported sender key format version: ${j.v}`);
  const state = {
    chainKey: fromBase64(j.chainKey),
    iteration: j.iteration,
    signPublic: fromBase64(j.signPublic),
    skipped: new Map(j.skipped.map(([i, mk]) => [i, fromBase64(mk)])),
  };
  if (j.signPrivate) state.signPrivate = fromBase64(j.signPrivate);
  return state;
}

module.exports = {
  createSenderKeyState, exportDistributionMessage, importSenderKeyState,
  encryptGroupMessage, decryptGroupMessage, decryptGroupMessageBytes,
  serializeSenderKeyState, deserializeSenderKeyState,
};
