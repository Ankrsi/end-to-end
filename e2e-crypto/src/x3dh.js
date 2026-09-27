'use strict';
const keys = require('./keys');
const { hkdf } = require('./kdf');
const { concat, toBase64, fromBase64, bytesOrBase64 } = require('./bytes');

// An identity a client generates once and keeps on-device (persist it with
// serializeIdentity). Only publicBundle(identity) is ever sent to the server.
function createIdentity({ oneTimePreKeyCount = 10 } = {}) {
  const identitySign = keys.generateEd25519KeyPair();     // signs the prekey
  const identityDH = keys.generateX25519KeyPair();         // used in DH1/DH2
  const signedPreKey = keys.generateX25519KeyPair();       // rotated periodically
  const signedPreKeySig = keys.sign(identitySign.privateKey, signedPreKey.publicKey);
  const oneTimePreKeys = Array.from({ length: oneTimePreKeyCount }, () => keys.generateX25519KeyPair());

  return { identitySign, identityDH, signedPreKey, signedPreKeySig, oneTimePreKeys };
}

// What actually gets published to the server / other users. No private keys.
function publicBundle(identity) {
  return {
    identitySignPub: toBase64(identity.identitySign.publicKey),
    identityDHPub: toBase64(identity.identityDH.publicKey),
    signedPreKeyPub: toBase64(identity.signedPreKey.publicKey),
    signedPreKeySig: toBase64(identity.signedPreKeySig),
    // one-time prekeys are consumed one at a time; server hands out one per handshake
    oneTimePreKeys: identity.oneTimePreKeys.map(k => toBase64(k.publicKey)),
  };
}

function combineDH(...parts) {
  // F || DH1 || DH2 || DH3 || DH4  — the leading 0xFF bytes are domain separation (Signal spec convention)
  const ikm = concat(new Uint8Array(32).fill(0xff), ...parts);
  return hkdf(ikm, new Uint8Array(32), 'E2EChat-X3DH', 32);
}

// Initiator (Alice) side: she has Bob's published bundle and her own identity.
function initiateHandshake(myIdentity, theirBundle, usedOneTimePreKeyIndex = 0) {
  const theirIdentitySignPub = fromBase64(theirBundle.identitySignPub);
  const sig = fromBase64(theirBundle.signedPreKeySig);
  const spkRaw = fromBase64(theirBundle.signedPreKeyPub);
  if (!keys.verify(theirIdentitySignPub, spkRaw, sig)) {
    throw new Error('Signed prekey signature invalid — possible tampering');
  }

  const theirIdentityDHPub = fromBase64(theirBundle.identityDHPub);
  const ephemeral = keys.generateX25519KeyPair();

  const dh1 = keys.dh(myIdentity.identityDH.privateKey, spkRaw);
  const dh2 = keys.dh(ephemeral.privateKey, theirIdentityDHPub);
  const dh3 = keys.dh(ephemeral.privateKey, spkRaw);

  let dh4 = new Uint8Array(0);
  let usedOTK = null;
  if (theirBundle.oneTimePreKeys && theirBundle.oneTimePreKeys.length > usedOneTimePreKeyIndex) {
    usedOTK = theirBundle.oneTimePreKeys[usedOneTimePreKeyIndex];
    dh4 = keys.dh(ephemeral.privateKey, fromBase64(usedOTK));
  }

  return {
    sharedSecret: combineDH(dh1, dh2, dh3, dh4),
    ephemeralPublicRaw: toBase64(ephemeral.publicKey),
    usedOneTimePreKeyIndex: usedOTK ? usedOneTimePreKeyIndex : null,
    associatedData: concat(myIdentity.identityDH.publicKey, theirIdentityDHPub),
    bobSignedPreKeyPublicRaw: spkRaw, // Bob's ratchet starting point
  };
}

// Responder (Bob) side: he receives Alice's identity public key + her ephemeral public key
// (sent alongside her first real message) and reconstructs the same shared secret.
// The two public keys may be raw bytes or base64 strings.
function respondToHandshake(myIdentity, aliceIdentityDHPub, aliceEphemeralPub, oneTimePreKeyUsed) {
  const aliceIdentityDHPubRaw = bytesOrBase64(aliceIdentityDHPub);
  const aliceEphemeralPubRaw = bytesOrBase64(aliceEphemeralPub);

  const dh1 = keys.dh(myIdentity.signedPreKey.privateKey, aliceIdentityDHPubRaw);
  const dh2 = keys.dh(myIdentity.identityDH.privateKey, aliceEphemeralPubRaw);
  const dh3 = keys.dh(myIdentity.signedPreKey.privateKey, aliceEphemeralPubRaw);

  let dh4 = new Uint8Array(0);
  if (oneTimePreKeyUsed != null) {
    const otk = myIdentity.oneTimePreKeys[oneTimePreKeyUsed];
    if (!otk) throw new Error(`Unknown one-time prekey index ${oneTimePreKeyUsed}`);
    dh4 = keys.dh(otk.privateKey, aliceEphemeralPubRaw);
  }

  return {
    sharedSecret: combineDH(dh1, dh2, dh3, dh4),
    associatedData: concat(aliceIdentityDHPubRaw, myIdentity.identityDH.publicKey),
  };
}

// --- Persistence. The output contains PRIVATE keys: store it in secure storage
// (Keychain / Keystore, e.g. react-native-keychain), never in plain AsyncStorage.

const pairToJSON = (kp) => ({ publicKey: toBase64(kp.publicKey), privateKey: toBase64(kp.privateKey) });
const pairFromJSON = (j) => ({ publicKey: fromBase64(j.publicKey), privateKey: fromBase64(j.privateKey) });

function serializeIdentity(identity) {
  return JSON.stringify({
    v: 1,
    identitySign: pairToJSON(identity.identitySign),
    identityDH: pairToJSON(identity.identityDH),
    signedPreKey: pairToJSON(identity.signedPreKey),
    signedPreKeySig: toBase64(identity.signedPreKeySig),
    oneTimePreKeys: identity.oneTimePreKeys.map(pairToJSON),
  });
}

function deserializeIdentity(json) {
  const j = typeof json === 'string' ? JSON.parse(json) : json;
  if (j.v !== 1) throw new Error(`Unsupported identity format version: ${j.v}`);
  return {
    identitySign: pairFromJSON(j.identitySign),
    identityDH: pairFromJSON(j.identityDH),
    signedPreKey: pairFromJSON(j.signedPreKey),
    signedPreKeySig: fromBase64(j.signedPreKeySig),
    oneTimePreKeys: j.oneTimePreKeys.map(pairFromJSON),
  };
}

module.exports = {
  createIdentity, publicBundle, initiateHandshake, respondToHandshake,
  serializeIdentity, deserializeIdentity,
};
