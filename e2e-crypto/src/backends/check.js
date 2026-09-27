'use strict';
const noble = require('./noble');
const { equal, utf8Encode } = require('../bytes');

// Verifies a backend produces keys, shared secrets and signatures interchangeable with the
// pure-JS reference. Run it once (e.g. in a dev build) before setCryptoBackend() with a
// backend that isn't covered by this package's tests, such as react-native-quick-crypto.
// Throws with a description of the first mismatch.
function checkCryptoBackend(backend) {
  const msg = utf8Encode('e2e-crypto backend check');

  const a = backend.generateX25519KeyPair();
  const b = noble.generateX25519KeyPair();
  if (!equal(backend.dh(a.privateKey, b.publicKey), noble.dh(b.privateKey, a.publicKey))) {
    throw new Error('X25519 shared secret does not match the reference implementation');
  }
  if (!equal(backend.dh(b.privateKey, a.publicKey), noble.dh(a.privateKey, b.publicKey))) {
    throw new Error('X25519 with an imported private key does not match the reference implementation');
  }

  const s = backend.generateEd25519KeyPair();
  if (!noble.verify(s.publicKey, msg, backend.sign(s.privateKey, msg))) {
    throw new Error('Ed25519 signature from backend rejected by the reference implementation');
  }
  const r = noble.generateEd25519KeyPair();
  const sig = noble.sign(r.privateKey, msg);
  if (!backend.verify(r.publicKey, msg, sig)) {
    throw new Error('Backend rejected a valid Ed25519 signature');
  }
  const forged = sig.slice();
  forged[0] ^= 1;
  let acceptedForgery;
  try { acceptedForgery = backend.verify(r.publicKey, msg, forged); } catch { acceptedForgery = false; }
  if (acceptedForgery) throw new Error('Backend accepted a forged Ed25519 signature');
  if (!equal(backend.sign(r.privateKey, msg), sig)) {
    throw new Error('Ed25519 signature with an imported private key does not match the reference implementation');
  }
  return true;
}

module.exports = { checkCryptoBackend };
