'use strict';
const { toBase64 } = require('../bytes');

// Backend for any module implementing Node's crypto API: Node's built-in 'crypto', or
// (untested) react-native-quick-crypto. The module is passed in rather than required here,
// so this file never pulls a Node built-in into a React Native bundle.

const X25519_PKCS8 = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20];
const ED25519_PKCS8 = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

const base64url = (bytes) => toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Last 32 bytes of the DER encoding are the raw key, for both SPKI and PKCS8 of these curves
const rawFromDer = (der) => new Uint8Array(der.subarray(der.length - 32));

function createNodeCryptoBackend(crypto) {
  // Parsing a PKCS8 private key costs ~0.5ms in OpenSSL 3, so private KeyObjects are cached
  // per raw-key array. Keys we generate go straight into the cache; keys restored from
  // storage are parsed once. Public keys arrive fresh with each message, so they use the
  // much cheaper JWK import instead.
  const privateCache = new WeakMap();

  function priv(prefix, raw) {
    let key = privateCache.get(raw);
    if (!key) {
      const der = new Uint8Array(prefix.length + raw.length);
      der.set(prefix, 0);
      der.set(raw, prefix.length);
      key = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
      privateCache.set(raw, key);
    }
    return key;
  }

  const pub = (crv, raw) => crypto.createPublicKey({ key: { kty: 'OKP', crv, x: base64url(raw) }, format: 'jwk' });

  function generate(type) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync(type);
    const rawPrivate = rawFromDer(privateKey.export({ type: 'pkcs8', format: 'der' }));
    privateCache.set(rawPrivate, privateKey);
    return { publicKey: rawFromDer(publicKey.export({ type: 'spki', format: 'der' })), privateKey: rawPrivate };
  }

  return {
    name: 'node-crypto',
    generateX25519KeyPair: () => generate('x25519'),
    dh(privateKey, publicKey) {
      return new Uint8Array(crypto.diffieHellman({
        privateKey: priv(X25519_PKCS8, privateKey),
        publicKey: pub('X25519', publicKey),
      }));
    },
    generateEd25519KeyPair: () => generate('ed25519'),
    sign(privateKey, data) {
      return new Uint8Array(crypto.sign(null, data, priv(ED25519_PKCS8, privateKey)));
    },
    verify(publicKey, data, signature) {
      return crypto.verify(null, data, pub('Ed25519', publicKey), signature);
    },
  };
}

module.exports = { createNodeCryptoBackend };
