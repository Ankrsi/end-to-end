'use strict';
// Storage helpers. A "store" is any async key-value object: { get(key), set(key, value), del(key) }
// with string values. Nothing here depends on a platform: adapters take the platform modules
// as arguments, so the package has no React Native / Node dependencies.

const { gcm } = require('@noble/ciphers/aes');
const { randomBytes, toBase64, fromBase64, utf8Encode, utf8Decode } = require('./bytes');

const NONCE = 12;

function memoryStore() {
  const m = new Map();
  return {
    get: async (k) => (m.has(k) ? m.get(k) : null),
    set: async (k, v) => { m.set(k, v); },
    del: async (k) => { m.delete(k); },
  };
}

function prefixStore(base, prefix) {
  return {
    get: (k) => base.get(prefix + k),
    set: (k, v) => base.set(prefix + k, v),
    del: (k) => base.del(prefix + k),
  };
}

// Encrypts every value with AES-256-GCM before it reaches `base`.
// Stored format: base64(nonce(12) || ciphertext+tag). Tampered values fail to load.
// `getKey` returns the 32-byte key (see masterKeyFrom).
function createEncryptedStore(base, getKey) {
  return {
    async get(k) {
      const s = await base.get(k);
      if (!s) return null;
      const raw = fromBase64(s);
      return utf8Decode(gcm(await getKey(), raw.subarray(0, NONCE)).decrypt(raw.subarray(NONCE)));
    },
    async set(k, v) {
      const nonce = randomBytes(NONCE);
      const ct = gcm(await getKey(), nonce).encrypt(utf8Encode(v));
      const out = new Uint8Array(NONCE + ct.length);
      out.set(nonce);
      out.set(ct, NONCE);
      await base.set(k, toBase64(out));
    },
    del: (k) => base.del(k),
  };
}

// A 32-byte key kept in `secureStore` (Keychain / Keystore), created on first use.
function masterKeyFrom(secureStore, name = 'e2e_master_key') {
  let pending = null;
  return () => {
    if (!pending) {
      pending = (async () => {
        const s = await secureStore.get(name);
        if (s) return fromBase64(s);
        const key = randomBytes(32);
        await secureStore.set(name, toBase64(key));
        return key;
      })();
      pending.catch(() => { pending = null; });
    }
    return pending;
  };
}

// React Native adapter: SecureStore (expo-secure-store) for secrets, AsyncStorage for the
// bulk (encrypted) state. Pass the modules in:
//   reactNativeStores({ SecureStore: require('expo-secure-store'), AsyncStorage })
function reactNativeStores({ SecureStore, AsyncStorage, prefix = 'e2e:' }) {
  if (!SecureStore || !AsyncStorage) throw new TypeError('e2e-crypto: pass { SecureStore, AsyncStorage }');
  return {
    secureStore: {
      get: (k) => SecureStore.getItemAsync(k),
      set: (k, v) => SecureStore.setItemAsync(k, v),
      del: (k) => SecureStore.deleteItemAsync(k),
    },
    store: prefixStore({
      get: (k) => AsyncStorage.getItem(k),
      set: (k, v) => AsyncStorage.setItem(k, v),
      del: (k) => AsyncStorage.removeItem(k),
    }, prefix),
  };
}

module.exports = { memoryStore, prefixStore, createEncryptedStore, masterKeyFrom, reactNativeStores };
