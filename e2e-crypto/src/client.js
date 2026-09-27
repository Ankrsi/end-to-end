'use strict';
// E2EEClient — everything a chat app needs, behind one object.
//
// You provide:
//   secureStore   small secret storage (Keychain / Keystore / SecureStore)
//   store         bulk storage (AsyncStorage, a file, a DB table...) — encrypted for you
//   uploadBundle  (bundleString) => send your public keys to your server
//   fetchBundle   (userId) => that user's bundleString from your server, or null
// Then call init() once after login, and encrypt/decrypt strings. How the resulting
// envelope strings travel (socket, HTTP, push) is up to you.

const { createIdentity, publicBundle, serializeIdentity, deserializeIdentity } = require('./x3dh');
const { SessionManager, MissingSenderKeyError } = require('./session');
const { createEncryptedStore, masterKeyFrom } = require('./storage');

const BUNDLE_TAG = 'x3dh1';
const K_PENDING = 'pending';
const MAX_PENDING = 500;

/** Public bundle -> one string for your server (a single text column is enough). */
function serializeBundle(bundle) {
  return JSON.stringify({ v: BUNDLE_TAG, ...bundle });
}

/** Server value -> bundle, or null if missing / from another scheme. */
function parseBundle(value) {
  if (value == null || value === '') return null;
  try {
    const obj = typeof value === 'string' ? JSON.parse(value) : value;
    return obj && obj.v === BUNDLE_TAG && obj.identityDHPub ? obj : null;
  } catch {
    return null;
  }
}

class E2EEClient {
  constructor({
    secureStore,
    store,
    uploadBundle,
    fetchBundle,
    onPendingDecrypted,
    identityKey = 'e2e_identity',
    masterKeyName = 'e2e_master_key',
    oneTimePreKeyCount = 10,
  }) {
    for (const [name, v] of Object.entries({ secureStore, store, uploadBundle, fetchBundle })) {
      if (!v) throw new TypeError(`e2e-crypto: E2EEClient needs ${name}`);
    }
    this.secureStore = secureStore;
    this.uploadBundle = uploadBundle;
    this.onPendingDecrypted = onPendingDecrypted;
    this.identityKey = identityKey;
    this.oneTimePreKeyCount = oneTimePreKeyCount;
    this.identityCache = null;
    this.initPromise = null;

    /** Encrypted view of `store`; sessions, sender keys and the pending queue live here. */
    this.store = createEncryptedStore(store, masterKeyFrom(secureStore, masterKeyName));
    this.sessions = new SessionManager({
      store: this.store,
      loadIdentity: () => this.loadIdentity(),
      fetchBundle: async (userId) => parseBundle(await fetchBundle(userId)),
    });
  }

  async loadIdentity() {
    if (this.identityCache) return this.identityCache;
    const s = await this.secureStore.get(this.identityKey);
    if (s) this.identityCache = deserializeIdentity(s);
    return this.identityCache;
  }

  /** Creates this device's identity on first run and uploads its public bundle. Safe to call repeatedly. */
  init() {
    if (!this.initPromise) {
      this.initPromise = (async () => {
        let identity = await this.loadIdentity();
        if (!identity) {
          identity = createIdentity({ oneTimePreKeyCount: this.oneTimePreKeyCount });
          await this.secureStore.set(this.identityKey, serializeIdentity(identity));
          this.identityCache = identity;
        }
        await this.uploadBundle(serializeBundle(publicBundle(identity)));   // public keys only
      })();
      this.initPromise.catch(() => { this.initPromise = null; });
    }
    return this.initPromise;
  }

  // ─── 1:1 ───
  encryptDirect(peerId, plaintext) { return this.sessions.encryptDirect(peerId, plaintext); }
  decryptDirect(senderId, value) { return this.sessions.decryptDirect(senderId, value); }
  hasDirectSession(peerId) { return this.sessions.hasDirectSession(peerId); }
  resetDirect(peerId) { return this.sessions.resetDirect(peerId); }
  /** Re-fetch a peer's bundle (e.g. when opening their chat) so a reinstall is noticed. */
  refreshBundle(userId) { return this.sessions.getBundle(userId, true); }

  // ─── Groups ───
  encryptGroup(conversationId, memberIds, plaintext, distribute) {
    return this.sessions.encryptGroup(conversationId, memberIds, plaintext, distribute);
  }
  decryptGroup(conversationId, senderId, value) { return this.sessions.decryptGroup(conversationId, senderId, value); }
  hasGroupKey(conversationId) { return this.sessions.hasGroupKey(conversationId); }
  resetGroup(conversationId) { return this.sessions.resetGroup(conversationId); }

  /**
   * Like decryptGroup, but a message that arrives before its sender's key is queued instead of
   * failing: returns { status: 'pending' }, and once the key arrives (acceptSenderKey) the
   * message is decrypted and passed to onPendingDecrypted(meta, plaintext).
   * `meta` is yours (e.g. { messageId, field }) — keep it JSON-serialisable.
   */
  async decryptGroupOrQueue(conversationId, senderId, value, meta) {
    try {
      return { status: 'ok', plaintext: await this.sessions.decryptGroup(conversationId, senderId, value) };
    } catch (err) {
      if (!(err instanceof MissingSenderKeyError)) throw err;
      await this.sessions.withLock(K_PENDING, async () => {
        const list = (await this.readPending());
        if (!list.some((p) => p.value === value)) {
          list.push({ conversationId, senderId, value, meta: meta ?? null });
          await this.store.set(K_PENDING, JSON.stringify(list.slice(-MAX_PENDING)));
        }
      });
      return { status: 'pending' };
    }
  }

  /** A sender-key packet from a group member. Decrypts any queued messages it unlocks. Returns the conversation id. */
  async acceptSenderKey(senderId, envelope) {
    const conversationId = await this.sessions.acceptSenderKey(senderId, envelope);
    await this.retryPending(conversationId, senderId);
    return conversationId;
  }

  async readPending() {
    const s = await this.store.get(K_PENDING);
    return s ? JSON.parse(s) : [];
  }

  async retryPending(conversationId, senderId) {
    const done = await this.sessions.withLock(K_PENDING, async () => {
      const list = await this.readPending();
      const keep = [];
      const done = [];
      for (const p of list) {
        if (p.conversationId !== conversationId || p.senderId !== senderId) {
          keep.push(p);
          continue;
        }
        try {
          done.push({ meta: p.meta, plaintext: await this.sessions.decryptGroup(conversationId, senderId, p.value) });
        } catch (err) {
          if (err instanceof MissingSenderKeyError) keep.push(p);   // needs a newer key
        }
      }
      if (keep.length !== list.length) await this.store.set(K_PENDING, JSON.stringify(keep));
      return done;
    });
    // Outside the lock, so the callback may queue/decrypt more messages.
    for (const d of done) {
      try {
        if (this.onPendingDecrypted) await this.onPendingDecrypted(d.meta, d.plaintext);
      } catch (err) {
        console.warn('[e2e-crypto] onPendingDecrypted failed', err);
      }
    }
  }
}

module.exports = { E2EEClient, serializeBundle, parseBundle };
