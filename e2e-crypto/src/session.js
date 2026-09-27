'use strict';
// Session manager for chat apps: keeps 1:1 Double Ratchet sessions per peer and group
// Sender Keys, on top of the primitives in this package.
//
// Storage, the local identity and the key-bundle lookup are injected, so the same code
// runs in React Native and Node. Everything it stores contains secrets: back `store` with
// something encrypted at rest.
//
// Handles: first-contact handshakes (repeated until the peer replies), crossed handshakes
// (both sides start at once), peer reinstalls (new identity), out-of-order and concurrent
// delivery (per-record locking), sender-key rotation and late sender-key arrival.

const { initiateHandshake, respondToHandshake } = require('./x3dh');
const { RatchetSession } = require('./doubleRatchet');
const {
  createSenderKeyState, exportDistributionMessage, importSenderKeyState,
  encryptGroupMessage, decryptGroupMessage, serializeSenderKeyState, deserializeSenderKeyState,
} = require('./senderKey');
const { toBase64, randomBytes } = require('./bytes');

// Old sessions / sender keys kept so late or crossed messages still decrypt.
const MAX_SESSIONS = 3;
const MAX_SENDER_KEYS = 3;

const K_DIRECT = 'dr.';
const K_BUNDLE = 'bundle.';
const K_GROUP_OWN = 'go.';
const K_GROUP_RECV = 'gr.';

class MissingSenderKeyError extends Error {
  constructor(conversationId, senderId) {
    super(`No sender key from ${senderId} for ${conversationId}`);
    this.name = 'MissingSenderKeyError';
    this.conversationId = conversationId;
    this.senderId = senderId;
  }
}

// Envelopes travel as JSON strings: { e2e: 'dr1', hs?, h, c } for 1:1, { e2e: 'sk1', kid, i, c, s } for groups.
function parseEnvelope(value) {
  let obj = value;
  if (typeof value === 'string') {
    if (!value.startsWith('{"e2e"')) return null;
    try { obj = JSON.parse(value); } catch { return null; }
  }
  if (obj && typeof obj === 'object' && (obj.e2e === 'dr1' || obj.e2e === 'sk1')) return obj;
  return null;
}

function isEnvelope(value) {
  return parseEnvelope(value) != null;
}

class SessionManager {
  /**
   * @param {{ store: {get(k):Promise<string|null>, set(k,v):Promise<void>, del(k):Promise<void>},
   *           loadIdentity(): Promise<object|null>,
   *           fetchBundle(userId): Promise<object|null> }} deps
   */
  constructor(deps) {
    this.deps = deps;
    this.locks = new Map();
    this.bundles = new Map();
  }

  // Serialises read-modify-write of one record (socket, offline sync and push can race).
  withLock(key, fn) {
    const prev = this.locks.get(key) || Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => { });
    this.locks.set(key, tail);
    tail.then(() => { if (this.locks.get(key) === tail) this.locks.delete(key); });
    return run;
  }

  async readJSON(key) {
    const s = await this.deps.store.get(key);
    return s ? JSON.parse(s) : null;
  }

  writeJSON(key, value) {
    return this.deps.store.set(key, JSON.stringify(value));
  }

  async identity() {
    const id = await this.deps.loadIdentity();
    if (!id) throw new Error('E2EE identity not initialised');
    return id;
  }

  // ─── Peer key bundles ───

  /** Cached bundle; `refresh` re-fetches it (falls back to the cache if offline). */
  async getBundle(userId, refresh = false) {
    if (!refresh) {
      const mem = this.bundles.get(userId);
      if (mem) return mem;
      const stored = await this.readJSON(K_BUNDLE + userId);
      if (stored) {
        this.bundles.set(userId, stored);
        return stored;
      }
    }
    let bundle;
    try {
      bundle = await this.deps.fetchBundle(userId);
    } catch (err) {
      const cached = this.bundles.get(userId) || await this.readJSON(K_BUNDLE + userId);
      if (cached) return cached;
      throw err;
    }
    if (bundle) {
      this.bundles.set(userId, bundle);
      await this.writeJSON(K_BUNDLE + userId, bundle);
    } else {
      this.bundles.delete(userId);
      await this.deps.store.del(K_BUNDLE + userId);
    }
    return bundle;
  }

  async forgetBundle(userId) {
    this.bundles.delete(userId);
    await this.deps.store.del(K_BUNDLE + userId);
  }

  // ─── 1:1 — Double Ratchet ───

  /** Returns the envelope string, or null if the peer has no bundle (can't encrypt). */
  encryptDirect(peerId, plaintext) {
    return this.withLock(K_DIRECT + peerId, async () => {
      const identity = await this.identity();
      const rec = (await this.readJSON(K_DIRECT + peerId)) || { v: 1, sessions: [] };
      let entry = rec.sessions[0];
      const bundle = await this.getBundle(peerId);

      const needNew = !entry || rec.reset || (bundle && entry.peerIk !== bundle.identityDHPub);
      if (needNew) {
        if (!bundle) return null;
        const otkCount = (bundle.oneTimePreKeys && bundle.oneTimePreKeys.length) || 0;
        const otkIndex = otkCount ? Math.floor(Math.random() * otkCount) : 0;
        const hs = initiateHandshake(identity, bundle, otkIndex);   // verifies the signed prekey
        const session = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);
        entry = {
          id: hs.ephemeralPublicRaw,
          state: session.serialize(),
          peerIk: bundle.identityDHPub,
          hs: { ik: toBase64(identity.identityDH.publicKey), ek: hs.ephemeralPublicRaw, otk: hs.usedOneTimePreKeyIndex },
        };
        rec.sessions = [entry, ...rec.sessions].slice(0, MAX_SESSIONS);
        delete rec.reset;
      }

      const session = RatchetSession.deserialize(entry.state);
      const { header, ciphertext } = session.encrypt(plaintext);
      entry.state = session.serialize();
      await this.writeJSON(K_DIRECT + peerId, rec);

      const env = { e2e: 'dr1', h: header, c: ciphertext };
      if (entry.hs) env.hs = entry.hs;
      return JSON.stringify(env);
    });
  }

  /** Non-envelope input is returned unchanged (plaintext from clients without E2EE). Throws if it can't decrypt. */
  async decryptDirect(senderId, value) {
    const env = parseEnvelope(value);
    if (!env) return value;
    if (env.e2e !== 'dr1') throw new Error('Expected a 1:1 envelope');

    return this.withLock(K_DIRECT + senderId, async () => {
      const rec = (await this.readJSON(K_DIRECT + senderId)) || { v: 1, sessions: [] };

      let candidates;
      let isNew = false;
      if (env.hs) {
        const existing = rec.sessions.find((s) => s.id === env.hs.ek);
        if (existing) {
          candidates = [existing];
        } else {
          const identity = await this.identity();
          const { sharedSecret } = respondToHandshake(identity, env.hs.ik, env.hs.ek, env.hs.otk);
          const session = RatchetSession.initAsReceiver(sharedSecret, identity.signedPreKey);
          candidates = [{ id: env.hs.ek, state: session.serialize(), peerIk: env.hs.ik }];
          isNew = true;
        }
      } else {
        candidates = rec.sessions;
      }

      for (const entry of candidates) {
        const session = RatchetSession.deserialize(entry.state);
        let plaintext;
        try {
          plaintext = session.decrypt(env.h, env.c);   // state unchanged on failure
        } catch {
          continue;
        }
        entry.state = session.serialize();
        delete entry.hs;   // the peer has this session now; stop sending the handshake
        rec.sessions = [entry, ...rec.sessions.filter((s) => s !== entry)].slice(0, MAX_SESSIONS);
        await this.writeJSON(K_DIRECT + senderId, rec);

        // Peer reinstalled / new identity: our cached bundle is stale.
        if (isNew) {
          const cached = this.bundles.get(senderId) || await this.readJSON(K_BUNDLE + senderId);
          if (cached && cached.identityDHPub !== entry.peerIk) await this.forgetBundle(senderId);
        }
        return plaintext;
      }
      throw new Error(`Unable to decrypt message from ${senderId}`);
    });
  }

  async hasDirectSession(peerId) {
    const rec = await this.readJSON(K_DIRECT + peerId);
    return !!(rec && rec.sessions.length);
  }

  /** Next message to this peer starts a fresh handshake. Existing sessions still decrypt. */
  resetDirect(peerId) {
    return this.withLock(K_DIRECT + peerId, async () => {
      const rec = await this.readJSON(K_DIRECT + peerId);
      if (!rec) return;
      rec.reset = true;
      await this.writeJSON(K_DIRECT + peerId, rec);
    });
  }

  // ─── Groups — Sender Keys ───

  /**
   * Encrypts once for the whole group. Our sender key is first sent (over 1:1 sessions)
   * to members who don't have it yet, through `distribute(to, envelope)`.
   * Returns null if some member has no bundle (they couldn't read it).
   */
  encryptGroup(conversationId, memberIds, plaintext, distribute) {
    return this.withLock(K_GROUP_OWN + conversationId, async () => {
      // Every recipient must be able to decrypt, or we don't encrypt at all.
      const bundles = new Map();
      for (const m of memberIds) {
        const b = await this.getBundle(m);
        if (!b) return null;
        bundles.set(m, b);
      }

      let rec = await this.readJSON(K_GROUP_OWN + conversationId);
      if (!rec) {
        rec = { v: 1, kid: toBase64(randomBytes(12)), state: serializeSenderKeyState(createSenderKeyState()), to: {} };
      }
      const state = deserializeSenderKeyState(rec.state);

      const missing = memberIds.filter((m) => rec.to[m] !== bundles.get(m).identityDHPub);
      if (missing.length) {
        const body = JSON.stringify({ t: 'skdm', conversationId, kid: rec.kid, dist: exportDistributionMessage(state) });
        for (const m of missing) {
          const env = await this.encryptDirect(m, body);
          if (!env) return null;
          await distribute(m, env);
          rec.to[m] = bundles.get(m).identityDHPub;
        }
      }

      const msg = encryptGroupMessage(state, plaintext);
      rec.state = serializeSenderKeyState(state);
      await this.writeJSON(K_GROUP_OWN + conversationId, rec);

      return JSON.stringify({ e2e: 'sk1', kid: rec.kid, i: msg.iteration, c: msg.ciphertext, s: msg.signature });
    });
  }

  /** Handles a sender-key distribution received over a 1:1 session. Returns its conversation id. */
  async acceptSenderKey(senderId, envelope) {
    const plaintext = await this.decryptDirect(senderId, envelope);
    const packet = JSON.parse(plaintext);
    if (!packet || packet.t !== 'skdm') throw new Error('Not a sender key packet');

    const key = K_GROUP_RECV + packet.conversationId + '.' + senderId;
    await this.withLock(key, async () => {
      const rec = (await this.readJSON(key)) || { v: 1, keys: [] };
      if (rec.keys.some((k) => k.kid === packet.kid)) return;   // duplicate delivery
      const state = importSenderKeyState(packet.dist);
      rec.keys = [{ kid: packet.kid, state: serializeSenderKeyState(state) }, ...rec.keys].slice(0, MAX_SENDER_KEYS);
      await this.writeJSON(key, rec);
    });
    return packet.conversationId;
  }

  /** Non-envelope input is returned unchanged. Throws MissingSenderKeyError if the sender's key hasn't arrived yet. */
  async decryptGroup(conversationId, senderId, value) {
    const env = parseEnvelope(value);
    if (!env) return value;
    if (env.e2e !== 'sk1') throw new Error('Expected a group envelope');

    const key = K_GROUP_RECV + conversationId + '.' + senderId;
    return this.withLock(key, async () => {
      const rec = await this.readJSON(key);
      const entry = rec && rec.keys.find((k) => k.kid === env.kid);
      if (!entry) throw new MissingSenderKeyError(conversationId, senderId);

      const state = deserializeSenderKeyState(entry.state);
      const plaintext = decryptGroupMessage(state, { iteration: env.i, ciphertext: env.c, signature: env.s });
      entry.state = serializeSenderKeyState(state);
      await this.writeJSON(key, rec);
      return plaintext;
    });
  }

  async hasGroupKey(conversationId) {
    return (await this.deps.store.get(K_GROUP_OWN + conversationId)) != null;
  }

  /** Drop our sender key so the next send rotates it (call when someone leaves / is removed). */
  resetGroup(conversationId) {
    return this.withLock(K_GROUP_OWN + conversationId, () => this.deps.store.del(K_GROUP_OWN + conversationId));
  }
}

module.exports = { SessionManager, MissingSenderKeyError, parseEnvelope, isEnvelope };
