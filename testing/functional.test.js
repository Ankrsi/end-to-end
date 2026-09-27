'use strict';
const assert = require('assert');
const e2e = require('e2e-crypto');
const { x3dh, RatchetSession, senderKey } = e2e;

// E2E_BACKEND=noble runs the whole suite on the pure-JS backend React Native uses by default
const nativeBackend = e2e.getCryptoBackend();
if (process.env.E2E_BACKEND === 'noble') e2e.setCryptoBackend(e2e.nobleBackend);
console.log(`\nCrypto backend: ${e2e.getCryptoBackend().name}`);

let passed = 0, failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`      ${e.message}`);
    failed++;
  }
}

function setupPair() {
  const alice = x3dh.createIdentity();
  const bob = x3dh.createIdentity();
  const aliceBundle = x3dh.publicBundle(alice);
  const bobBundle = x3dh.publicBundle(bob);
  const hs = x3dh.initiateHandshake(alice, bobBundle, 0);
  const sessionA = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);
  const resp = x3dh.respondToHandshake(
    bob, Buffer.from(aliceBundle.identityDHPub, 'base64'),
    Buffer.from(hs.ephemeralPublicRaw, 'base64'), hs.usedOneTimePreKeyIndex
  );
  const sessionB = RatchetSession.initAsReceiver(resp.sharedSecret, bob.signedPreKey);
  return { alice, bob, sessionA, sessionB };
}

console.log('\n--- X3DH handshake ---');

test('handshake produces matching shared secret on both sides', () => {
  const { sessionA, sessionB } = setupPair();
  const m = sessionA.encrypt(Buffer.from('probe'));
  const pt = sessionB.decrypt(m.header, m.ciphertext);
  assert.strictEqual(pt, 'probe');
});

test('tampered signed-prekey signature is rejected', () => {
  const alice = x3dh.createIdentity();
  const bob = x3dh.createIdentity();
  const bundle = x3dh.publicBundle(bob);
  bundle.signedPreKeySig = Buffer.from(bundle.signedPreKeySig, 'base64')
    .map((b, i) => (i === 0 ? b ^ 0xff : b)); // flip a byte
  bundle.signedPreKeySig = Buffer.from(bundle.signedPreKeySig).toString('base64');
  assert.throws(() => x3dh.initiateHandshake(alice, bundle, 0), /signature invalid/);
});

console.log('\n--- Double Ratchet: ordering ---');

test('in-order messages decrypt correctly', () => {
  const { sessionA, sessionB } = setupPair();
  for (let i = 0; i < 10; i++) {
    const m = sessionA.encrypt(Buffer.from(`msg ${i}`));
    assert.strictEqual(sessionB.decrypt(m.header, m.ciphertext), `msg ${i}`);
  }
});

test('out-of-order messages decrypt correctly (reversed)', () => {
  const { sessionA, sessionB } = setupPair();
  const msgs = [];
  for (let i = 0; i < 10; i++) msgs.push(sessionA.encrypt(Buffer.from(`msg ${i}`)));
  for (let i = 9; i >= 0; i--) {
    assert.strictEqual(sessionB.decrypt(msgs[i].header, msgs[i].ciphertext), `msg ${i}`);
  }
});

test('out-of-order messages decrypt correctly (shuffled)', () => {
  const { sessionA, sessionB } = setupPair();
  const idx = Array.from({ length: 30 }, (_, i) => i);
  for (let i = idx.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [idx[i], idx[j]] = [idx[j], idx[i]]; }
  const msgs = [];
  for (let i = 0; i < 30; i++) msgs.push(sessionA.encrypt(Buffer.from(`msg ${i}`)));
  for (const i of idx) assert.strictEqual(sessionB.decrypt(msgs[i].header, msgs[i].ciphertext), `msg ${i}`);
});

test('bidirectional conversation (DH ratchet flips direction correctly)', () => {
  const { sessionA, sessionB } = setupPair();
  const a1 = sessionA.encrypt(Buffer.from('hi bob'));
  assert.strictEqual(sessionB.decrypt(a1.header, a1.ciphertext), 'hi bob');
  const b1 = sessionB.encrypt(Buffer.from('hi alice'));
  assert.strictEqual(sessionA.decrypt(b1.header, b1.ciphertext), 'hi alice');
  const a2 = sessionA.encrypt(Buffer.from('how are you'));
  assert.strictEqual(sessionB.decrypt(a2.header, a2.ciphertext), 'how are you');
  const b2 = sessionB.encrypt(Buffer.from('good, you?'));
  assert.strictEqual(sessionA.decrypt(b2.header, b2.ciphertext), 'good, you?');
});

test('many back-and-forth turns stay in sync', () => {
  const { sessionA, sessionB } = setupPair();
  let sender = sessionA, receiver = sessionB;
  for (let i = 0; i < 50; i++) {
    const m = sender.encrypt(Buffer.from(`turn ${i}`));
    assert.strictEqual(receiver.decrypt(m.header, m.ciphertext), `turn ${i}`);
    [sender, receiver] = [receiver, sender];
  }
});

console.log('\n--- Double Ratchet: tamper / forward secrecy ---');

test('corrupted ciphertext fails authentication instead of returning garbage', () => {
  const { sessionA, sessionB } = setupPair();
  const m = sessionA.encrypt(Buffer.from('secret'));
  const bad = Buffer.from(m.ciphertext, 'base64');
  bad[0] ^= 0xff;
  assert.throws(() => sessionB.decrypt(m.header, bad.toString('base64')));
});

test('message key is single-use: re-decrypting the same message twice fails the second time', () => {
  const { sessionA, sessionB } = setupPair();
  const m = sessionA.encrypt(Buffer.from('once'));
  assert.strictEqual(sessionB.decrypt(m.header, m.ciphertext), 'once');
  assert.throws(() => sessionB.decrypt(m.header, m.ciphertext)); // key already consumed
});

console.log('\n--- Sender Keys (group messaging) ---');

test('group message round-trips correctly', () => {
  const state = senderKey.createSenderKeyState();
  const member = senderKey.importSenderKeyState(senderKey.exportDistributionMessage(state));
  const m = senderKey.encryptGroupMessage(state, Buffer.from('hello group'));
  assert.strictEqual(senderKey.decryptGroupMessage(member, m), 'hello group');
});

test('group messages decrypt correctly even if received out of order', () => {
  const state = senderKey.createSenderKeyState();
  const member = senderKey.importSenderKeyState(senderKey.exportDistributionMessage(state));
  const msgs = [];
  for (let i = 0; i < 10; i++) msgs.push(senderKey.encryptGroupMessage(state, Buffer.from(`g${i}`)));
  // deliver in reverse
  for (let i = 9; i >= 0; i--) assert.strictEqual(senderKey.decryptGroupMessage(member, msgs[i]), `g${i}`);
});

test('forged group message (bad signature) is rejected', () => {
  const state = senderKey.createSenderKeyState();
  const member = senderKey.importSenderKeyState(senderKey.exportDistributionMessage(state));
  const m = senderKey.encryptGroupMessage(state, Buffer.from('legit'));
  m.signature = senderKey.encryptGroupMessage(senderKey.createSenderKeyState(), Buffer.from('x')).signature; // swap in a bogus sig
  assert.throws(() => senderKey.decryptGroupMessage(member, m), /signature invalid/);
});

test('true replay of the same group message is still rejected', () => {
  const state = senderKey.createSenderKeyState();
  const member = senderKey.importSenderKeyState(senderKey.exportDistributionMessage(state));
  const m = senderKey.encryptGroupMessage(state, Buffer.from('once only'));
  assert.strictEqual(senderKey.decryptGroupMessage(member, m), 'once only');
  assert.throws(() => senderKey.decryptGroupMessage(member, m), /already used/); // replay
});

console.log('\n--- Persistence (app restarts) ---');

test('identity survives serialize/deserialize and can still complete handshakes', () => {
  const alice = x3dh.createIdentity();
  const bob = x3dh.deserializeIdentity(x3dh.serializeIdentity(x3dh.createIdentity()));
  const hs = x3dh.initiateHandshake(alice, x3dh.publicBundle(bob), 3);
  const sessionA = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);
  const restoredBob = x3dh.deserializeIdentity(x3dh.serializeIdentity(bob));
  const resp = x3dh.respondToHandshake(restoredBob, x3dh.publicBundle(alice).identityDHPub, hs.ephemeralPublicRaw, hs.usedOneTimePreKeyIndex);
  const sessionB = RatchetSession.initAsReceiver(resp.sharedSecret, restoredBob.signedPreKey);
  const m = sessionA.encrypt('after restart');
  assert.strictEqual(sessionB.decrypt(m.header, m.ciphertext), 'after restart');
});

test('ratchet session restored mid-conversation keeps pending out-of-order keys', () => {
  let { sessionA, sessionB } = setupPair();
  const msgs = [0, 1, 2, 3].map(i => sessionA.encrypt(`m${i}`));
  assert.strictEqual(sessionB.decrypt(msgs[3].header, msgs[3].ciphertext), 'm3'); // caches keys for 0..2
  sessionA = RatchetSession.deserialize(sessionA.serialize());
  sessionB = RatchetSession.deserialize(JSON.parse(JSON.stringify(sessionB))); // toJSON path
  for (const i of [1, 0, 2]) assert.strictEqual(sessionB.decrypt(msgs[i].header, msgs[i].ciphertext), `m${i}`);
  const reply = sessionB.encrypt('reply');
  assert.strictEqual(sessionA.decrypt(reply.header, reply.ciphertext), 'reply');
});

test('sender key states (sending and receiving) survive serialize/deserialize', () => {
  let state = senderKey.createSenderKeyState();
  let member = senderKey.importSenderKeyState(senderKey.exportDistributionMessage(state));
  const early = [0, 1].map(i => senderKey.encryptGroupMessage(state, `g${i}`));
  assert.strictEqual(senderKey.decryptGroupMessage(member, early[1]), 'g1');
  state = senderKey.deserializeSenderKeyState(senderKey.serializeSenderKeyState(state));
  member = senderKey.deserializeSenderKeyState(senderKey.serializeSenderKeyState(member));
  assert.strictEqual(senderKey.decryptGroupMessage(member, early[0]), 'g0');
  const later = senderKey.encryptGroupMessage(state, 'after restart');
  assert.strictEqual(senderKey.decryptGroupMessage(member, later), 'after restart');
});

console.log('\n--- Robustness ---');

test('a corrupted message does not desync the session', () => {
  const { sessionA, sessionB } = setupPair();
  const m1 = sessionA.encrypt('one');
  const bad = Buffer.from(m1.ciphertext, 'base64'); bad[0] ^= 0xff;
  assert.throws(() => sessionB.decrypt(m1.header, bad.toString('base64')));
  assert.strictEqual(sessionB.decrypt(m1.header, m1.ciphertext), 'one'); // real one still works
  const m2 = sessionA.encrypt('two');
  assert.strictEqual(sessionB.decrypt(m2.header, m2.ciphertext), 'two');
});

test('unicode text and binary payloads round-trip', () => {
  const { sessionA, sessionB } = setupPair();
  const text = 'héllo wörld — 你好 🔐👋🏽';
  const m = sessionA.encrypt(text);
  assert.strictEqual(sessionB.decrypt(m.header, m.ciphertext), text);
  const bin = new Uint8Array(256).map((_, i) => i);
  const mb = sessionA.encrypt(bin);
  assert.deepStrictEqual(Array.from(sessionB.decryptBytes(mb.header, mb.ciphertext)), Array.from(bin));
});

test('library works without Node Buffer (React Native environment)', () => {
  const { spawnSync } = require('child_process');
  const script = `
    delete globalThis.Buffer;
    const e = require('e2e-crypto');
    e.setCryptoBackend(e.nobleBackend); // what a React Native app runs by default
    const a = e.createIdentity(), b = e.createIdentity();
    const hs = e.initiateHandshake(a, e.publicBundle(b), 0);
    const sa = e.RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);
    const r = e.respondToHandshake(b, e.publicBundle(a).identityDHPub, hs.ephemeralPublicRaw, hs.usedOneTimePreKeyIndex);
    const sb = e.RatchetSession.initAsReceiver(r.sharedSecret, b.signedPreKey);
    const m = sa.encrypt('no buffer 🔐');
    if (sb.decrypt(m.header, m.ciphertext) !== 'no buffer 🔐') process.exit(2);
    const g = e.createSenderKeyState(), mem = e.importSenderKeyState(e.exportDistributionMessage(g));
    if (e.decryptGroupMessage(mem, e.encryptGroupMessage(g, 'grp')) !== 'grp') process.exit(3);
  `;
  const res = spawnSync(process.execPath, ['-e', script], { cwd: __dirname, encoding: 'utf8' });
  assert.strictEqual(res.status, 0, res.stderr);
});

test('base64 and UTF-8 helpers match Node Buffer exactly', () => {
  const { toBase64, fromBase64, utf8Encode, utf8Decode } = require('e2e-crypto');
  for (let len = 0; len < 70; len++) {
    const b = require('crypto').randomBytes(len);
    assert.strictEqual(toBase64(b), b.toString('base64'));
    assert.deepStrictEqual(Buffer.from(fromBase64(b.toString('base64'))), b);
  }
  const s = 'aé€𐍈 🔐 \u0000 end';
  assert.deepStrictEqual(Buffer.from(utf8Encode(s)), Buffer.from(s, 'utf8'));
  assert.strictEqual(utf8Decode(Buffer.from(s, 'utf8')), s);
});

test('checkCryptoBackend accepts the native backend and rejects a broken one', () => {
  assert.strictEqual(e2e.checkCryptoBackend(nativeBackend), true);
  const broken = { ...nativeBackend, verify: () => true };
  assert.throws(() => e2e.checkCryptoBackend(broken), /forged/);
});

test('native and pure-JS backends interoperate (keys, handshake, 1:1 and group)', () => {
  const original = e2e.getCryptoBackend();
  const use = (b) => e2e.setCryptoBackend(b);
  try {
    use(nativeBackend);
    const alice = x3dh.createIdentity();
    use(e2e.nobleBackend);
    const bob = x3dh.createIdentity();
    use(nativeBackend);
    const hs = x3dh.initiateHandshake(alice, x3dh.publicBundle(bob), 0);
    const sessionA = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);
    use(e2e.nobleBackend);
    const resp = x3dh.respondToHandshake(bob, x3dh.publicBundle(alice).identityDHPub, hs.ephemeralPublicRaw, hs.usedOneTimePreKeyIndex);
    const sessionB = RatchetSession.initAsReceiver(resp.sharedSecret, bob.signedPreKey);
    for (let i = 0; i < 6; i++) {
      use(i % 2 ? nativeBackend : e2e.nobleBackend);
      const [s, r] = i % 2 ? [sessionB, sessionA] : [sessionA, sessionB];
      const m = s.encrypt(`x${i}`);
      use(i % 2 ? e2e.nobleBackend : nativeBackend);
      assert.strictEqual(r.decrypt(m.header, m.ciphertext), `x${i}`);
    }
    use(nativeBackend);
    const g = senderKey.createSenderKeyState();
    const dist = senderKey.exportDistributionMessage(g);
    const gm = senderKey.encryptGroupMessage(g, 'cross-backend group');
    use(e2e.nobleBackend);
    const member = senderKey.importSenderKeyState(dist);
    assert.strictEqual(senderKey.decryptGroupMessage(member, gm), 'cross-backend group');
  } finally {
    use(original);
  }
});

// SessionManager (chat sessions + group sender keys): out-of-order, concurrent, crossed handshakes, replay, groups
(async () => {
  console.log('\nSessionManager self-test:');
  const r = await e2e.runSelfTest(null, (line) => console.log('  ' + line));
  passed += r.passed;
  failed += r.failed;

  // E2EEClient: identity, encrypted storage, bundle format, late group-key queue
  console.log('\nE2EEClient:');
  const atest = async (name, fn) => {
    try { await fn(); console.log(`  ✓ ${name}`); passed++; } catch (e) { console.log(`  ✗ ${name}\n      ${e.message}`); failed++; }
  };
  const server = new Map();   // userId -> bundle string (what a real server would store)
  const mkClient = (userId, stores = { secureStore: e2e.memoryStore(), store: e2e.memoryStore() }, extra = {}) => {
    let uploads = 0;
    const client = new e2e.E2EEClient({
      ...stores,
      uploadBundle: async (b) => { uploads++; server.set(userId, b); },
      fetchBundle: async (u) => server.get(u) ?? null,
      ...extra,
    });
    return { client, stores, uploads: () => uploads };
  };

  await atest('two clients chat after init(); init is idempotent', async () => {
    const a = mkClient('ca'), b = mkClient('cb');
    await Promise.all([a.client.init(), a.client.init(), b.client.init()]);
    assert.strictEqual(a.uploads(), 1);
    const env = await a.client.encryptDirect('cb', 'hello');
    assert.strictEqual(await b.client.decryptDirect('ca', env), 'hello');
    assert.strictEqual(await a.client.decryptDirect('cb', await b.client.encryptDirect('ca', 'hi')), 'hi');
  });

  await atest('identity and sessions survive an app restart (new client, same stores)', async () => {
    const a = mkClient('ra'), b = mkClient('rb');
    await a.client.init(); await b.client.init();
    await b.client.decryptDirect('ra', await a.client.encryptDirect('rb', 'one'));
    const bundleBefore = server.get('ra');
    const a2 = mkClient('ra', a.stores);
    await a2.client.init();
    assert.strictEqual(server.get('ra'), bundleBefore, 'identity was regenerated');
    assert.strictEqual(await b.client.decryptDirect('ra', await a2.client.encryptDirect('rb', 'two')), 'two');
  });

  await atest('bulk store is encrypted at rest and tamper-evident', async () => {
    const a = mkClient('ea'), b = mkClient('eb');
    await a.client.init(); await b.client.init();
    await a.client.encryptDirect('eb', 'secret');
    const raw = a.stores.store;
    const keys = [];
    const base = { get: raw.get, set: async (k, v) => { keys.push(k); return raw.set(k, v); }, del: raw.del };
    const enc = e2e.createEncryptedStore(base, e2e.masterKeyFrom(a.stores.secureStore));
    await enc.set('probe', 'plaintext-marker');
    const stored = await raw.get('probe');
    assert.ok(!stored.includes('plaintext-marker'));
    assert.strictEqual(await enc.get('probe'), 'plaintext-marker');
    const bytes = e2e.fromBase64(stored); bytes[20] ^= 1;
    await raw.set('probe', e2e.toBase64(bytes));
    await assert.rejects(enc.get('probe'));
  });

  await atest('parseBundle accepts e2e-crypto bundles only', async () => {
    const id = x3dh.createIdentity();
    assert.ok(e2e.parseBundle(e2e.serializeBundle(x3dh.publicBundle(id))));
    assert.strictEqual(e2e.parseBundle('bGVnYWN5LWRoLWtleQ=='), null);   // legacy base64 key
    assert.strictEqual(e2e.parseBundle(null), null);
    assert.strictEqual(e2e.parseBundle('{"v":"other"}'), null);
  });

  await atest('group message before its sender key is queued, then delivered via onPendingDecrypted', async () => {
    const delivered = [];
    const a = mkClient('qa'), b = mkClient('qb', undefined, { onPendingDecrypted: (meta, text) => { delivered.push([meta.id, text]); } });
    await a.client.init(); await b.client.init();
    const keyPackets = [];
    const m1 = await a.client.encryptGroup('grp', ['qb'], 'first', (to, env) => { keyPackets.push(env); });
    const m2 = await a.client.encryptGroup('grp', ['qb'], 'second', () => { });
    assert.deepStrictEqual(await b.client.decryptGroupOrQueue('grp', 'qa', m2, { id: 2 }), { status: 'pending' });
    assert.deepStrictEqual(await b.client.decryptGroupOrQueue('grp', 'qa', m1, { id: 1 }), { status: 'pending' });
    await b.client.decryptGroupOrQueue('grp', 'qa', m1, { id: 1 });   // duplicate: queued once
    assert.strictEqual(await b.client.acceptSenderKey('qa', keyPackets[0]), 'grp');
    assert.deepStrictEqual(delivered.sort(), [[1, 'first'], [2, 'second']]);
    const m3 = await a.client.encryptGroup('grp', ['qb'], 'third', () => { });
    assert.deepStrictEqual(await b.client.decryptGroupOrQueue('grp', 'qa', m3, { id: 3 }), { status: 'ok', plaintext: 'third' });
  });

  await atest('reactNativeStores maps expo-secure-store / AsyncStorage', async () => {
    const sec = new Map(), as = new Map();
    const { secureStore, store } = e2e.reactNativeStores({
      SecureStore: { getItemAsync: async (k) => sec.get(k) ?? null, setItemAsync: async (k, v) => { sec.set(k, v); }, deleteItemAsync: async (k) => { sec.delete(k); } },
      AsyncStorage: { getItem: async (k) => as.get(k) ?? null, setItem: async (k, v) => { as.set(k, v); }, removeItem: async (k) => { as.delete(k); } },
    });
    const c = mkClient('rn', { secureStore, store });
    await c.client.init();
    await c.client.encryptDirect('ca', 'x');
    assert.ok(sec.has('e2e_identity') && sec.has('e2e_master_key'));
    assert.ok([...as.keys()].every((k) => k.startsWith('e2e:')) && as.size > 0);
  });

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
