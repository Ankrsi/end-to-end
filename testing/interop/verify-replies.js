'use strict';
// Step 2 of the cross-language test: JS (alice) decrypts what the native library (bob, carol) sent.
// Usage: node testing/interop/verify-replies.js <replies.json> [stateDir]
const fs = require('fs');
const path = require('path');
const e2e = require('e2e-crypto');

const repliesFile = process.argv[2];
const stateDir = process.argv[3] || __dirname;
if (!repliesFile) { console.error('usage: verify-replies.js <replies.json> [stateDir]'); process.exit(2); }

let passed = 0, failed = 0;
const check = async (name, fn) => {
  try { await fn(); console.log(`  ✓ ${name}`); passed++; } catch (err) { console.log(`  ✗ ${name}\n      ${err.message}`); failed++; }
};
const eq = (a, b, what) => { if (a !== b) throw new Error(`${what}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); };

(async () => {
  const replies = JSON.parse(fs.readFileSync(repliesFile, 'utf8'));
  const state = JSON.parse(fs.readFileSync(path.join(stateDir, 'vectors-state.json'), 'utf8'));
  const map = new Map(state.aliceStore);
  const alice = e2e.deserializeIdentity(state.aliceIdentity);
  const bundles = { ...state.bundles, ...(replies.carol ? { carol: replies.carol.bundle } : {}) };
  const sm = new e2e.SessionManager({
    store: { get: async (k) => (map.has(k) ? map.get(k) : null), set: async (k, v) => { map.set(k, v); }, del: async (k) => { map.delete(k); } },
    loadIdentity: async () => alice,
    fetchBundle: async (u) => e2e.parseBundle(bundles[u]),
  });

  console.log(`\nInterop: JS decrypting replies from ${replies.implementation || 'native'}`);

  await check('envelopes start with {"e2e" (JS detection)', async () => {
    for (const r of [...replies.direct, ...replies.group, ...(replies.carol?.messages || [])]) {
      if (!e2e.isEnvelope(r.env)) throw new Error(`not an envelope: ${r.env.slice(0, 40)}`);
    }
  });

  await check(`1:1 bob→alice, ${replies.direct.length} msgs, reversed order`, async () => {
    for (const r of [...replies.direct].reverse()) eq(await sm.decryptDirect('bob', r.env), r.text, 'plaintext');
  });

  await check('group: bob\'s sender key accepted, messages decrypted out of order', async () => {
    for (const pkt of replies.groupKeyPackets) eq(await sm.acceptSenderKey('bob', pkt), 'g1', 'conversation');
    const shuffled = replies.group.map((r, i) => ({ r, k: (i * 7) % replies.group.length })).sort((a, b) => a.k - b.k).map((x) => x.r);
    for (const r of shuffled) eq(await sm.decryptGroup('g1', 'bob', r.env), r.text, 'group plaintext');
  });

  if (replies.carol) {
    await check('native-initiated handshake (carol→alice) decrypts', async () => {
      for (const r of replies.carol.messages) eq(await sm.decryptDirect('carol', r.env), r.text, 'plaintext');
    });
    await check('native signed prekey verifies in JS (initiateHandshake to carol\'s bundle)', async () => {
      e2e.initiateHandshake(alice, e2e.parseBundle(replies.carol.bundle), 0);
    });
    await check('JS can reply to carol on the same session', async () => {
      const env = await sm.encryptDirect('carol', 'alice→carol');
      if (JSON.parse(env).hs) throw new Error('alice should reuse carol\'s session, not start a new handshake');
    });
  }

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
