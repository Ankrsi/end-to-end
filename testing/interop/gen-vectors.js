'use strict';
// Step 1 of the cross-language test. Writes:
//   vectors.json        — fixed-input results for every primitive, plus real envelopes from
//                         "alice" (JS) to "bob" (played by the native library under test)
//   vectors-state.json  — alice's private state, used by verify-replies.js (test data only)
// Usage: node testing/interop/gen-vectors.js [outDir]
const fs = require('fs');
const path = require('path');
const e2e = require('e2e-crypto');
const { hkdf, kdfChainKey } = require('../../e2e-crypto/src/kdf');
const aead = require('../../e2e-crypto/src/aead');
const keys = require('../../e2e-crypto/src/keys');

const outDir = process.argv[2] || __dirname;
const b64 = e2e.toBase64;
const seq = (n, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);

const mapStore = (map = new Map()) => ({
  map,
  get: async (k) => (map.has(k) ? map.get(k) : null),
  set: async (k, v) => { map.set(k, v); },
  del: async (k) => { map.delete(k); },
});

(async () => {
  // Deterministic primitives: every implementation must reproduce these bytes exactly.
  const x25519PrivA = seq(32, 1), x25519PrivB = seq(32, 101);
  const { x25519, ed25519 } = require('@noble/curves/ed25519');
  const edSeed = seq(32, 7);
  const edMsg = e2e.utf8Encode('e2e-crypto interop ✍️');
  const chain = kdfChainKey(seq(32, 50));
  const aeadKey = seq(32, 200);
  const aeadText = 'héllo 🔒 wörld — 你好';
  const primitives = {
    base64: [0, 1, 2, 3, 4, 5, 31, 32, 33].map((n) => ({ bytes: b64(seq(n, 250)), len: n })),
    hkdf: [
      { ikm: b64(seq(32)), salt: b64(seq(32, 64)), info: 'E2EChat-RootRatchet', length: 64 },
      { ikm: b64(seq(32, 9)), salt: '', info: 'E2EChat-MsgKey', length: 44 },
      { ikm: b64(seq(160, 3)), salt: b64(new Uint8Array(32)), info: 'E2EChat-X3DH', length: 32 },
    ].map((v) => ({ ...v, out: b64(hkdf(e2e.fromBase64(v.ikm), e2e.fromBase64(v.salt), v.info, v.length)) })),
    chain: { chainKey: b64(seq(32, 50)), nextChainKey: b64(chain.chainKey), messageKey: b64(chain.messageKey) },
    aead: { messageKey: b64(aeadKey), plaintext: aeadText, ciphertext: b64(aead.encrypt(aeadKey, e2e.utf8Encode(aeadText))) },
    x25519: {
      privA: b64(x25519PrivA), pubA: b64(x25519.getPublicKey(x25519PrivA)),
      pubB: b64(x25519.getPublicKey(x25519PrivB)), shared: b64(keys.dh(x25519PrivA, x25519.getPublicKey(x25519PrivB))),
    },
    ed25519: { seed: b64(edSeed), publicKey: b64(ed25519.getPublicKey(edSeed)), message: b64(edMsg), signature: b64(ed25519.sign(edMsg, edSeed)) },
  };

  // Protocol: alice (JS) -> bob (native)
  const server = new Map();
  const alice = e2e.createIdentity(), bob = e2e.createIdentity();
  server.set('alice', e2e.serializeBundle(e2e.publicBundle(alice)));
  server.set('bob', e2e.serializeBundle(e2e.publicBundle(bob)));
  const aliceStore = mapStore();
  const sm = new e2e.SessionManager({
    store: aliceStore,
    loadIdentity: async () => alice,
    fetchBundle: async (u) => e2e.parseBundle(server.get(u)),
  });

  const directTexts = Array.from({ length: 10 }, (_, i) => `alice→bob #${i} héllo 🔒 你好`);
  const directEnvs = [];
  for (const t of directTexts) directEnvs.push(await sm.encryptDirect('bob', t));
  const order = [7, 2, 9, 0, 5, 1, 8, 3, 6, 4];   // out-of-order delivery

  const keyPackets = [];
  const groupTexts = Array.from({ length: 5 }, (_, i) => `alice group #${i} 👋`);
  const groupEnvs = [];
  for (const t of groupTexts) groupEnvs.push(await sm.encryptGroup('g1', ['bob'], t, (to, env) => keyPackets.push({ to, env })));

  const vectors = {
    protocolVersion: 'x3dh1',
    primitives,
    bobIdentity: e2e.serializeIdentity(bob),
    bundles: Object.fromEntries(server),
    direct: { from: 'alice', envelopes: directEnvs, plaintexts: directTexts, order },
    group: { conversationId: 'g1', from: 'alice', keyPackets: keyPackets.map((p) => p.env), envelopes: groupEnvs, plaintexts: groupTexts, order: [4, 0, 3, 1, 2] },
  };
  fs.writeFileSync(path.join(outDir, 'vectors.json'), JSON.stringify(vectors, null, 1));
  fs.writeFileSync(path.join(outDir, 'vectors-state.json'), JSON.stringify({
    aliceIdentity: e2e.serializeIdentity(alice), aliceStore: [...aliceStore.map], bundles: Object.fromEntries(server),
  }));
  console.log(`vectors written to ${outDir}`);
})().catch((e) => { console.error(e); process.exit(1); });
