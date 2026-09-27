'use strict';
const { x3dh, RatchetSession, senderKey } = require('e2e-crypto');

function bench(label, fn, n) {
  const start = process.hrtime.bigint();
  fn(n);
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  console.log(`${label.padEnd(55)} ${n} ops in ${ms.toFixed(1)}ms  ->  ${(n / (ms / 1000)).toFixed(0)} ops/sec, ${(ms / n * 1000).toFixed(1)}µs/op`);
}

console.log(`\nNode ${process.version}, ${require('os').cpus().length} CPU(s): ${require('os').cpus()[0].model}\n`);

// --- X3DH: real per-new-contact cost (identities pre-existing, not created fresh each time) ---
const alice = x3dh.createIdentity();
const bundles = Array.from({ length: 500 }, () => x3dh.publicBundle(x3dh.createIdentity()));
bench('X3DH handshake (new contact, identities pre-existing)', (n) => {
  for (let i = 0; i < n; i++) x3dh.initiateHandshake(alice, bundles[i % bundles.length], 0);
}, 1000);

// --- Ratchet steady state ---
const bob = x3dh.createIdentity();
const bobBundle = x3dh.publicBundle(bob);
const aliceBundle = x3dh.publicBundle(alice);
const hs = x3dh.initiateHandshake(alice, bobBundle, 0);
const sessionA = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);
bench('Ratchet encrypt (send a message)', (n) => {
  for (let i = 0; i < n; i++) sessionA.encrypt(Buffer.from('hello world ' + i));
}, 50000);

const resp = x3dh.respondToHandshake(bob, Buffer.from(aliceBundle.identityDHPub, 'base64'), Buffer.from(hs.ephemeralPublicRaw, 'base64'), hs.usedOneTimePreKeyIndex);
const sessionB = RatchetSession.initAsReceiver(resp.sharedSecret, bob.signedPreKey);
const sessionA2 = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);
const msgs = [];
for (let i = 0; i < 20000; i++) msgs.push(sessionA2.encrypt(Buffer.from('msg ' + i)));
bench('Ratchet decrypt (in-order)', (n) => {
  for (let i = 0; i < n; i++) sessionB.decrypt(msgs[i].header, msgs[i].ciphertext);
}, 20000);

// --- Out-of-order worst case ---
const alice3 = x3dh.createIdentity(), bob3 = x3dh.createIdentity();
const hs3 = x3dh.initiateHandshake(alice3, x3dh.publicBundle(bob3), 0);
const s3 = RatchetSession.initAsSender(hs3.sharedSecret, hs3.bobSignedPreKeyPublicRaw);
const resp3 = x3dh.respondToHandshake(bob3, Buffer.from(x3dh.publicBundle(alice3).identityDHPub, 'base64'), Buffer.from(hs3.ephemeralPublicRaw, 'base64'), hs3.usedOneTimePreKeyIndex);
const r3 = RatchetSession.initAsReceiver(resp3.sharedSecret, bob3.signedPreKey);
const N = 500;
const msgs3 = [];
for (let i = 0; i < N; i++) msgs3.push(s3.encrypt(Buffer.from('msg ' + i)));
const t0 = process.hrtime.bigint();
r3.decrypt(msgs3[N - 1].header, msgs3[N - 1].ciphertext);
console.log(`${('Decrypt last-of-' + N + ' arriving FIRST (worst-case reorder)').padEnd(55)} ${(Number(process.hrtime.bigint() - t0) / 1e6).toFixed(2)}ms one-time cost to backfill ${N - 1} keys`);

// --- Group / Sender Keys ---
const gState = senderKey.createSenderKeyState();
bench('Group encrypt (sender, flat cost regardless of group size)', (n) => {
  for (let i = 0; i < n; i++) senderKey.encryptGroupMessage(gState, Buffer.from('g' + i));
}, 50000);

const gState2 = senderKey.createSenderKeyState();
const memberState = senderKey.importSenderKeyState(senderKey.exportDistributionMessage(gState2));
const gmsgs = [];
for (let i = 0; i < 20000; i++) gmsgs.push(senderKey.encryptGroupMessage(gState2, Buffer.from('g' + i)));
bench('Group decrypt (per member, incl. signature verify)', (n) => {
  for (let i = 0; i < n; i++) senderKey.decryptGroupMessage(memberState, gmsgs[i]);
}, 20000);

console.log('\nDone. For real network + concurrency numbers, run: npm run loadtest\n');
