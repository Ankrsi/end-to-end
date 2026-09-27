'use strict';
// Self-test for SessionManager: out-of-order, concurrent, crossed handshakes, replay and
// groups. Runs anywhere (Node, React Native) — run it on a device to check the real engine
// and storage. Pass a real store to exercise it (keys are namespaced and removed afterwards).

const { createIdentity, publicBundle } = require('./x3dh');
const { SessionManager, MissingSenderKeyError } = require('./session');

const memoryStore = () => {
  const m = new Map();
  return { get: async (k) => (m.has(k) ? m.get(k) : null), set: async (k, v) => { m.set(k, v); }, del: async (k) => { m.delete(k); } };
};

const prefixedStore = (base, prefix, used) => ({
  get: (k) => base.get(prefix + k),
  set: (k, v) => { used.add(prefix + k); return base.set(prefix + k, v); },
  del: (k) => base.del(prefix + k),
});

const shuffle = (a) => {
  const r = [...a];
  for (let i = r.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [r[i], r[j]] = [r[j], r[i]];
  }
  return r;
};

function assert(cond, msg) {
  if (!cond) throw new Error('ASSERT: ' + msg);
}

/**
 * @param {object|null} realStore  store to test against (null = in-memory)
 * @param {(line: string) => void} log
 * @returns {Promise<{passed: number, failed: number}>}
 */
async function runSelfTest(realStore, log = console.log) {
  const server = new Map();
  const cleanup = [];

  const mkUser = (name) => {
    const identity = createIdentity();
    server.set(name, publicBundle(identity));
    let store = memoryStore();
    if (realStore) {
      const keys = new Set();
      store = prefixedStore(realStore, `selftest.${name}.`, keys);
      cleanup.push(keys);
    }
    return new SessionManager({ store, loadIdentity: async () => identity, fetchBundle: async (u) => server.get(u) || null });
  };

  let passed = 0, failed = 0;
  const test = async (name, fn) => {
    const t0 = Date.now();
    try {
      await fn();
      passed++;
      log(`✅ ${name} (${Date.now() - t0} ms)`);
    } catch (e) {
      failed++;
      log(`❌ ${name}: ${(e && e.message) || e}`);
    }
  };

  const N = 50;

  await test(`1:1 out-of-order (${N} msgs shuffled)`, async () => {
    const a = mkUser('a1'), b = mkUser('b1');
    const sent = [];
    for (let i = 0; i < N; i++) sent.push({ env: await a.encryptDirect('b1', 'm' + i), text: 'm' + i });
    for (const m of shuffle(sent)) assert((await b.decryptDirect('a1', m.env)) === m.text, 'wrong plaintext');
  });

  await test(`1:1 concurrent (${N} decrypts at once, shuffled)`, async () => {
    const a = mkUser('a2'), b = mkUser('b2');
    const sent = [];
    for (let i = 0; i < N; i++) sent.push({ env: await a.encryptDirect('b2', 'm' + i), text: 'm' + i });
    const order = shuffle(sent);
    const got = await Promise.all(order.map((m) => b.decryptDirect('a2', m.env)));
    order.forEach((m, i) => assert(got[i] === m.text, `msg ${m.text} decrypted as ${got[i]}`));
  });

  await test('1:1 concurrent encrypts + replies interleaved', async () => {
    const a = mkUser('a3'), b = mkUser('b3');
    const [fromA, fromB] = await Promise.all([
      Promise.all(Array.from({ length: 10 }, (_, i) => a.encryptDirect('b3', 'a' + i))),
      Promise.all(Array.from({ length: 10 }, (_, i) => b.encryptDirect('a3', 'b' + i))),
    ]);
    await Promise.all([
      ...shuffle(fromA.map((e, i) => ({ e, i }))).map(async ({ e, i }) => assert((await b.decryptDirect('a3', e)) === 'a' + i, 'a->b')),
      ...shuffle(fromB.map((e, i) => ({ e, i }))).map(async ({ e, i }) => assert((await a.decryptDirect('b3', e)) === 'b' + i, 'b->a')),
    ]);
    for (let i = 0; i < 5; i++) {
      assert((await b.decryptDirect('a3', await a.encryptDirect('b3', 'x' + i))) === 'x' + i, 'after crossing a->b');
      assert((await a.decryptDirect('b3', await b.encryptDirect('a3', 'y' + i))) === 'y' + i, 'after crossing b->a');
    }
  });

  await test('1:1 duplicate / replay is rejected', async () => {
    const a = mkUser('a4'), b = mkUser('b4');
    const e = await a.encryptDirect('b4', 'once');
    assert((await b.decryptDirect('a4', e)) === 'once', 'first');
    let threw = false;
    try { await b.decryptDirect('a4', e); } catch { threw = true; }
    assert(threw, 'replay accepted');
    assert((await b.decryptDirect('a4', await a.encryptDirect('b4', 'next'))) === 'next', 'session broken after replay');
  });

  await test(`group out-of-order + concurrent (${N} msgs, 3 members)`, async () => {
    const a = mkUser('ga'), b = mkUser('gb'), c = mkUser('gc');
    const users = { gb: b, gc: c };
    const packets = [];
    const sent = [];
    for (let i = 0; i < N; i++) {
      sent.push({ env: await a.encryptGroup('g', ['gb', 'gc'], 'g' + i, (to, env) => { packets.push({ to, env }); }), text: 'g' + i });
    }
    let missing = false;
    try { await b.decryptGroup('g', 'ga', sent[0].env); } catch (e) { missing = e instanceof MissingSenderKeyError; }
    assert(missing, 'expected MissingSenderKeyError before key');
    for (const p of packets) await users[p.to].acceptSenderKey('ga', p.env);
    for (const u of [b, c]) {
      const order = shuffle(sent);
      const got = await Promise.all(order.map((m) => u.decryptGroup('g', 'ga', m.env)));
      order.forEach((m, i) => assert(got[i] === m.text, 'group plaintext mismatch'));
    }
  });

  await test('performance: 1 handshake + 20 msgs', async () => {
    const a = mkUser('pa'), b = mkUser('pb');
    const t0 = Date.now();
    for (let i = 0; i < 20; i++) await b.decryptDirect('pa', await a.encryptDirect('pb', 'p' + i));
    log(`   avg ${(Date.now() - t0) / 20} ms per encrypt+decrypt`);
  });

  for (const keys of cleanup) for (const k of keys) await realStore.del(k);
  log(`Done: ${passed} passed, ${failed} failed${realStore ? ' (real storage)' : ''}`);
  return { passed, failed };
}

module.exports = { runSelfTest };
