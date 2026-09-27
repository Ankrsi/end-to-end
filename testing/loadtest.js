'use strict';
// Load test against the REAL examples/server.js over REAL WebSocket connections.
// Simulates NUM_PAIRS concurrent 1:1 conversations, each doing a fresh X3DH handshake,
// then firing a burst of messages that arrive out of order, and measures end-to-end
// (encrypt -> network -> decrypt) latency, not just isolated crypto speed.

const WebSocket = require('ws');
const { x3dh, RatchetSession } = require('e2e-crypto');

const SERVER_URL = process.argv[2] || 'ws://localhost:8080';
const NUM_PAIRS = parseInt(process.argv[3] || '100', 10);
const MSGS_PER_PAIR = parseInt(process.argv[4] || '20', 10);

function makeClient(username) {
  return new Promise((resolve) => {
    const ws = new WebSocket(SERVER_URL);
    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'register', username, bundle: null }));
    });
    ws.once('message', () => resolve(ws)); // 'registered' ack
  });
}

async function setupPair(i) {
  const aliceName = `alice${i}`, bobName = `bob${i}`;
  const identityA = x3dh.createIdentity();
  const identityB = x3dh.createIdentity();
  const bundleA = x3dh.publicBundle(identityA);
  const bundleB = x3dh.publicBundle(identityB);

  const wsA = await makeClient(aliceName);
  const wsB = await makeClient(bobName);
  wsA.send(JSON.stringify({ type: 'register', username: aliceName, bundle: bundleA }));
  wsB.send(JSON.stringify({ type: 'register', username: bobName, bundle: bundleB }));
  await new Promise(r => setTimeout(r, 20));

  const hs = x3dh.initiateHandshake(identityA, bundleB, 0);
  const sessionA = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);

  return { aliceName, bobName, identityA, identityB, bundleA, wsA, wsB, hs, sessionA };
}

async function sendAndReceive(pair, latencies) {
  const { aliceName, bobName, identityA, identityB, bundleA, wsA, wsB, hs, sessionA } = pair;
  let sessionB = null;
  const pending = new Map();
  let received = 0;

  const done = new Promise((resolve) => {
    wsB.on('message', (raw) => {
      const msg = JSON.parse(raw);
      if (msg.type !== 'direct_message') return;
      const payload = msg.payload;
      if (!sessionB) {
        const resp = x3dh.respondToHandshake(
          identityB,
          Buffer.from(payload.identityDHPub, 'base64'),
          Buffer.from(payload.ephemeralPub, 'base64'),
          payload.otkIndex
        );
        sessionB = RatchetSession.initAsReceiver(resp.sharedSecret, identityB.signedPreKey);
      }
      const n = payload.header.n;
      sessionB.decrypt(payload.header, payload.ciphertext);
      const sentAt = pending.get(n);
      if (sentAt) latencies.push(Number(process.hrtime.bigint() - sentAt) / 1e6);
      received += 1;
      if (received === MSGS_PER_PAIR) resolve();
    });
  });

  const toSend = [];
  for (let n = 0; n < MSGS_PER_PAIR; n++) {
    const { header, ciphertext } = sessionA.encrypt(Buffer.from(`msg ${n} from ${aliceName}`));
    toSend.push({ header, ciphertext });
  }
  for (let k = toSend.length - 1; k > 0; k--) {
    const j = Math.floor(Math.random() * (k + 1));
    [toSend[k], toSend[j]] = [toSend[j], toSend[k]];
  }
  const hsData = {
    identityDHPub: bundleA.identityDHPub,
    ephemeralPub: hs.ephemeralPublicRaw,
    otkIndex: hs.usedOneTimePreKeyIndex,
  };
  toSend.forEach((m, idx) => {
    const payload = idx === 0
      ? { kind: 'handshake+msg', ...hsData, header: m.header, ciphertext: m.ciphertext }
      : { kind: 'msg', header: m.header, ciphertext: m.ciphertext };
    const doSend = () => {
      pending.set(m.header.n, process.hrtime.bigint());
      wsA.send(JSON.stringify({ type: 'direct_message', to: bobName, payload }));
    };
    if (process.env.STAGGER_MS) setTimeout(doSend, idx * Number(process.env.STAGGER_MS));
    else doSend();
  });

  await done;
}


(async () => {
  console.log(`Load test: ${NUM_PAIRS} concurrent pairs x ${MSGS_PER_PAIR} shuffled (out-of-order) messages each = ${NUM_PAIRS * MSGS_PER_PAIR} total messages`);
  const latencies = [];

  const setupStart = process.hrtime.bigint();
  // Phase 1: establish all connections + handshakes first (this is connection/TLS-handshake-bound,
  // not crypto-bound — separate it from message-sending so we don't conflate the two costs)
  const pairs = await Promise.all(Array.from({ length: NUM_PAIRS }, (_, i) => setupPair(i)));
  const setupMs = Number(process.hrtime.bigint() - setupStart) / 1e6;
  console.log(`Connection setup (${NUM_PAIRS * 2} websocket connections + registration): ${setupMs.toFixed(1)}ms`);

  const msgStart = process.hrtime.bigint();
  await Promise.all(pairs.map(p => sendAndReceive(p, latencies)));
  const msgMs = Number(process.hrtime.bigint() - msgStart) / 1e6;

  latencies.sort((a, b) => a - b);
  const pct = (p) => latencies[Math.floor(latencies.length * p)].toFixed(2);

  console.log(`\nMessage phase only (handshake payload + ${NUM_PAIRS * MSGS_PER_PAIR} out-of-order msgs): ${msgMs.toFixed(1)}ms`);
  console.log(`Effective throughput (message phase only): ${(NUM_PAIRS * MSGS_PER_PAIR / (msgMs/1000)).toFixed(0)} messages/sec`);
  console.log(`End-to-end latency (encrypt -> ws relay -> decrypt), out-of-order delivery:`);
  console.log(`  p50: ${pct(0.5)}ms   p90: ${pct(0.9)}ms   p99: ${pct(0.99)}ms   max: ${latencies[latencies.length-1].toFixed(2)}ms`);
  pairs.forEach(p => { p.wsA.close(); p.wsB.close(); });
  process.exit(0);
})();
