'use strict';
const WebSocket = require('ws');
const readline = require('readline');
const { x3dh, RatchetSession, senderKey } = require('e2e-crypto');

const username = process.argv[2];
const serverUrl = process.argv[3] || 'ws://localhost:8080';
if (!username) {
  console.error('Usage: node examples/client.js <username> [ws://host:port]');
  process.exit(1);
}

const identity = x3dh.createIdentity();          // stays on this device, never sent
const myBundle = x3dh.publicBundle(identity);     // only public keys, safe to publish

const ratchets = new Map();          // peer username -> RatchetSession
const pendingHandshake = new Map();  // peer username -> handshake data while awaiting first send

const myGroupSenderStates = new Map();     // group -> my own SenderKeyState (for sending)
const groupSenderStatesFromOthers = new Map(); // `${group}:${fromUser}` -> imported SenderKeyState

const ws = new WebSocket(serverUrl);

function log(...args) { console.log(...args); }

ws.on('open', () => {
  ws.send(JSON.stringify({ type: 'register', username, bundle: myBundle }));
});

function request(type, payload) {
  return new Promise((resolve) => {
    const handler = (raw) => {
      const msg = JSON.parse(raw);
      if (msg.type === (type === 'get_bundle' ? 'bundle' : 'user_list')) {
        ws.off('message', handler);
        resolve(msg);
      }
    };
    ws.on('message', handler);
    ws.send(JSON.stringify({ type, ...payload }));
  });
}

function sendDirect(to, payload) {
  ws.send(JSON.stringify({ type: 'direct_message', to, payload }));
}

async function ensureSession(peer) {
  if (ratchets.has(peer)) return ratchets.get(peer);

  // No session yet -> run X3DH against their published bundle, then start our ratchet
  const { bundle } = await request('get_bundle', { username: peer });
  if (!bundle) throw new Error(`${peer} hasn't registered yet`);

  const hs = x3dh.initiateHandshake(identity, bundle, 0);
  const session = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);
  ratchets.set(peer, session);
  pendingHandshake.set(peer, {
    identityDHPub: Buffer.from(myBundle.identityDHPub, 'base64').toString('base64'),
    ephemeralPub: hs.ephemeralPublicRaw,
    otkIndex: hs.usedOneTimePreKeyIndex,
  });
  return session;
}

async function sendDirectMessage(peer, text) {
  const session = await ensureSession(peer);
  const { header, ciphertext } = session.encrypt(Buffer.from(text, 'utf8'));

  const hsData = pendingHandshake.get(peer);
  if (hsData) {
    // First message to this peer: piggyback the X3DH handshake data
    sendDirect(peer, { kind: 'handshake+msg', ...hsData, header, ciphertext });
    pendingHandshake.delete(peer);
  } else {
    sendDirect(peer, { kind: 'msg', header, ciphertext });
  }
}

function handleIncomingDirect(from, payload) {
  let session = ratchets.get(from);

  if (payload.kind === 'handshake+msg') {
    const { sharedSecret } = x3dh.respondToHandshake(
      identity,
      Buffer.from(payload.identityDHPub, 'base64'),
      Buffer.from(payload.ephemeralPub, 'base64'),
      payload.otkIndex
    );
    session = RatchetSession.initAsReceiver(sharedSecret, identity.signedPreKey);
    ratchets.set(from, session);
  }

  if (!session) {
    log(`[!] Got a message from ${from} but no session exists (out of order?) — dropping.`);
    return;
  }

  try {
    const plaintext = session.decrypt(payload.header, payload.ciphertext);
    log(`\n${from}: ${plaintext}`);
  } catch (e) {
    log(`[!] Failed to decrypt message from ${from}: ${e.message}`);
  }
}

// --- Groups (Sender Keys) ---

async function createGroup(group, members) {
  const others = members.filter(m => m !== username); // never message ourselves
  ws.send(JSON.stringify({ type: 'create_group', group, members: others }));

  const state = senderKey.createSenderKeyState();
  myGroupSenderStates.set(group, state);
  const distMsg = senderKey.exportDistributionMessage(state);

  // Distribute our sender key to each other member privately over their 1:1 ratchet session
  for (const member of others) {
    await ensureSession(member);
    const session = ratchets.get(member);
    const { header, ciphertext } = session.encrypt(Buffer.from(JSON.stringify({ group, distMsg }), 'utf8'));
    const hsData = pendingHandshake.get(member);
    if (hsData) {
      sendDirect(member, { kind: 'handshake+msg', ...hsData, header, ciphertext, senderKeyDist: true });
      pendingHandshake.delete(member);
    } else {
      sendDirect(member, { kind: 'msg', header, ciphertext, senderKeyDist: true });
    }
  }
  log(`[+] Ready to send in group '${group}'. Distributed your sender key to: ${others.join(', ') || '(no one else yet)'}`);
}

function sendGroupMessage(group, text) {
  const state = myGroupSenderStates.get(group);
  if (!state) { log(`[!] You haven't created/joined group '${group}' from this client.`); return; }
  const msg = senderKey.encryptGroupMessage(state, Buffer.from(text, 'utf8'));
  ws.send(JSON.stringify({ type: 'group_message', group, payload: msg }));
}

function handleIncomingGroup(group, from, payload) {
  const key = `${group}:${from}`;
  const state = groupSenderStatesFromOthers.get(key);
  if (!state) {
    log(`[!] No sender key from ${from} for group '${group}' yet — waiting for distribution message.`);
    return;
  }
  try {
    const plaintext = senderKey.decryptGroupMessage(state, payload);
    log(`\n[${group}] ${from}: ${plaintext}`);
  } catch (e) {
    log(`[!] Failed to decrypt group message from ${from}: ${e.message}`);
  }
}

ws.on('message', (raw) => {
  const msg = JSON.parse(raw);

  if (msg.type === 'registered') {
    log(`[+] Registered as '${username}'. Commands:`);
    log(`    /list                          list online users`);
    log(`    /msg <user> <text>             send a private E2E message`);
    log(`    /creategroup <name> <u1,u2>    create a group with members`);
    log(`    /joingroup <name> <u1,u2>      start sending in an existing group (sets up your own sender key)`);
    log(`    /gmsg <group> <text>           send an E2E group message`);
    log(`    /quit`);
    rl.prompt();
    return;
  }

  if (msg.type === 'direct_message') {
    const payload = msg.payload;
    if (payload.senderKeyDist) {
      // This direct message actually carries a group sender-key distribution
      let session = ratchets.get(msg.from);
      if (payload.kind === 'handshake+msg') {
        const { sharedSecret } = x3dh.respondToHandshake(
          identity, Buffer.from(payload.identityDHPub, 'base64'),
          Buffer.from(payload.ephemeralPub, 'base64'), payload.otkIndex
        );
        session = RatchetSession.initAsReceiver(sharedSecret, identity.signedPreKey);
        ratchets.set(msg.from, session);
      }
      const plaintext = session.decrypt(payload.header, payload.ciphertext);
      const { group, distMsg } = JSON.parse(plaintext);
      groupSenderStatesFromOthers.set(`${group}:${msg.from}`, senderKey.importSenderKeyState(distMsg));
      log(`[+] Received sender key for group '${group}' from ${msg.from}`);
      rl.prompt();
      return;
    }
    handleIncomingDirect(msg.from, payload);
    rl.prompt();
    return;
  }

  if (msg.type === 'group_message') {
    handleIncomingGroup(msg.group, msg.from, msg.payload);
    rl.prompt();
    return;
  }
});

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: `${username}> ` });

rl.on('line', async (line) => {
  const [cmd, ...rest] = line.trim().split(' ');
  try {
    if (cmd === '/list') {
      const { users } = await request('list_users', {});
      log('Online:', users.join(', '));
    } else if (cmd === '/msg') {
      const [peer, ...textParts] = rest;
      await sendDirectMessage(peer, textParts.join(' '));
    } else if (cmd === '/creategroup' || cmd === '/joingroup') {
      const [group, memberList] = rest;
      await createGroup(group, memberList.split(','));
    } else if (cmd === '/gmsg') {
      const [group, ...textParts] = rest;
      sendGroupMessage(group, textParts.join(' '));
    } else if (cmd === '/quit') {
      process.exit(0);
    } else if (cmd) {
      log('Unknown command.');
    }
  } catch (e) {
    log(`[!] Error: ${e.message}`);
  }
  rl.prompt();
});
