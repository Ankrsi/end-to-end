'use strict';
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const wss = new WebSocketServer({ port: PORT });

const clients = new Map();     // username -> ws
const bundles = new Map();     // username -> published public key bundle (JSON)
const groups = new Map();      // groupName -> Set of usernames

function send(ws, obj) {
  if (ws && ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

wss.on('connection', (ws) => {
  let username = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {
      case 'register': {
        username = msg.username;
        clients.set(username, ws);
        bundles.set(username, msg.bundle); // public prekey bundle only
        console.log(`[server] ${username} registered (bundle published, no private data)`);
        send(ws, { type: 'registered', username });
        break;
      }

      case 'get_bundle': {
        const bundle = bundles.get(msg.username);
        send(ws, { type: 'bundle', username: msg.username, bundle: bundle || null });
        break;
      }

      case 'list_users': {
        send(ws, { type: 'user_list', users: Array.from(clients.keys()) });
        break;
      }

      // Relay a 1:1 handshake or ratchet-encrypted message — opaque blob to us
      case 'direct_message': {
        const target = clients.get(msg.to);
        send(target, { type: 'direct_message', from: username, payload: msg.payload });
        break;
      }

      case 'create_group': {
        if (!groups.has(msg.group)) groups.set(msg.group, new Set());
        groups.get(msg.group).add(username);
        (msg.members || []).forEach(m => groups.get(msg.group).add(m));
        console.log(`[server] group '${msg.group}' now has members: ${[...groups.get(msg.group)]}`);
        break;
      }

      // Sender-key distribution messages (still individually encrypted per-recipient
      // via 1:1 ratchet) or group ciphertext — relay to every other member
      case 'group_message': {
        const members = groups.get(msg.group) || new Set();
        for (const member of members) {
          if (member !== username) send(clients.get(member), {
            type: 'group_message', group: msg.group, from: username, payload: msg.payload,
          });
        }
        break;
      }

      default:
        break;
    }
  });

  ws.on('close', () => {
    if (username) {
      clients.delete(username);
      console.log(`[server] ${username} disconnected`);
    }
  });
});

console.log(`[server] E2E chat relay listening on ws://localhost:${PORT}`);
console.log(`[server] Server only ever stores/relays: public key bundles + opaque ciphertext blobs.`);
