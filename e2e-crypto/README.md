# e2e-crypto

End-to-end encryption for chat: **X3DH** key agreement, **Double Ratchet** for 1:1 messages,
**Sender Keys** for groups (the Signal/WhatsApp design). Plain JavaScript with TypeScript
types; runs in **React Native** and **Node** with the same API and the same wire format.

- No native modules required. Crypto comes from the audited [`@noble`](https://paulmillr.com/noble/) libraries.
- No `Buffer`, `TextDecoder` or `atob` needed. Works on Hermes.
- All keys and state are plain data that can be serialized, so sessions survive app restarts.
- On Node, native OpenSSL is used automatically for the curve math.

## Install in a React Native app

Requirements: React Native 0.70+ (Hermes with BigInt) or Expo SDK 47+.

Build a tarball of the package, then install it in your app:

```bash
cd path/to/server/e2e-crypto
npm pack                                   # -> e2e-crypto-<version>.tgz

cd path/to/your-rn-app
npm install path/to/server/e2e-crypto/e2e-crypto-<version>.tgz
npm install react-native-get-random-values # secure randomness for RN
```

The tarball avoids Metro's problems with symlinked packages outside the project root. For a
team, publish it to a private registry (or GitHub Packages) instead.

Import the random-values polyfill **once, first**, in your entry file (`index.js` / `App.tsx`),
before anything imports `e2e-crypto`:

```js
import 'react-native-get-random-values';
```

Without it, key generation throws a clear error rather than using weak randomness.

In Node (18+) and browsers nothing extra is needed.

## Use it in any project (E2EEClient)

`E2EEClient` is the recommended way in: it manages the identity, encrypts everything it stores,
keeps sessions and group keys, and queues group messages whose key hasn't arrived yet. Your
project only connects **storage** and **your server**; how the encrypted strings travel
(socket, HTTP, push) stays up to you.

### 1. Create the client

React Native / Expo:

```ts
import 'react-native-get-random-values';            // first line of your entry file
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as SecureStore from 'expo-secure-store';
import { E2EEClient, reactNativeStores } from 'e2e-crypto';

export const e2e = new E2EEClient({
  ...reactNativeStores({ SecureStore, AsyncStorage }),                 // secrets in Keychain/Keystore, rest encrypted
  uploadBundle: (bundle) => api.post('/keys', { bundle }),             // your endpoint: store one string per user
  fetchBundle: (userId) => api.get(`/keys/${userId}`).then((r) => r.bundle ?? null),
  onPendingDecrypted: (meta, text) => db.updateMessage(meta.messageId, text),   // late group messages
});
```

Node / other platforms: pass any `{ get, set, del }` async stores instead of `reactNativeStores(...)`
(`memoryStore()` for tests; a file or DB table in production). `secureStore` holds only two
small values (identity, storage key); `store` holds the rest, encrypted with AES-256-GCM.

### 2. After login

```ts
await e2e.init();   // first run: creates keys and uploads the public bundle. Safe to call on every start.
```

### 3. Send and receive

```ts
// 1:1
const env = await e2e.encryptDirect(peerId, JSON.stringify(message));  // null => peer has no keys yet
send({ to: peerId, content: env ?? message });
const text = await e2e.decryptDirect(senderId, received.content);       // plaintext passes through unchanged

// groups — your sender key goes to members who lack it via the callback, over 1:1 sessions
const genv = await e2e.encryptGroup(groupId, otherMemberIds, JSON.stringify(message),
  (to, keyEnvelope) => send({ type: 'group-key', to, groupId, content: keyEnvelope }));
// receiving side
await e2e.acceptSenderKey(from, packet.content);                        // on a 'group-key' packet
const r = await e2e.decryptGroupOrQueue(groupId, from, received.content, { messageId });
if (r.status === 'ok') show(r.plaintext); else show('Waiting for this message…');

// housekeeping
await e2e.resetGroup(groupId);          // a member left/was removed: rotate your sender key
await e2e.refreshBundle(peerId);        // opening a chat: notice if they reinstalled
```

Envelopes are JSON strings starting with `{"e2e"`; `isEnvelope(value)` tells them apart from
plaintext, so encrypted and unencrypted clients can coexist during a rollout.

### What your server needs

- Store one bundle string per user (`uploadBundle`) and return it (`fetchBundle`).
- Relay message strings unchanged. It never sees private keys or plaintext.

### Check it on a device

`runSelfTest(e2e.store, console.log)` runs the out-of-order / concurrent / crossed-handshake /
replay / group checks against the real storage (test keys are cleaned up afterwards).

## Native apps: Kotlin and Swift

The same protocol and API are available natively, with identical wire formats:

- **Android / JVM:** [`../e2e-crypto-kotlin`](../e2e-crypto-kotlin) (`E2EEClient`, `SessionManager`, …)
- **iOS / macOS:** [`../e2e-crypto-swift`](../e2e-crypto-swift) (Swift Package `E2ECrypto`)

`npm run test:interop` (server project) checks that JS, Kotlin and Swift reproduce the same
primitives byte for byte and can decrypt each other's 1:1 and group messages, in both directions.

## Low-level API

Everything `E2EEClient` is built from is exported too, for custom designs.

### Your identity (once per install)

```ts
import { createIdentity, publicBundle, serializeIdentity, deserializeIdentity } from 'e2e-crypto';

const identity = createIdentity();          // private — never leaves the device
await secureStore.set('identity', serializeIdentity(identity));
api.uploadBundle(publicBundle(identity));    // public keys only; this is what the server stores
```

### 1:1 — sending the first message (Alice)

```ts
import { initiateHandshake, RatchetSession } from 'e2e-crypto';

const bobBundle = await api.getBundle('bob');
const hs = initiateHandshake(identity, bobBundle, 0);      // verifies Bob's signed prekey
const session = RatchetSession.initAsSender(hs.sharedSecret, hs.bobSignedPreKeyPublicRaw);

const { header, ciphertext } = session.encrypt('hi bob');
socket.send({
  type: 'direct_message', to: 'bob',
  payload: {
    kind: 'handshake+msg',                               // first message carries the handshake
    identityDHPub: publicBundle(identity).identityDHPub,
    ephemeralPub: hs.ephemeralPublicRaw,
    otkIndex: hs.usedOneTimePreKeyIndex,
    header, ciphertext,
  },
});
// later messages: payload = { kind: 'msg', header, ciphertext }
```

### 1:1 — receiving (Bob)

```ts
import { respondToHandshake, RatchetSession } from 'e2e-crypto';

function onDirectMessage(from: string, payload) {
  let session = sessions.get(from);
  if (payload.kind === 'handshake+msg') {
    const { sharedSecret } = respondToHandshake(identity, payload.identityDHPub, payload.ephemeralPub, payload.otkIndex);
    session = RatchetSession.initAsReceiver(sharedSecret, identity.signedPreKey);
    sessions.set(from, session);
  }
  const text = session.decrypt(payload.header, payload.ciphertext); // throws on tamper/replay
}
```

Messages may arrive in any order (up to 1000 skipped per chain). If a message fails to
decrypt (corrupted, forged or replayed), the session state is left unchanged and later
messages still decrypt.

### Groups (Sender Keys)

```ts
import { createSenderKeyState, exportDistributionMessage, importSenderKeyState,
         encryptGroupMessage, decryptGroupMessage } from 'e2e-crypto';

// Sender: one sender key per group. Send its distribution message to each member
// privately, through their 1:1 session.
const mine = createSenderKeyState();
const dist = exportDistributionMessage(mine);
for (const member of members) sendDirectEncrypted(member, JSON.stringify({ group, distMsg: dist }));

// Each send is encrypted once, whatever the group size.
socket.send({ type: 'group_message', group, payload: encryptGroupMessage(mine, 'hello all') });

// Receiver: import each member's distribution message, then decrypt their messages.
const theirs = importSenderKeyState(distMsg);
const text = decryptGroupMessage(theirs, payload); // verifies the Ed25519 signature first
```

Binary payloads are supported too: `encrypt()` and `encryptGroupMessage()` accept a
`Uint8Array`, and `decryptBytes()` / `decryptGroupMessageBytes()` return one.

## Session manager (recommended for chat apps)

`SessionManager` does the bookkeeping above for you: one 1:1 session per peer, Sender Keys per
group, and the edge cases that come with real delivery. You give it three things; it returns
envelopes (JSON strings) to put in your messages.

```ts
import { SessionManager, MissingSenderKeyError, isEnvelope } from 'e2e-crypto';

const sessions = new SessionManager({
  store,                                   // { get, set, del } — async, ENCRYPTED at rest
  loadIdentity: async () => identity,      // your deserialized identity
  fetchBundle: async (userId) => bundle,   // their public bundle from your server, or null
});

// 1:1
const env = await sessions.encryptDirect('bob', 'hi');      // null if bob has no bundle
const text = await sessions.decryptDirect('alice', env);    // plaintext input passes through

// Groups: your sender key is sent to members who lack it via `distribute`, over 1:1 sessions
const genv = await sessions.encryptGroup(groupId, memberIds, 'hello all',
  (to, keyEnvelope) => socket.emit('group-key', { groupId, to, content: keyEnvelope }));
await sessions.acceptSenderKey(fromUserId, keyEnvelope);    // on the receiving side
try {
  const gtext = await sessions.decryptGroup(groupId, fromUserId, genv);
} catch (e) {
  if (e instanceof MissingSenderKeyError) { /* key still on its way: retry after acceptSenderKey */ }
}

await sessions.resetGroup(groupId);   // after someone leaves: next send rotates your sender key
await sessions.getBundle('bob', true); // refresh a peer's bundle (e.g. on opening their chat)
```

What it handles:
- **First contact:** the handshake rides along on every message until the peer replies.
- **Out-of-order and duplicate delivery:** late messages decrypt; replays are rejected.
- **Concurrency:** calls for the same peer/group are serialised, so a socket, an offline
  sync and a push handler can decrypt at the same time without corrupting state.
- **Crossed handshakes:** both sides starting at once converge on one session (the last 3
  sessions per peer are kept and tried).
- **Peer reinstall:** a handshake from a new identity replaces the session and drops the stale
  cached bundle.
- **Group rotation:** members are tracked by identity key, so a reinstalled member gets the
  sender key again; the last 3 sender keys per member are kept for late messages.

`runSelfTest(store, log)` checks all of the above (pass `null` for an in-memory store, or a
real store to exercise it on a device). It is part of `npm test`.

Envelope wire format: 1:1 `{ e2e: 'dr1', hs?: { ik, ek, otk }, h, c }`; group
`{ e2e: 'sk1', kid, i, c, s }`; sender key packets are 1:1 envelopes carrying
`{ t: 'skdm', conversationId, kid, dist }`.

## Persistence (surviving app restarts)

All state has to be saved, or the app can't decrypt after a restart:

| State | Save with | Restore with | When to save |
|---|---|---|---|
| Identity | `serializeIdentity(identity)` | `deserializeIdentity(str)` | once |
| 1:1 session | `session.serialize()` | `RatchetSession.deserialize(str)` | after **every** encrypt/decrypt |
| Sender key (yours or imported) | `serializeSenderKeyState(s)` | `deserializeSenderKeyState(str)` | after every group send/receive |

These strings contain **private keys**. Don't store them in plain AsyncStorage. Either:
- put them in the Keychain/Keystore (`react-native-keychain`, `expo-secure-store`), or
- keep a random key in the Keychain and use it to encrypt the blobs you save elsewhere.
  Session blobs grow with the number of skipped keys, and `expo-secure-store` warns about
  values over 2 KB.

## Performance and native backends

Only the elliptic-curve operations are pluggable. Hashing, HMAC, HKDF and AES-GCM always run
in JS and handle about 25k messages/s on a laptop.

| Backend | Where | Handshake | Group send | Group receive |
|---|---|---|---|---|
| `noble` (pure JS, default) | everywhere | ~14 ms | ~0.8 ms | ~3.8 ms |
| `node-crypto` (OpenSSL) | Node (automatic) | ~0.6 ms | ~0.08 ms | ~0.19 ms |

These are laptop numbers (i5-1135G7). Expect pure JS on Hermes to be several times slower,
because Hermes BigInt is slow. It's fine for normal chat, but noticeable when catching up on a
large group backlog.

For native speed in React Native you can try
[`react-native-quick-crypto`](https://github.com/margelo/react-native-quick-crypto), which
implements Node's crypto API. **This combination has not been tested.** Check it before
switching:

```ts
import QuickCrypto from 'react-native-quick-crypto';
import { createNodeCryptoBackend, checkCryptoBackend, setCryptoBackend } from 'e2e-crypto';

const native = createNodeCryptoBackend(QuickCrypto);
checkCryptoBackend(native);   // throws if it isn't interchangeable with the reference
setCryptoBackend(native);
```

Keys are raw bytes in every backend, so switching backends never invalidates stored identities
or sessions, and users on different backends can talk to each other. The test suite checks this.

## Wire format

All binary values are standard base64.

- **Public bundle:** `{ identitySignPub, identityDHPub, signedPreKeyPub, signedPreKeySig, oneTimePreKeys[] }`
- **1:1 message:** `{ header: { dh, pn, n }, ciphertext }`, where ciphertext is AES-256-GCM output with the tag appended
- **Group message:** `{ iteration, ciphertext, signature }`
- **Sender key distribution:** `{ chainKey, iteration, signPublic }`, where `signPublic` is the raw 32-byte Ed25519 key (earlier Node-only versions sent PEM)

## Known limitations

Carried over from the original design:
- **One-time prekeys are never used up.** The demo server always hands out index 0 and
  nothing deletes a used prekey, so a production server should give out a different prekey
  per handshake and have clients upload more.
- **Associated data isn't bound to identities.** Messages aren't tied to the two identity
  keys, and there's no safety-number UI for users to verify each other.
- **No multi-device support.** Each identity is one device.
- **Transport isn't covered.** Use `wss://` (TLS) for the socket as well.

## Testing

From the server project: `npm test` runs the suite on both backends, and `npm run test:all`
adds the benchmarks and load tests over the real WebSocket server.
