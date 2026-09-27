# E2E Encrypted Chat — X3DH + Double Ratchet + Sender Keys

A working, from-scratch implementation of the protocol WhatsApp/Signal use. The crypto
lives in [`e2e-crypto/`](e2e-crypto/README.md), a standalone package that runs in both Node
and **React Native** (same API, same wire format). The server (`examples/server.js`) only ever
sees public key bundles and opaque ciphertext blobs; it can never read a message or
compute a key.

## Why it's fast

- **X25519** for key exchange, **AES-256-GCM** for message encryption — both are
  hardware-accelerated and orders of magnitude cheaper than RSA.
- The expensive asymmetric handshake (X3DH) happens **once per pair of users**. Every
  message after that is one HMAC step (to advance the ratchet) + one AES-GCM call.
  That's it — no public-key math per message.
- **Group messages are O(1) per send**, not O(n): each sender encrypts once with their
  own "sender key" chain (`e2e-crypto/src/senderKey.js`) and the ciphertext is fanned out to every
  member, who all decrypt with the same distributed chain key. This is what lets
  WhatsApp groups with hundreds of members stay fast.

## Why it handles concurrent/out-of-order messages

The Double Ratchet (`e2e-crypto/src/doubleRatchet.js`) derives a **new key for every message** from
a hash chain. If message #5 arrives before #4 (common on mobile networks, or with
multiple chats interleaving), the receiver just caches the skipped chain keys
(`this.skipped`) and decrypts #5 immediately — no blocking, no waiting for order.
Each conversation also has its own independent ratchet state, so messages in different
chats never block each other.

Verified in testing: out-of-order delivery (`m3` before `m2`), and simultaneous 1:1 +
group traffic, all decrypt correctly — run `npm test`.

## Files

- `e2e-crypto/` — the encryption library (use this in your React Native app; see its README)
  - `src/x3dh.js` — the async handshake (works even if the other person is offline)
  - `src/doubleRatchet.js` — per-message key ratchet with out-of-order support
  - `src/senderKey.js` — group messaging (Signal's "Sender Keys" protocol)
  - `src/keys.js`, `src/backends/` — X25519 / Ed25519, pure-JS or native OpenSSL
  - `src/kdf.js`, `src/aead.js` — HKDF / HMAC chain KDF, AES-256-GCM
- `testing/` — functional tests, benchmarks, load tests
- `examples/server.js` — WebSocket relay (stores public bundles, forwards ciphertext, nothing else)
- `examples/client.js` — CLI client you run once per user

## Run it

```bash
npm install        # installs `ws` and links the local e2e-crypto package
node examples/server.js      # starts the relay on ws://localhost:8080
```

In separate terminals:

```bash
node examples/client.js alice
node examples/client.js bob
```

Commands inside a client session:

```
/list                          list online users
/msg <user> <text>              send a private, end-to-end encrypted message
/creategroup <name> <u1,u2>     create a group and set up your sender key
/joingroup <name> <u1,u2>       start sending in an existing group (any member can run this)
/gmsg <group> <text>            send an end-to-end encrypted group message
/quit
```

Try: open 3 terminals (alice, bob, carol) — `/msg` between any two, and
`/creategroup family bob,carol` from alice, then `/joingroup family alice,carol` from bob,
then everyone `/gmsg family ...`.

## What's simplified vs. a production system (Signal/WhatsApp)

This is a correct, working implementation of the core protocol — good for learning it or
building on — but a production system adds more:

1. **Persistence**: the library can serialize identities, sessions and sender keys
   (see `e2e-crypto/README.md`), but the CLI demo client keeps them in memory, so they
   vanish when it exits.
2. **Prekey replenishment**: the demo generates 10 one-time prekeys once; a real server
   tracks how many are left per user and asks the client to upload more before running out.
3. **Multi-device**: WhatsApp/Signal handle a user having several devices, each with its
   own identity, fanning messages out to all of them. Not modeled here.
4. **Associated data binding**: production Double Ratchet implementations bind each
   message's AD to both parties' identity keys to prevent certain identity-substitution
   attacks. Simplified here for readability.
5. **Prekey signature/identity verification UX**: we verify the signed-prekey signature,
   but there's no "safety number" comparison flow for users to verify they're not being
   MITM'd — that's a UX layer real apps add on top.
6. **Transport security**: this demo uses plain `ws://`. A real deployment needs
   `wss://` (TLS) for the transport layer too — E2E encryption protects the payload, but
   TLS still matters for metadata and connection integrity.

## Quick sanity check

```bash
npm test          # protocol tests on both crypto backends, no network needed
```
