# E2E Encrypted Chat — X3DH + Double Ratchet + Sender Keys

A working, from-scratch implementation of the protocol WhatsApp/Signal use, in plain
Node.js (built-in `crypto` only — no crypto npm deps). The server (`examples/server.js`) only ever
sees public key bundles and opaque ciphertext blobs; it can never read a message or
compute a key.

## Why it's fast

- **X25519** for key exchange, **AES-256-GCM** for message encryption — both are
  hardware-accelerated and orders of magnitude cheaper than RSA.
- The expensive asymmetric handshake (X3DH) happens **once per pair of users**. Every
  message after that is one HMAC step (to advance the ratchet) + one AES-GCM call.
  That's it — no public-key math per message.
- **Group messages are O(1) per send**, not O(n): each sender encrypts once with their
  own "sender key" chain (`lib/senderKey.js`) and the ciphertext is fanned out to every
  member, who all decrypt with the same distributed chain key. This is what lets
  WhatsApp groups with hundreds of members stay fast.

## Why it handles concurrent/out-of-order messages

The Double Ratchet (`lib/doubleRatchet.js`) derives a **new key for every message** from
a hash chain. If message #5 arrives before #4 (common on mobile networks, or with
multiple chats interleaving), the receiver just caches the skipped chain keys
(`this.skipped`) and decrypts #5 immediately — no blocking, no waiting for order.
Each conversation also has its own independent ratchet state, so messages in different
chats never block each other.

Verified in testing: out-of-order delivery (`m3` before `m2`), and simultaneous 1:1 +
group traffic, all decrypt correctly (see the test run in `lib/` — run
`node test.js` if you added one, or see the session transcript this was built from).

## Files

- `lib/keys.js` — X25519 / Ed25519 key generation and raw-key <-> KeyObject conversion
- `lib/kdf.js` — HKDF (used once, for X3DH) and the HMAC ratchet-chain KDF (used per message)
- `lib/aead.js` — AES-256-GCM encrypt/decrypt wrapper
- `lib/x3dh.js` — the async handshake (works even if the other person is offline)
- `lib/doubleRatchet.js` — per-message key ratchet with out-of-order support
- `lib/senderKey.js` — group messaging (Signal's "Sender Keys" protocol)
- `examples/server.js` — WebSocket relay (stores public bundles, forwards ciphertext, nothing else)
- `examples/client.js` — CLI client you run once per user

## Run it

```bash
npm install        # installs `ws`, the only dependency
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

## Automated testing

Everything below is self-contained — no manual server setup needed, each command starts
and tears down whatever it needs.

```bash
npm test                  # functional correctness tests (13 checks: handshake, ratcheting,
                           # out-of-order delivery, tamper/replay rejection, groups)

npm run bench              # isolated crypto speed (no network): handshake, encrypt,
                           # decrypt, out-of-order worst case, group send/receive

npm run loadtest            # burst load test: spawns the real server, opens 100 concurrent
                           # WebSocket sessions, fires 2000 out-of-order messages at once,
                           # reports throughput + latency percentiles, shuts server down

npm run loadtest:realistic  # same, but paced like real chat traffic (~200ms between
                           # messages) instead of one giant burst — shows realistic latency

npm run test:all            # runs all of the above in order and writes a timestamped
                           # markdown report to testing/report-<timestamp>.md
                           # (skips perf tests automatically if correctness fails)
```

What each layer actually checks:

| Command | Verifies |
|---|---|
| `npm test` | Correctness: does decryption produce the right plaintext, does it reject tampering/replays, does out-of-order delivery still work |
| `npm run bench` | Speed of the crypto itself, isolated from network |
| `npm run loadtest` | Speed **and** correctness together, over the real WebSocket server, under concurrent + out-of-order conditions — closest to production reality |

If you're iterating on the crypto code, run `npm test` after every change — it's fast
(well under a second) and will catch a broken ratchet or a group-message regression
immediately, the way it caught a real out-of-order bug in `lib/senderKey.js` during
development of this project.

You can tune the load test scale directly:

```bash
node examples/server.js &                                    # start once, leave running
node testing/loadtest.js ws://localhost:8080 500 20          # 500 concurrent pairs, 20 msgs each
STAGGER_MS=100 node testing/loadtest.js ws://localhost:8080 200 15   # paced instead of burst
```

## What's simplified vs. a production system (Signal/WhatsApp)

This is a correct, working implementation of the core protocol — good for learning it or
building on — but a production system adds more:

1. **Persistence**: sessions, skipped-message keys, and identity keys here live in memory
   and vanish when the client exits. Real apps persist these (encrypted at rest) so a
   restart doesn't lose the ability to decrypt.
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
npm test
```
