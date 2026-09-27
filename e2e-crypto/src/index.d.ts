// Type definitions for e2e-crypto

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Private, on-device identity. Persist with serializeIdentity() in secure storage. */
export interface Identity {
  identitySign: KeyPair;
  identityDH: KeyPair;
  signedPreKey: KeyPair;
  signedPreKeySig: Uint8Array;
  oneTimePreKeys: KeyPair[];
}

/** Public keys only (all base64). Safe to upload to the server. */
export interface PublicBundle {
  identitySignPub: string;
  identityDHPub: string;
  signedPreKeyPub: string;
  signedPreKeySig: string;
  oneTimePreKeys: string[];
}

export interface HandshakeResult {
  sharedSecret: Uint8Array;
  /** base64 — send to the responder along with the first message */
  ephemeralPublicRaw: string;
  /** send to the responder along with the first message */
  usedOneTimePreKeyIndex: number | null;
  associatedData: Uint8Array;
  bobSignedPreKeyPublicRaw: Uint8Array;
}

export interface RespondResult {
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
}

export function createIdentity(options?: { oneTimePreKeyCount?: number }): Identity;
export function publicBundle(identity: Identity): PublicBundle;
export function initiateHandshake(myIdentity: Identity, theirBundle: PublicBundle, usedOneTimePreKeyIndex?: number): HandshakeResult;
/** Public keys may be raw bytes or base64 strings. */
export function respondToHandshake(
  myIdentity: Identity,
  aliceIdentityDHPub: Uint8Array | string,
  aliceEphemeralPub: Uint8Array | string,
  oneTimePreKeyUsed: number | null | undefined,
): RespondResult;
export function serializeIdentity(identity: Identity): string;
export function deserializeIdentity(json: string | object): Identity;

export interface MessageHeader {
  /** sender's current ratchet public key, base64 */
  dh: string;
  pn: number;
  n: number;
}

export interface EncryptedMessage {
  header: MessageHeader;
  /** base64 */
  ciphertext: string;
}

export class RatchetSession {
  /** Initiator side, right after initiateHandshake(). */
  static initAsSender(sharedSecret: Uint8Array, bobRatchetPublicRaw: Uint8Array): RatchetSession;
  /** Responder side, right after respondToHandshake(). Pass identity.signedPreKey. */
  static initAsReceiver(sharedSecret: Uint8Array, bobRatchetKeyPair: KeyPair): RatchetSession;
  static deserialize(json: string | object): RatchetSession;

  encrypt(plaintext: string | Uint8Array, associatedData?: Uint8Array): EncryptedMessage;
  /** Returns the UTF-8 plaintext. Throws on tampering/replay; session state is unchanged on failure. */
  decrypt(header: MessageHeader, ciphertext: string, associatedData?: Uint8Array): string;
  /** Like decrypt() but returns raw bytes. */
  decryptBytes(header: MessageHeader, ciphertext: string, associatedData?: Uint8Array): Uint8Array;

  /** Save after every encrypt/decrypt — the state advances with each message. Contains secrets. */
  serialize(): string;
  toJSON(): object;
}

export interface SenderKeyState {
  chainKey: Uint8Array;
  iteration: number;
  signPublic: Uint8Array;
  /** Only present on your own sending state. */
  signPrivate?: Uint8Array;
  skipped: Map<number, Uint8Array>;
}

export interface SenderKeyDistributionMessage {
  chainKey: string;
  iteration: number;
  signPublic: string;
}

export interface GroupMessage {
  iteration: number;
  ciphertext: string;
  signature: string;
}

export function createSenderKeyState(): SenderKeyState;
/** Send this to each group member over their 1:1 RatchetSession. */
export function exportDistributionMessage(state: SenderKeyState): SenderKeyDistributionMessage;
export function importSenderKeyState(distMsg: SenderKeyDistributionMessage): SenderKeyState;
export function encryptGroupMessage(senderState: SenderKeyState, plaintext: string | Uint8Array): GroupMessage;
export function decryptGroupMessage(senderKeyState: SenderKeyState, msg: GroupMessage): string;
export function decryptGroupMessageBytes(senderKeyState: SenderKeyState, msg: GroupMessage): Uint8Array;
export function serializeSenderKeyState(state: SenderKeyState): string;
export function deserializeSenderKeyState(json: string | object): SenderKeyState;

export const x3dh: {
  createIdentity: typeof createIdentity;
  publicBundle: typeof publicBundle;
  initiateHandshake: typeof initiateHandshake;
  respondToHandshake: typeof respondToHandshake;
  serializeIdentity: typeof serializeIdentity;
  deserializeIdentity: typeof deserializeIdentity;
};

export const senderKey: {
  createSenderKeyState: typeof createSenderKeyState;
  exportDistributionMessage: typeof exportDistributionMessage;
  importSenderKeyState: typeof importSenderKeyState;
  encryptGroupMessage: typeof encryptGroupMessage;
  decryptGroupMessage: typeof decryptGroupMessage;
  decryptGroupMessageBytes: typeof decryptGroupMessageBytes;
  serializeSenderKeyState: typeof serializeSenderKeyState;
  deserializeSenderKeyState: typeof deserializeSenderKeyState;
};

export function toBase64(bytes: Uint8Array): string;
export function fromBase64(str: string): Uint8Array;
export function utf8Encode(str: string): Uint8Array;
export function utf8Decode(bytes: Uint8Array): string;

/** Implementation of the curve operations. All keys are raw 32-byte Uint8Arrays. */
export interface CryptoBackend {
  name?: string;
  generateX25519KeyPair(): KeyPair;
  dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  generateEd25519KeyPair(): KeyPair;
  sign(privateKey: Uint8Array, data: Uint8Array): Uint8Array;
  verify(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean;
}

/** Swap the curve implementation globally. Keys/sessions stay valid across backends. */
export function setCryptoBackend(backend: CryptoBackend): void;
export function getCryptoBackend(): CryptoBackend;
/** Pure-JS default backend. */
export const nobleBackend: CryptoBackend;
/** Backend over any Node-crypto-compatible module (Node's 'crypto', react-native-quick-crypto). */
export function createNodeCryptoBackend(cryptoModule: unknown): CryptoBackend;
/** Throws unless the backend is interchangeable with the pure-JS reference. Run before adopting an untested backend. */
export function checkCryptoBackend(backend: CryptoBackend): true;

// ─── Session manager (1:1 sessions per peer + group Sender Keys) ───

/** Async key-value store for session state. Values contain secrets: encrypt at rest. */
export interface SessionStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  del(key: string): Promise<void>;
}

export interface SessionManagerDeps {
  store: SessionStore;
  loadIdentity(): Promise<Identity | null>;
  /** The user's current bundle from the server, or null if they have none (can't encrypt to them). */
  fetchBundle(userId: string): Promise<PublicBundle | null>;
}

/** Sent with 1:1 messages until the peer replies, so they can build the session. */
export interface Handshake {
  ik: string;
  ek: string;
  otk: number | null;
}

export interface DirectEnvelope {
  e2e: 'dr1';
  hs?: Handshake;
  h: MessageHeader;
  c: string;
}

export interface GroupEnvelope {
  e2e: 'sk1';
  kid: string;
  i: number;
  c: string;
  s: string;
}

export type Envelope = DirectEnvelope | GroupEnvelope;

export class MissingSenderKeyError extends Error {
  conversationId: string;
  senderId: string;
  constructor(conversationId: string, senderId: string);
}

export class SessionManager {
  constructor(deps: SessionManagerDeps);
  /** Cached bundle; `refresh` re-fetches it (falls back to the cache if offline). */
  getBundle(userId: string, refresh?: boolean): Promise<PublicBundle | null>;
  /** Returns the envelope JSON string, or null if the peer has no bundle. */
  encryptDirect(peerId: string, plaintext: string): Promise<string | null>;
  /** Non-envelope input is returned unchanged. Throws if it can't decrypt. */
  decryptDirect(senderId: string, value: unknown): Promise<string>;
  hasDirectSession(peerId: string): Promise<boolean>;
  /** Next message to this peer starts a fresh handshake. */
  resetDirect(peerId: string): Promise<void>;
  /** Returns the envelope JSON string, or null if a member has no bundle. Distributes our sender key first where needed. */
  encryptGroup(
    conversationId: string,
    memberIds: string[],
    plaintext: string,
    distribute: (to: string, envelope: string) => void | Promise<void>,
  ): Promise<string | null>;
  /** Handles a sender-key distribution received over 1:1. Returns its conversation id. */
  acceptSenderKey(senderId: string, envelope: unknown): Promise<string>;
  /** Non-envelope input is returned unchanged. Throws MissingSenderKeyError if the sender's key hasn't arrived. */
  decryptGroup(conversationId: string, senderId: string, value: unknown): Promise<string>;
  hasGroupKey(conversationId: string): Promise<boolean>;
  /** Drop our sender key so the next send rotates it. */
  resetGroup(conversationId: string): Promise<void>;
}

export function parseEnvelope(value: unknown): Envelope | null;
export function isEnvelope(value: unknown): boolean;

/** Self-test (out-of-order, concurrent, crossed handshakes, replay, groups). null store = in-memory. */
export function runSelfTest(store: SessionStore | null, log?: (line: string) => void): Promise<{ passed: number; failed: number }>;

// ─── High-level client (recommended starting point) ───

export interface E2EEClientOptions {
  /** Small secret storage: Keychain / Keystore / expo-secure-store. Holds the identity and the storage key. */
  secureStore: SessionStore;
  /** Bulk storage (AsyncStorage, file, DB...). Everything written here is AES-256-GCM encrypted. */
  store: SessionStore;
  /** Send this device's public bundle (one string) to your server. */
  uploadBundle(bundle: string): Promise<unknown>;
  /** That user's bundle string from your server, or null if they have none. */
  fetchBundle(userId: string): Promise<string | object | null>;
  /** A queued group message was decrypted after its sender key arrived. */
  onPendingDecrypted?(meta: any, plaintext: string): void | Promise<void>;
  /** SecureStore key names (defaults: 'e2e_identity', 'e2e_master_key'). */
  identityKey?: string;
  masterKeyName?: string;
  /** Default 10. */
  oneTimePreKeyCount?: number;
}

export type GroupDecryptResult = { status: 'ok'; plaintext: string } | { status: 'pending' };

export class E2EEClient {
  constructor(options: E2EEClientOptions);
  /** Encrypted view of `store`. */
  readonly store: SessionStore;
  readonly sessions: SessionManager;
  /** Creates the identity on first run and uploads the public bundle. Safe to call repeatedly. */
  init(): Promise<void>;
  loadIdentity(): Promise<Identity | null>;

  encryptDirect(peerId: string, plaintext: string): Promise<string | null>;
  decryptDirect(senderId: string, value: unknown): Promise<string>;
  hasDirectSession(peerId: string): Promise<boolean>;
  resetDirect(peerId: string): Promise<void>;
  refreshBundle(userId: string): Promise<PublicBundle | null>;

  encryptGroup(
    conversationId: string,
    memberIds: string[],
    plaintext: string,
    distribute: (to: string, envelope: string) => void | Promise<void>,
  ): Promise<string | null>;
  decryptGroup(conversationId: string, senderId: string, value: unknown): Promise<string>;
  /** Queues messages whose sender key hasn't arrived; they come back via onPendingDecrypted. */
  decryptGroupOrQueue(conversationId: string, senderId: string, value: unknown, meta?: any): Promise<GroupDecryptResult>;
  /** Handles a sender-key packet and decrypts queued messages it unlocks. Returns the conversation id. */
  acceptSenderKey(senderId: string, envelope: unknown): Promise<string>;
  hasGroupKey(conversationId: string): Promise<boolean>;
  resetGroup(conversationId: string): Promise<void>;
}

/** Public bundle -> one string for your server. */
export function serializeBundle(bundle: PublicBundle): string;
/** Server value -> bundle, or null if missing / not an e2e-crypto bundle. */
export function parseBundle(value: unknown): PublicBundle | null;

// ─── Storage helpers ───

export function memoryStore(): SessionStore;
export function prefixStore(base: SessionStore, prefix: string): SessionStore;
export function createEncryptedStore(base: SessionStore, getKey: () => Promise<Uint8Array>): SessionStore;
/** 32-byte key kept in secureStore under `name`, created on first use. */
export function masterKeyFrom(secureStore: SessionStore, name?: string): () => Promise<Uint8Array>;
/** React Native: pass expo-secure-store and AsyncStorage; returns { secureStore, store }. */
export function reactNativeStores(modules: { SecureStore: any; AsyncStorage: any; prefix?: string }): {
  secureStore: SessionStore;
  store: SessionStore;
};
