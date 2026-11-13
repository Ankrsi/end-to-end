'use strict';
// Chat photos, videos, voice notes and files are locked on the phone before upload (like WhatsApp):
//   1. every file gets its own new random key
//   2. the file is locked with that key, and only the locked copy is uploaded
//   3. the key goes inside the chat message, which is end-to-end encrypted
// So the server stores files it can't open, and never sees the keys.
//
// Locked file = nonce (24 bytes) + XChaCha20-Poly1305 ciphertext.
// Same strength as AES-256, and faster on phones when done in JavaScript.
const { xchacha20poly1305 } = require('@noble/ciphers/chacha');
const { randomBytes, concat, bytesOrBase64 } = require('./bytes');

const NONCE_LENGTH = 24;

// file bytes -> { key, data }. Upload `data`; send `key` (e.g. toBase64(key)) in the chat message.
function encryptFile(fileBytes) {
  const key = randomBytes(32);
  const nonce = randomBytes(NONCE_LENGTH);
  const data = concat(nonce, xchacha20poly1305(key, nonce).encrypt(fileBytes));
  return { key, data };
}

// Downloads the locked file from `url`, unlocks it, and returns { data, type }.
// `key` is the key from the chat message (bytes or base64). `type` is the url's extension
// (mp4, pdf, jpeg, png, ...), or '' if it has none. Throws if the key is wrong or the file was changed.
async function decryptFile(key, url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`e2e-crypto: file download failed (${res.status})`);
  const locked = new Uint8Array(await res.arrayBuffer());
  const nonce = locked.subarray(0, NONCE_LENGTH);
  const data = xchacha20poly1305(bytesOrBase64(key), nonce).decrypt(locked.subarray(NONCE_LENGTH));
  return { data, type: fileType(url) };
}

// "https://cdn/x/photo.JPEG?token=1#a" -> "jpeg"
function fileType(url) {
  const name = String(url).split(/[?#]/)[0].split('/').pop();
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
}

module.exports = { encryptFile, decryptFile };
