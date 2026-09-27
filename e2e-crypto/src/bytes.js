'use strict';
// Byte helpers that work without Node's Buffer (React Native / Hermes has no Buffer,
// and older Hermes versions lack TextDecoder / atob / btoa).

function randomBytes(length) {
  const c = typeof globalThis === 'object' ? globalThis.crypto : undefined;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error(
      'e2e-crypto: crypto.getRandomValues is not available. In React Native, install ' +
      "'react-native-get-random-values' and import it once at the very top of your entry file."
    );
  }
  return c.getRandomValues(new Uint8Array(length));
}

function concat(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

// Constant-time comparison (length is not secret)
function equal(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = new Uint8Array(128).fill(255);
for (let i = 0; i < B64.length; i++) B64_LOOKUP[B64.charCodeAt(i)] = i;

function toBase64(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += B64[n >> 18] + B64[(n >> 12) & 63] + '==';
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + '=';
  }
  return out;
}

function fromBase64(str) {
  if (typeof str !== 'string') throw new TypeError('e2e-crypto: expected a base64 string');
  const clean = str.replace(/=+$/, '');
  if (clean.length % 4 === 1) throw new Error('e2e-crypto: invalid base64');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let buffer = 0, bits = 0, o = 0;
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    const v = code < 128 ? B64_LOOKUP[code] : 255;
    if (v === 255) throw new Error('e2e-crypto: invalid base64');
    buffer = ((buffer << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) { bits -= 8; out[o++] = (buffer >> bits) & 0xff; }
  }
  return out;
}

function utf8Encode(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let cp = str.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < str.length) {
      const lo = str.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) { cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00); i++; }
    }
    if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd; // lone surrogate
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
  }
  return new Uint8Array(out);
}

function utf8Decode(bytes) {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i];
    let cp, extra;
    if (b < 0x80) { cp = b; extra = 0; }
    else if (b >= 0xc2 && b < 0xe0) { cp = b & 0x1f; extra = 1; }
    else if (b >= 0xe0 && b < 0xf0) { cp = b & 0x0f; extra = 2; }
    else if (b >= 0xf0 && b < 0xf5) { cp = b & 0x07; extra = 3; }
    else { out += '�'; i++; continue; }

    let ok = i + extra < bytes.length;
    for (let k = 1; ok && k <= extra; k++) {
      const c = bytes[i + k];
      if ((c & 0xc0) !== 0x80) ok = false;
      else cp = (cp << 6) | (c & 0x3f);
    }
    if (!ok) { out += '�'; i++; continue; }
    i += extra + 1;

    if (cp > 0xffff) {
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    } else {
      out += String.fromCharCode(cp);
    }
  }
  return out;
}

// Accepts a string (UTF-8 encoded) or any Uint8Array (including Node Buffers)
function toBytes(input) {
  if (typeof input === 'string') return utf8Encode(input);
  if (input instanceof Uint8Array) return input;
  throw new TypeError('e2e-crypto: expected a string or Uint8Array');
}

// Accepts raw bytes or a base64 string
function bytesOrBase64(input) {
  return typeof input === 'string' ? fromBase64(input) : toBytes(input);
}

module.exports = { randomBytes, concat, equal, toBase64, fromBase64, utf8Encode, utf8Decode, toBytes, bytesOrBase64 };
