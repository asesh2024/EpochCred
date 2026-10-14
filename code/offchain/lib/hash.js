'use strict';
// Domain-separated hash functions. MUST match src/CredLib.sol byte-for-byte.
const { keccak256 } = require('./keccak');

const ZERO = new Uint8Array(32);
const enc = new TextEncoder();

const toBytes = (x) => (typeof x === 'string' ? enc.encode(x) : x);
function hexToBytes(h) {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(2 * i, 2), 16);
  return out;
}
const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(b) {
  let s = '0x';
  for (let i = 0; i < b.length; i++) s += HEX[b[i]];
  return s;
}
function isZero(b) {
  for (let i = 0; i < 32; i++) if (b[i] !== 0) return false;
  return true;
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const buf65 = new Uint8Array(65);
function tagged2(tag, l, r) {
  buf65[0] = tag;
  buf65.set(l, 1);
  buf65.set(r, 33);
  return keccak256(buf65);
}

/** H(0x00 || salt || H(key) || H(value)) */
function attrLeaf(salt, key, value) {
  const b = new Uint8Array(97);
  b[0] = 0x00;
  b.set(salt, 1);
  b.set(keccak256(toBytes(key)), 33);
  b.set(keccak256(toBytes(value)), 65);
  return keccak256(b);
}
/** unsalted variant, used only by the dictionary-attack experiment (prior-work style) */
function attrLeafUnsalted(key, value) {
  return attrLeaf(ZERO, key, value);
}
const node = (l, r) => tagged2(0x01, l, r);

/** H(0x02 || attrRoot || holder(20) || nullifier || validUntil(uint64 BE) || schemaId) */
function credLeaf(attrRoot, holder, nullifier, validUntil, schemaId) {
  const b = new Uint8Array(1 + 32 + 20 + 32 + 8 + 32);
  b[0] = 0x02;
  b.set(attrRoot, 1);
  b.set(hexToBytes(holder), 33);
  b.set(nullifier, 53);
  let v = BigInt(validUntil);
  for (let i = 7; i >= 0; i--) { b[85 + i] = Number(v & 0xffn); v >>= 8n; }
  b.set(schemaId, 93);
  return keccak256(b);
}
/** nullifier = H(0x03 || credSecret); unlinkable to the credential without credSecret */
function nullifier(credSecret) {
  const b = new Uint8Array(33);
  b[0] = 0x03;
  b.set(credSecret, 1);
  return keccak256(b);
}
function smtLeaf(key) {
  const b = new Uint8Array(33);
  b[0] = 0x04;
  b.set(key, 1);
  return keccak256(b);
}
function smtNode(l, r) {
  if (isZero(l) && isZero(r)) return ZERO;
  return tagged2(0x05, l, r);
}

/** status-list word leaf: H(0x07 || word) (root-anchored bitstring status list baseline) */
function statusLeaf(word) {
  const b = new Uint8Array(33);
  b[0] = 0x07;
  b.set(word, 1);
  return keccak256(b);
}

module.exports = {
  statusLeaf,
  ZERO, keccak256, attrLeaf, attrLeafUnsalted, node, credLeaf, nullifier, smtLeaf, smtNode,
  hexToBytes, bytesToHex, isZero, eq, toBytes,
};
