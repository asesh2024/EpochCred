'use strict';
// Sparse Merkle tree of depth 256 keyed by nullifiers (revocation registry).
//  * empty subtree hashes to 0 (so no table of default hashes is needed, on- or off-chain)
//  * O(r) memory: only branching nodes are cached; single-key subtrees are recomputed on demand
//  * compressed proofs: a 256-bit bitmap marks non-zero siblings; only those are transmitted.
const { smtLeaf, smtNode, ZERO, bytesToHex, hexToBytes, isZero } = require('./hash');

const DEPTH = 256;
const toBig = (b) => BigInt(bytesToHex(b));

class SparseMerkleTree {
  constructor(keys = []) {
    this.keySet = new Map(); // hex -> bigint
    for (const k of keys) this.keySet.set(bytesToHex(k), toBig(k));
    this._rebuild();
  }
  get size() {
    return this.keySet.size;
  }
  has(key) {
    return this.keySet.has(bytesToHex(key));
  }
  insertMany(keys) {
    for (const k of keys) this.keySet.set(bytesToHex(k), toBig(k));
    this._rebuild();
  }
  _rebuild() {
    this.sorted = [...this.keySet.values()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    this.cache = new Map(); // `${h}:${prefix}` -> hash, only for subtrees holding >= 2 keys
    this.root = this.sorted.length ? this._build(0, this.sorted.length, DEPTH, 0n) : ZERO;
  }
  _lowerBound(x, lo, hi) {
    while (lo < hi) {
      const m = (lo + hi) >> 1;
      if (this.sorted[m] < x) lo = m + 1;
      else hi = m;
    }
    return lo;
  }
  /** hash of a subtree of height h containing exactly one key */
  _single(key, h) {
    let v = smtLeaf(hexToBytes(key.toString(16).padStart(64, '0')));
    for (let i = 0; i < h; i++) v = (key >> BigInt(i)) & 1n ? smtNode(ZERO, v) : smtNode(v, ZERO);
    return v;
  }
  _build(lo, hi, h, prefix) {
    if (hi - lo === 0) return ZERO;
    if (hi - lo === 1) return this._single(this.sorted[lo], h);
    const mid = this._lowerBound(((prefix << 1n) | 1n) << BigInt(h - 1), lo, hi);
    const l = this._build(lo, mid, h - 1, prefix << 1n);
    const r = this._build(mid, hi, h - 1, (prefix << 1n) | 1n);
    const v = smtNode(l, r);
    this.cache.set(`${h}:${prefix}`, v);
    return v;
  }
  _nodeAt(h, prefix) {
    const c = this.cache.get(`${h}:${prefix}`);
    if (c) return c;
    const lo = this._lowerBound(prefix << BigInt(h), 0, this.sorted.length);
    const hi = this._lowerBound((prefix + 1n) << BigInt(h), lo, this.sorted.length);
    if (hi - lo === 0) return ZERO;
    if (hi - lo === 1) return this._single(this.sorted[lo], h);
    throw new Error('cache miss for branching node');
  }
  /** compressed (non-)membership proof for `key` */
  proof(key) {
    const k = toBig(key);
    let bitmap = 0n;
    const siblings = [];
    for (let h = 0; h < DEPTH; h++) {
      const sib = this._nodeAt(h, (k >> BigInt(h)) ^ 1n);
      if (!isZero(sib)) {
        bitmap |= 1n << BigInt(h);
        siblings.push(sib);
      }
    }
    return { bitmap, siblings };
  }
}

/** recompute a root from a leaf value (ZERO for non-membership, smtLeaf(key) for membership) */
function smtRootFromProof(key, leafValue, { bitmap, siblings }) {
  const k = toBig(key);
  let v = leafValue;
  let j = 0;
  for (let h = 0; h < DEPTH; h++) {
    let sib = ZERO;
    if ((bitmap >> BigInt(h)) & 1n) sib = siblings[j++];
    if (isZero(v) && isZero(sib)) continue;
    v = (k >> BigInt(h)) & 1n ? smtNode(sib, v) : smtNode(v, sib);
  }
  if (j !== siblings.length) throw new Error('unused siblings');
  return v;
}

module.exports = { SparseMerkleTree, smtRootFromProof, DEPTH };
