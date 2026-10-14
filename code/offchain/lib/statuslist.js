'use strict';
// Root-anchored bitstring status list (baseline B4-SL): N-bit list (W3C minimum 131,072 entries), split into
// 256-bit words; a positional Merkle tree over H(0x07 || word) is anchored on chain instead of the bitmap.
// Revocation = set bit + re-anchor the root. Non-revocation proof = the word + its Merkle path.
const H = require('./hash');
const { MerkleTree, rootFromProof } = require('./merkle');

class StatusList {
  constructor(capacity = 131072) {
    if (capacity % 256) throw new Error('capacity must be a multiple of 256');
    this.capacity = capacity;
    this.words = Array.from({ length: capacity / 256 }, () => new Uint8Array(32));
    this._rebuild();
  }
  revoke(indices) {
    for (const i of indices) {
      const w = this.words[i >> 8];
      const bit = i & 255; // bit b of the uint256 word (big-endian bytes)
      w[31 - (bit >> 3)] |= 1 << (bit & 7);
    }
    this._rebuild();
  }
  _rebuild() {
    this.tree = new MerkleTree(this.words.map(H.statusLeaf));
  }
  get root() {
    return this.tree.root;
  }
  proof(index) {
    return { word: this.words[index >> 8], path: this.tree.proof(index >> 8) };
  }
}

function statusNotRevoked(index, { word, path }, root) {
  const r = rootFromProof(H.statusLeaf(word), index >> 8, path);
  if (!H.eq(r, root)) return false;
  const bit = index & 255;
  return ((word[31 - (bit >> 3)] >> (bit & 7)) & 1) === 0;
}

module.exports = { StatusList, statusNotRevoked };
