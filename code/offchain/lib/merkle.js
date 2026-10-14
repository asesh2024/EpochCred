'use strict';
// Positional binary Merkle tree with domain-separated internal nodes, padded with zero leaves to 2^h.
// Supports single proofs (on-chain compatible with CredLib.merkleRoot) and compact multiproofs.
const { node, ZERO, eq } = require('./hash');

class MerkleTree {
  constructor(leaves) {
    if (leaves.length === 0) throw new Error('empty tree');
    let h = 0;
    while (1 << h < leaves.length) h++;
    this.height = h;
    const level0 = leaves.slice();
    while (level0.length < 1 << h) level0.push(ZERO);
    this.layers = [level0];
    for (let d = 0; d < h; d++) {
      const prev = this.layers[d];
      const next = new Array(prev.length >> 1);
      for (let i = 0; i < next.length; i++) next[i] = node(prev[2 * i], prev[2 * i + 1]);
      this.layers.push(next);
    }
  }
  get root() {
    return this.layers[this.height][0];
  }
  proof(index) {
    const path = [];
    for (let d = 0; d < this.height; d++) path.push(this.layers[d][(index >> d) ^ 1]);
    return path;
  }
  /** compact multiproof: siblings not derivable from the disclosed leaves, level-major, index-ascending */
  multiproof(indices) {
    let known = [...new Set(indices)].sort((a, b) => a - b);
    const proof = [];
    for (let d = 0; d < this.height; d++) {
      const set = new Set(known);
      for (const i of known) {
        const sib = i ^ 1;
        if (!set.has(sib)) proof.push(this.layers[d][sib]);
      }
      known = [...new Set(known.map((i) => i >> 1))];
    }
    return proof;
  }
}

function rootFromProof(leaf, index, path) {
  let h = leaf;
  for (let d = 0; d < path.length; d++) h = (index >> d) & 1 ? node(path[d], h) : node(h, path[d]);
  if (index >> path.length !== 0) throw new Error('index out of range');
  return h;
}

/** leaves: Map(index -> hash). Returns the root implied by the multiproof. */
function rootFromMultiproof(leaves, height, proof) {
  let known = new Map([...leaves.entries()].sort((a, b) => a[0] - b[0]));
  let p = 0;
  for (let d = 0; d < height; d++) {
    const next = new Map();
    for (const [i, h] of known) {
      if (next.has(i >> 1)) continue;
      const sib = i ^ 1;
      let sh;
      if (known.has(sib)) sh = known.get(sib);
      else {
        if (p >= proof.length) throw new Error('multiproof too short');
        sh = proof[p++];
      }
      next.set(i >> 1, i & 1 ? node(sh, h) : node(h, sh));
    }
    known = next;
  }
  if (p !== proof.length) throw new Error('multiproof too long');
  if (known.size !== 1 || !known.has(0)) throw new Error('bad multiproof indices');
  return known.get(0);
}

module.exports = { MerkleTree, rootFromProof, rootFromMultiproof, eq };
