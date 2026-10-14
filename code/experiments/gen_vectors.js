'use strict';
// Generates cross-implementation test vectors consumed by test/CrossImpl.t.sol (JS <-> Solidity agreement).
const fs = require('fs');
const path = require('path');
const H = require('../offchain/lib/hash');
const { MerkleTree } = require('../offchain/lib/merkle');
const { SparseMerkleTree } = require('../offchain/lib/smt');
const C = require('../offchain/lib/credential');
const { makeRecords } = require('../offchain/lib/data');

const hex = H.bytesToHex;
const rec = makeRecords(1, 99)[0];
const seed = new Uint8Array(32).fill(7);
const at = C.attrTree(rec, seed);
const j = C.SCHEMA_KEYS.indexOf('degree');
const salt = C.deriveSalt(seed, j);
const nul = H.nullifier(new Uint8Array(32).fill(9));
const holder = '0x1111111111111111111111111111111111111111';
const leaf = H.credLeaf(at.root, holder, nul, 2000000000, C.SCHEMA_ID);
const leaves = [leaf];
for (let i = 1; i < 37; i++) leaves.push(H.keccak256(new Uint8Array([i])));
const t = new MerkleTree(leaves);
const keys = Array.from({ length: 50 }, (_, i) => H.keccak256(new Uint8Array([200, i])));
const smt = new SparseMerkleTree(keys);
const nonMem = smt.proof(nul);
const mem = smt.proof(keys[17]);

const v = {
  degreeValue: rec.degree, salt: hex(salt), attrIndex: j, attrPath: at.proof(j).map(hex), attrLeaf: hex(H.attrLeaf(salt, 'degree', rec.degree)), attrRoot: hex(at.root),
  holder, nullifier: hex(nul), validUntil: 2000000000, schemaId: hex(C.SCHEMA_ID), credLeaf: hex(leaf),
  leafIndex: 0, issuancePath: t.proof(0).map(hex), issuanceRoot: hex(t.root),
  smtRoot: hex(smt.root), nonMemBitmap: '0x' + nonMem.bitmap.toString(16).padStart(64, '0'), nonMemSiblings: nonMem.siblings.map(hex),
  memKey: hex(keys[17]), memBitmap: '0x' + mem.bitmap.toString(16).padStart(64, '0'), memSiblings: mem.siblings.map(hex),
};
fs.mkdirSync(path.join(__dirname, '..', 'results'), { recursive: true });
fs.writeFileSync(path.join(__dirname, '..', 'results', 'vectors.json'), JSON.stringify(v, null, 2));
console.log('wrote results/vectors.json');
