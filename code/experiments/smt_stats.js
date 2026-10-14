'use strict';
// Validates Proposition 1: expected number of non-zero siblings in a non-membership proof.
// The expectation is over BOTH the random tree and the absent query key, so trees are re-sampled.
const fs = require('fs');
const path = require('path');
const C = require('../offchain/lib/credential');
const { SparseMerkleTree } = require('../offchain/lib/smt');
const H = require('../offchain/lib/hash');
/** number of hash evaluations a verifier performs for a NON-membership proof (levels below the first
 *  non-zero sibling hash (0,0) -> 0 and are skipped, exactly as in CredLib.smtRoot) */
function hashCount(key, { bitmap, siblings }) {
  const k = BigInt(H.bytesToHex(key));
  let v = H.ZERO, j = 0, n = 0;
  for (let h = 0; h < 256; h++) {
    let sib = H.ZERO;
    if ((bitmap >> BigInt(h)) & 1n) sib = siblings[j++];
    if (H.isZero(v) && H.isZero(sib)) continue;
    n++;
    v = (k >> BigInt(h)) & 1n ? H.smtNode(sib, v) : H.smtNode(v, sib);
  }
  return n;
}

const RS = (process.env.QUICK === '1') ? [1, 4, 16, 64, 256] : [1, 2, 4, 8, 16, 64, 256, 1024, 4096, 16384];
const QUERIES = 400;
const out = [];
for (const r of RS) {
  const trees = Math.max(1, Math.min(QUERIES, Math.floor(40000 / r)));
  const perTree = Math.ceil(QUERIES / trees);
  const xs = [], hs = [];
  for (let t = 0; t < trees; t++) {
    const tree = new SparseMerkleTree(Array.from({ length: r }, () => C.rand32()));
    for (let q = 0; q < perTree; q++) { const key = C.rand32(); const p = tree.proof(key); xs.push(p.siblings.length); hs.push(hashCount(key, p)); }
  }
  const hMean = hs.reduce((a, b) => a + b, 0) / hs.length;
  const hSd = Math.sqrt(hs.reduce((a, b) => a + (b - hMean) ** 2, 0) / Math.max(1, hs.length - 1));
  const n = xs.length, mean = xs.reduce((a, b) => a + b, 0) / n;
  const sd = Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / Math.max(1, n - 1));
  let expct = 0;
  for (let j = 1; j <= 256; j++) expct += 1 - Math.pow(1 - Math.pow(2, -j), r);
  const ci95 = (1.96 * sd) / Math.sqrt(n);
  out.push({ r, trees, samples: n, mean, sd, ci95, expected: expct, log2r: Math.log2(r), withinCI: Math.abs(mean - expct) <= Math.max(ci95, 1e-9),
    hashes_mean: hMean, hashes_ci95: (1.96 * hSd) / Math.sqrt(hs.length), hashes_expected: expct + 1, hashes_max: Math.max(...hs), hashesWithinCI: Math.abs(hMean - expct - 1) <= Math.max((1.96 * hSd) / Math.sqrt(hs.length), 1e-9) });
  console.log(`r=${r} trees=${trees} n=${n} siblings=${mean.toFixed(3)}±${ci95.toFixed(3)} (exp ${expct.toFixed(3)}) hashes=${hMean.toFixed(3)} (exp ${(expct + 1).toFixed(3)}) max=${Math.max(...hs)}`);
}
fs.writeFileSync(path.join(__dirname, '..', 'results', 'smt_stats.json'), JSON.stringify(out, null, 2));
