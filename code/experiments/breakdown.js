'use strict';
// Where do the ~3 ms of off-chain verification go? Times each verification step separately (no chain needed).
const fs = require('fs');
const path = require('path');
const ethers = require('../offchain/vendor/ethers.umd.min.js');
const { randomWallet } = require('../offchain/lib/chain');
const C = require('../offchain/lib/credential');
const H = require('../offchain/lib/hash');
const { MerkleTree, rootFromProof, rootFromMultiproof } = require('../offchain/lib/merkle');
const { SparseMerkleTree, smtRootFromProof } = require('../offchain/lib/smt');
const { makeRecords } = require('../offchain/lib/data');

const B = 1024, R = 1024, ITER = Number(process.env.ITER || 300);
const holder = randomWallet();
const issuer = new C.Issuer({ issuerId: ethers.ZeroHash, officers: [randomWallet()], threshold: 1, chainId: 1, registry: ethers.ZeroAddress });
for (let i = 0; i < R; i++) issuer.revoke(C.rand32());
const b = issuer.buildEpoch(makeRecords(B, 3).map((attrs) => ({ attrs, holder: holder.address, validUntil: 4e9 })));
const w = b.wallets[17];
const challenge = 'nonce:123';
const p = C.present(w, holder, ['degree', 'major', 'graduationYear'], issuer.revoked, challenge);
const rec = { issuanceRoot: b.value.issuanceRoot, revocationRoot: b.value.revocationRoot, timestamp: 1, count: B, prevHead: ethers.ZeroHash };

const steps = {
  'record digests (2)': () => { C.recordDigest(rec); C.recordDigest(rec); },
  'attribute leaves + multiproof': () => rootFromMultiproof(new Map(p.disclosed.map((d) => [d.index, H.attrLeaf(d.salt, d.key, d.value)])), p.attrHeight, p.attrProof),
  'credential leaf + issuance path': () => rootFromProof(H.credLeaf(H.ZERO, p.holder, p.nullifier, p.validUntil, p.schemaId), p.leafIndex, p.issuancePath),
  'SMT non-membership (256 levels)': () => smtRootFromProof(p.nullifier, H.ZERO, p.nonRevocation),
  'holder signature recovery': () => ethers.recoverAddress(ethers.hashMessage(ethers.concat([new Uint8Array(32), H.toBytes(challenge)])), p.holderSig),
};
const out = [];
for (const [name, fn] of Object.entries(steps)) {
  for (let i = 0; i < 30; i++) fn(); // warm-up
  const xs = [];
  for (let i = 0; i < ITER; i++) { const t = process.hrtime.bigint(); fn(); xs.push(Number(process.hrtime.bigint() - t) / 1e6); }
  xs.sort((a, c) => a - c);
  out.push({ step: name, median_ms: xs[Math.floor(xs.length / 2)] });
  console.log(name.padEnd(36), xs[Math.floor(xs.length / 2)].toFixed(4), 'ms');
}
// ---- issuer throughput: median of 3 builds per epoch size (k = 3 signers)
const officers = Array.from({ length: 5 }, () => randomWallet());
const throughput = [];
const QB = process.env.QUICK === '1' ? [1, 16, 256, 1024] : [1, 4, 16, 64, 256, 1024, 4096, 16384];
for (const Bq of QB) {
  const reqs = makeRecords(Bq, 11).map((attrs) => ({ attrs, holder: holder.address, validUntil: 4e9 }));
  const xs = [];
  for (let rep = 0; rep < 3; rep++) {
    const iss = new C.Issuer({ issuerId: ethers.ZeroHash, officers, threshold: 3, chainId: 1, registry: ethers.ZeroAddress });
    const t = process.hrtime.bigint(); iss.buildEpoch(reqs); xs.push(Number(process.hrtime.bigint() - t) / 1e6);
  }
  xs.sort((a, c) => a - c);
  throughput.push({ B: Bq, build_ms: xs[1], creds_per_s: Bq / (xs[1] / 1000) });
  console.log('build B', Bq, xs[1].toFixed(1), 'ms');
}
// ---- endorsement signing time: k EIP-712 signatures, median of 60
const signing = [];
const dom = C.eip712Domain(1, ethers.ZeroAddress);
const val = { issuerId: ethers.ZeroHash, epoch: 1, issuanceRoot: ethers.ZeroHash, revocationRoot: ethers.ZeroHash, count: 1, prevHead: ethers.ZeroHash };
const ten = Array.from({ length: 10 }, () => randomWallet());
for (let k = 1; k <= 10; k++) {
  for (let i = 0; i < 10; i++) C.signThreshold(ten.slice(0, k), dom, C.EPOCH_TYPES, val);
  const xs = [];
  for (let i = 0; i < 60; i++) { const t = process.hrtime.bigint(); C.signThreshold(ten.slice(0, k), dom, C.EPOCH_TYPES, val); xs.push(Number(process.hrtime.bigint() - t) / 1e6); }
  xs.sort((a, c) => a - c);
  signing.push({ k, median_ms: xs[30], p05: xs[3], p95: xs[56] });
}
console.log('signing', signing.map((s) => s.median_ms.toFixed(2)).join(' '));
fs.writeFileSync(path.join(__dirname, '..', 'results', 'breakdown.json'), JSON.stringify(out, null, 2));
fs.writeFileSync(path.join(__dirname, '..', 'results', 'offchain_costs.json'), JSON.stringify({ throughput, signing }, null, 2));
