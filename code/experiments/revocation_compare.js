'use strict';
// E3b: revocation-proof comparison under the SAME root-anchored architecture (reviewer request):
//   nullifier SMT (EpochCred)  vs  root-anchored bitstring status list (W3C minimum size 131,072).
// Measures proof bytes, off-chain check time, hash evaluations, on-chain check gas, and the gas of the
// revocation-removal fraud proof. Requires a running anvil node.
const fs = require('fs');
const path = require('path');
const { ethers, provider, devWallet, deploy } = require('../offchain/lib/chain');
const H = require('../offchain/lib/hash');
const C = require('../offchain/lib/credential');
const { SparseMerkleTree, smtRootFromProof } = require('../offchain/lib/smt');
const { StatusList, statusNotRevoked } = require('../offchain/lib/statuslist');
const { mulberry32 } = require('../offchain/lib/data');
const { setupRegistry, commitEpoch } = require('../offchain/lib/setup');

const QUICK = process.env.QUICK === '1';
const RS = QUICK ? [1, 64, 1024] : [1, 16, 256, 1024, 4096, 16384];
const CAP = 131072;
const SAMPLES = QUICK ? 50 : 200;
const GAS_SAMPLES = 10;
const rnd = mulberry32(77);
const hex = H.bytesToHex;
const el = (t) => Number(process.hrtime.bigint() - t) / 1e6;
const med = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

function smtHashCount(key, leaf, { bitmap, siblings }) {
  const k = BigInt(hex(key));
  let v = leaf, j = 0, n = 0;
  for (let h = 0; h < 256; h++) {
    let sib = H.ZERO;
    if ((bitmap >> BigInt(h)) & 1n) sib = siblings[j++];
    if (H.isZero(v) && H.isZero(sib)) continue;
    n++;
    v = (k >> BigInt(h)) & 1n ? H.smtNode(sib, v) : H.smtNode(v, sib);
  }
  return n;
}

(async () => {
  const prov = provider();
  const owner = devWallet(0, prov);
  const { contract: hz } = await deploy(owner, 'Baselines.sol', 'RevocationCheckHarness');
  const out = { capacity: CAP, rows: [], fraud: [] };
  for (const r of RS) {
    const keys = Array.from({ length: r }, () => C.rand32());
    const smt = new SparseMerkleTree(keys);
    const sl = new StatusList(CAP);
    const revokedIdx = new Set();
    while (revokedIdx.size < r) revokedIdx.add(Math.floor(rnd() * CAP));
    sl.revoke([...revokedIdx]);
    const row = { r };
    const smtSize = [], smtT = [], smtHash = [], slT = [];
    let smtGas = 0, slGas = 0, smtNaiveGas = 0;
    for (let s = 0; s < SAMPLES; s++) {
      const q = C.rand32();
      const p = smt.proof(q);
      smtSize.push(32 + 32 * p.siblings.length);
      smtHash.push(smtHashCount(q, H.ZERO, p));
      let t = process.hrtime.bigint();
      smtRootFromProof(q, H.ZERO, p);
      smtT.push(el(t));
      let i;
      do { i = Math.floor(rnd() * CAP); } while (revokedIdx.has(i));
      const sp = sl.proof(i);
      t = process.hrtime.bigint();
      if (!statusNotRevoked(i, sp, sl.root)) throw new Error('status check failed');
      slT.push(el(t));
      if (s < GAS_SAMPLES) { // on-chain gas: mean over the first GAS_SAMPLES random absent keys / indices
        smtGas += (Number(await hz.smtNotRevoked.estimateGas(hex(q), p.bitmap, p.siblings.map(hex), hex(smt.root))) - 21000) / GAS_SAMPLES;
        smtNaiveGas += (Number(await hz.smtNotRevokedNaive.estimateGas(hex(q), p.bitmap, p.siblings.map(hex), hex(smt.root))) - 21000) / GAS_SAMPLES;
        slGas += (Number(await hz.statusNotRevoked.estimateGas(i, hex(sp.word), sp.path.map(hex), hex(sl.root))) - 21000) / GAS_SAMPLES;
        if (!(await hz.smtNotRevoked(hex(q), p.bitmap, p.siblings.map(hex), hex(smt.root)))) throw new Error('on-chain smt');
        if (!(await hz.statusNotRevoked(i, hex(sp.word), sp.path.map(hex), hex(sl.root)))) throw new Error('on-chain status');
      }
    }
    // membership (used by the issuer's fraud-proof target and by insertions): always 256 hashes
    const mp = smt.proof(keys[0]);
    row.smt = { proof_bytes: med(smtSize), proof_bytes_mean: smtSize.reduce((a, b) => a + b, 0) / SAMPLES, mean_siblings: smtSize.reduce((a, b) => a + b, 0) / SAMPLES / 32 - 1, check_ms: med(smtT),
      mean_hashes_nonmember: smtHash.reduce((a, b) => a + b, 0) / SAMPLES, hashes_member: smtHashCount(keys[0], H.smtLeaf(keys[0]), mp), onchain_check_gas: Math.round(smtGas), onchain_check_gas_naive: Math.round(smtNaiveGas), gas_samples: GAS_SAMPLES };
    row.statusList = { proof_bytes: 32 + 32 * Math.log2(CAP / 256), check_ms: med(slT), hashes: 1 + Math.log2(CAP / 256), onchain_check_gas: Math.round(slGas) };
    let e = 0; for (let j = 1; j <= 256; j++) e += 1 - Math.pow(1 - 2 ** -j, r);
    row.predicted_siblings = e; row.predicted_hashes = e + 1;
    out.rows.push(row);
    console.log('r', r, JSON.stringify(row));
  }

  // ---- fraud proof: issuer quorum drops a revoked nullifier; anyone proves it and freezes the issuer
  for (const r of QUICK ? [16] : [16, 1024]) {
    const fx = await setupRegistry({ n: 5, k: 3, prov });
    for (let i = 0; i < r; i++) fx.issuer.revoke(C.rand32());
    const victim = C.rand32();
    fx.issuer.revoke(victim);
    const e1 = await commitEpoch(fx, []);
    const oldTree = fx.issuer.revoked;
    const memberProof = oldTree.proof(victim);
    // malicious epoch 2: same set minus the victim
    const keep = [...oldTree.keySet.keys()].filter((k) => k !== hex(victim)).map(H.hexToBytes);
    fx.issuer.revoked = new SparseMerkleTree(keep);
    const e2 = await commitEpoch(fx, []);
    const absentProof = fx.issuer.revoked.proof(victim);
    const enc = (p) => ({ bitmap: p.bitmap, siblings: p.siblings.map(hex) });
    // L_proof: an auditor rebuilds both published sets and produces the two proofs
    const oldKeys = [...oldTree.keySet.keys()].map(H.hexToBytes);
    const tP = process.hrtime.bigint();
    const tOld = new SparseMerkleTree(oldKeys);
    const tNew = new SparseMerkleTree(keep);
    tOld.proof(victim); tNew.proof(victim);
    const proofGenMs = Number(process.hrtime.bigint() - tP) / 1e6;
    const tx = await fx.regRelayer.challengeRevocationRemoval(fx.issuer.issuerId, 1, e1.rec, 2, e2.rec, hex(victim), enc(memberProof), enc(absentProof));
    const rc = await tx.wait();
    const iss = await fx.reg.issuers(fx.issuer.issuerId);
    out.fraud.push({ r: r + 1, gas: Number(rc.gasUsed), frozen: iss.frozen, proof_gen_ms: proofGenMs, calldata_bytes: ethers.getBytes(tx.data).length });
    console.log('fraud proof r', r + 1, 'gas', Number(rc.gasUsed), 'frozen', iss.frozen);
  }
  fs.writeFileSync(path.join(__dirname, '..', 'results', 'revocation_compare.json'), JSON.stringify(out, null, 2));
  console.log('wrote results/revocation_compare.json');
})().catch((e) => { console.error(e); process.exit(1); });
