'use strict';
// E1-E3: measured gas (transaction receipts on an anvil node) for issuance, threshold size and revocation,
// for EpochCred and three baselines implemented in the same testbed.
const fs = require('fs');
const path = require('path');
const { ethers, provider, devWallet, deploy, send: send0, randomWallet } = require('../offchain/lib/chain');
const RECEIPTS = [];
let CTX = '';
async function send(p) { // every transaction's receipt is logged for the artifact
  const r = await send0(p);
  RECEIPTS.push({ ctx: CTX, txHash: r.receipt.hash, block: r.receipt.blockNumber, gasUsed: r.gas, calldataBytes: r.calldataBytes });
  return r;
}
const H = require('../offchain/lib/hash');
const { MerkleTree } = require('../offchain/lib/merkle');
const { makeRecords } = require('../offchain/lib/data');
const { setupRegistry, commitEpoch } = require('../offchain/lib/setup');

const OUT = path.join(__dirname, '..', 'results');
const QUICK = process.env.QUICK === '1';
const BATCHES = QUICK ? [1, 4, 16, 64, 256] : [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
const REVS = QUICK ? [1, 16, 64] : [1, 4, 16, 64, 256, 1024];
const hashRec = (r) => H.keccak256(H.toBytes(JSON.stringify(r)));
const ms = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;

(async () => {
  const prov = provider();
  const owner = devWallet(0, prov);
  const now = (await prov.getBlock('latest')).timestamp;
  const allRecs = makeRecords(Math.max(...BATCHES), 1);
  const holder = randomWallet().address;
  const reqs = allRecs.map((attrs) => ({ attrs, holder, validUntil: now + 3e8 }));
  const res = { meta: { node: 'anvil', note: 'gasUsed from transaction receipts (includes 21000 intrinsic + calldata)', batches: BATCHES }, deploy: {}, issuance: [], threshold: [], revocation: [] };

  // ----------------------------------------------------------------- deployment
  const d1 = await deploy(owner, 'Baselines.sol', 'PerCredentialRegistry');
  const d2 = await deploy(owner, 'Baselines.sol', 'BatchMerkleRegistry');
  const d3 = await deploy(owner, 'Baselines.sol', 'StatusListRegistry');
  const d4 = await deploy(owner, 'Baselines.sol', 'SingleSignerRootRegistry');
  const fxProbe = await setupRegistry({ n: 5, k: 3, prov });
  const fxProbeFull = await setupRegistry({ n: 5, k: 3, prov, storeFull: true });
  res.deploy = { PerCredential: d1.gas, BatchMerkle: d2.gas, StatusList: d3.gas, SingleSignerRoot: d4.gas, EpochCred: fxProbe.deployGas, EpochCredFull: fxProbeFull.deployGas, registerIssuer_n5: fxProbe.regGas };
  console.log('deploy', res.deploy);

  // ----------------------------------------------------------------- E1 issuance vs batch size
  const single = await send(d1.contract.issue(ethers.id('single-probe')));
  for (const B of BATCHES) {
    CTX = `E1 B=${B}`;
    const docs = allRecs.slice(0, B).map((r, i) => H.bytesToHex(hashRec({ ...r, nonce: B * 100000 + i })));
    const row = { B };
    row.perCred_singleTx = single.gas; // one tx per credential
    row.perCred_batchTx = (await send(d1.contract.issueBatch(docs))).gas / B;
    const root = H.bytesToHex(new MerkleTree(docs.map(H.hexToBytes)).root);
    row.batchMerkle = (await send(d2.contract.anchor(root))).gas / B;
    row.statusList = (await send(d3.contract.anchor(root))).gas / B;
    // B4: a fresh deployment per row, so its FIRST (cold-storage) and STEADY-STATE commits are both measured
    CTX = `E1 B=${B} B4`;
    const d4r = await deploy(owner, 'Baselines.sol', 'SingleSignerRootRegistry');
    row.singleSignerRoot_first_txGas = (await send(d4r.contract.commit(root, ethers.id('statusRoot' + B), B))).gas;
    row.singleSignerRoot_txGas = (await send(d4r.contract.commit(root, ethers.id('statusRoot2' + B), B))).gas;
    row.singleSignerRoot = row.singleSignerRoot_txGas / B;
    for (const [k, full] of [[1, false], [3, false], [5, false], [3, true]]) {
      CTX = `E1 B=${B} EpochCred k=${k}${full ? ' full' : ''}`;
      const fx = await setupRegistry({ n: 5, k, prov, storeFull: full });
      const tag = `epochCred_k${k}${full ? '_full' : ''}`;
      // first epoch of the issuer (digest/head slots go zero -> non-zero) ...
      const b1 = fx.issuer.buildEpoch(reqs.slice(0, B));
      const s1 = await send(fx.regRelayer.commitEpoch(b1.value.issuerId, b1.value.epoch, b1.value.issuanceRoot, b1.value.revocationRoot, b1.value.count, b1.sigs));
      fx.issuer.confirm(b1.value, (await prov.getBlock(s1.receipt.blockNumber)).timestamp);
      // ... then a subsequent issuance epoch of the same size (steady state); per-credential figures use this one
      const t0 = process.hrtime.bigint();
      const b = fx.issuer.buildEpoch(reqs.slice(0, B));
      const buildMs = ms(t0);
      const v = b.value;
      const s = await send(fx.regRelayer.commitEpoch(v.issuerId, v.epoch, v.issuanceRoot, v.revocationRoot, v.count, b.sigs));
      row[`${tag}_first_txGas`] = s1.gas;
      row[`${tag}_txGas`] = s.gas;
      row[tag] = s.gas / B;
      if (k === 3 && !full) { row.build_ms_k3 = buildMs; row.commit_calldata_bytes_k3 = s.calldataBytes; }
    }
    res.issuance.push(row);
    console.log('E1', JSON.stringify(row));
  }

  // ----------------------------------------------------------------- E2 threshold k (n = 10)
  for (let k = 1; k <= 10; k++) {
    CTX = `E2 k=${k}`;
    const fx = await setupRegistry({ n: 10, k, prov });
    const gas = [];
    for (let e = 0; e < 3; e++) gas.push((await commitEpoch(fx, reqs.slice(0, 8))).gas);
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < 20; i++) fx.issuer.buildEpoch([]); // signing cost only (no credentials)
    const signMs = ms(t0) / 20;
    res.threshold.push({ k, n: 10, gas_first: gas[0], gas_steady: gas[2], sign_ms: signMs });
    console.log('E2', k, gas, signMs.toFixed(2));
  }

  // ----------------------------------------------------------------- E3 revocation vs number revoked
  const N = 4096;
  const docs = allRecs.slice(0, N).map((r, i) => H.bytesToHex(hashRec({ ...r, rev: i })));
  for (let i = 0; i < N; i += 512) await send(d1.contract.issueBatch(docs.slice(i, i + 512)));
  const root = H.bytesToHex(new MerkleTree(docs.map(H.hexToBytes)).root);
  await send(d3.contract.anchor(root));
  const fx = await setupRegistry({ n: 5, k: 3, prov });
  const e1 = await commitEpoch(fx, reqs.slice(0, N));
  await send(d4.contract.commit(ethers.id('warm'), ethers.ZeroHash, 1)); // B4 past its first (cold) commit
  const fx1 = await setupRegistry({ n: 5, k: 1, prov }); // EpochCred k=1: isolates ECDSA authorisation vs msg.sender
  await commitEpoch(fx1, reqs.slice(0, 8));
  let cursor = 0;
  const rnd = require('../offchain/lib/data').mulberry32(5);
  for (const r of REVS) {
    CTX = `E3 r=${r}`;
    const ids = docs.slice(cursor, cursor + r);
    const idx = Array.from({ length: r }, () => Math.floor(rnd() * N)); // random positions -> scattered words
    const row = { r };
    row.perCred_singleTx = (await send(d1.contract.revoke(ids[0]))).gas;
    row.perCred_batchTx = r > 1 ? (await send(d1.contract.revokeBatch(ids.slice(1)))).gas : 0;
    row.perCred_total = row.perCred_singleTx + row.perCred_batchTx;
    row.batchMerkle_total = (await send(d2.contract.revokeBatch(ids))).gas;
    // B3: a fresh, all-zero status list per row so every row starts from the same storage state
    const rootR = ethers.keccak256(ethers.concat([root, ethers.toBeHex(r, 32)]));
    const rootR2 = ethers.keccak256(ethers.concat([rootR, '0x01']));
    await send(d3.contract.anchor(rootR));
    await send(d3.contract.anchor(rootR2));
    row.statusList_total = (await send(d3.contract.revokeBatch(rootR, idx))).gas;
    // B3-opt: same revocations grouped by storage word off-chain (one SSTORE per touched word)
    const masks = new Map();
    for (const i of idx) masks.set(i >> 8, (masks.get(i >> 8) || 0n) | (1n << BigInt(i & 255)));
    row.statusListWords_total = (await send(d3.contract.revokeWords(rootR2, [...masks.keys()], [...masks.values()]))).gas;
    row.words_touched = masks.size;
    // B4: single-signer root registry; revocation = one commit carrying the new revocation root
    row.singleSignerRoot_total = (await send(d4.contract.commit(ethers.ZeroHash, ethers.id('rev' + r), 0))).gas;
    for (const w of e1.wallets.slice(cursor, cursor + r)) fx.issuer.revoke(w.nullifier);
    const t0 = process.hrtime.bigint();
    const b = fx.issuer.buildEpoch([]);
    row.smt_update_ms = ms(t0);
    const v = b.value;
    const s = await send(fx.regRelayer.commitEpoch(v.issuerId, v.epoch, v.issuanceRoot, v.revocationRoot, v.count, b.sigs));
    fx.issuer.confirm(v, (await prov.getBlock('latest')).timestamp);
    row.epochCred_total = s.gas;
    const b1r = fx1.issuer.buildEpoch([]);
    const s1r = await send(fx1.regRelayer.commitEpoch(b1r.value.issuerId, b1r.value.epoch, b1r.value.issuanceRoot, b1r.value.revocationRoot, b1r.value.count, b1r.sigs));
    fx1.issuer.confirm(b1r.value, (await prov.getBlock(s1r.receipt.blockNumber)).timestamp);
    row.epochCred_k1_total = s1r.gas;
    row.smt_size = fx.issuer.revoked.size;
    cursor += r;
    res.revocation.push(row);
    console.log('E3', JSON.stringify(row));
  }

  fs.writeFileSync(path.join(OUT, 'receipts.json'), JSON.stringify(RECEIPTS, null, 1));
  fs.writeFileSync(path.join(OUT, 'gas.json'), JSON.stringify(res, null, 2));
  console.log('wrote results/gas.json');
})().catch((e) => { console.error(e); process.exit(1); });
