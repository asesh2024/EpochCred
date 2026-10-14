'use strict';
// E4-E6: presentation size, verification latency (off-chain and on-chain gas), sensitivity to the epoch
// batch size B, disclosed attributes d and revocation-set size r, plus baseline verifiers.
const fs = require('fs');
const path = require('path');
const { ethers, provider, devWallet, deploy, send, randomWallet } = require('../offchain/lib/chain');
const C = require('../offchain/lib/credential');
const H = require('../offchain/lib/hash');
const { MerkleTree, rootFromProof } = require('../offchain/lib/merkle');
const { SparseMerkleTree } = require('../offchain/lib/smt');
const { makeRecords, mulberry32 } = require('../offchain/lib/data');
const { setupRegistry, commitEpoch, chainView } = require('../offchain/lib/setup');

const QUICK = process.env.QUICK === '1';
const BS = QUICK ? [16, 256, 1024] : [16, 64, 256, 1024, 4096, 16384, 65536];
const RS = QUICK ? [0, 16, 256] : [0, 16, 64, 256, 1024, 4096, 16384, 32768];
const DS = [1, 2, 4, 8, 12, 16];
const SAMPLES = QUICK ? 40 : 200;
const rnd = mulberry32(2024);
const now_ns = () => process.hrtime.bigint();
const el = (t0) => Number(process.hrtime.bigint() - t0) / 1e6; // ms

function stats(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.floor(p * s.length))];
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  const sd = Math.sqrt(s.reduce((a, b) => a + (b - mean) ** 2, 0) / (s.length - 1));
  return { n: s.length, mean, sd, median: q(0.5), p05: q(0.05), p95: q(0.95), ci95: (1.96 * sd) / Math.sqrt(s.length), raw: xs };
}
function randomKeys(d) {
  const k = [...C.SCHEMA_KEYS];
  for (let i = k.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [k[i], k[j]] = [k[j], k[i]]; }
  return k.slice(0, d);
}
function onchainArgs(fx, p, w, issRec, latestRec) {
  const at = C.attrTree(w.attrs, w.seed);
  const d = p.disclosed[0];
  return [
    fx.issuer.issuerId, p.epoch, issRec, latestRec,
    { key: ethers.toUtf8Bytes(d.key), value: ethers.toUtf8Bytes(d.value), salt: H.bytesToHex(d.salt), attrIndex: d.index, attrPath: at.proof(d.index).map(H.bytesToHex) },
    { holder: p.holder, nullifier: H.bytesToHex(p.nullifier), validUntil: p.validUntil, schemaId: H.bytesToHex(p.schemaId), leafIndex: p.leafIndex, issuancePath: p.issuancePath.map(H.bytesToHex) },
    { bitmap: p.nonRevocation.bitmap, siblings: p.nonRevocation.siblings.map(H.bytesToHex) },
    86400,
  ];
}

/** create an issuer with an epoch of B credentials and a revocation set of r random nullifiers */
async function scenario(prov, B, r, holders) {
  const fx = await setupRegistry({ n: 5, k: 3, prov });
  const now = (await prov.getBlock('latest')).timestamp;
  const recsData = makeRecords(B, B + r);
  const reqs = recsData.map((attrs, i) => ({ attrs, holder: holders[i % holders.length].address, validUntil: now + 3e8 }));
  const t0 = now_ns();
  for (let i = 0; i < r; i++) fx.issuer.revoke(C.rand32());
  const e = await commitEpoch(fx, reqs);
  const buildMs = el(t0);
  return { fx, wallets: e.wallets, recs: { 1: e.rec }, buildMs };
}

async function measure(fx, wallets, recs, holders, keysFn, samples, prov, withOnchain) {
  const vt = [], pt = [], sizes = [], sibs = [];
  let gasOnchain = null;
  const cv = await chainView(fx, 1, recs);
  const challenge = 'nonce:' + ethers.hexlify(ethers.randomBytes(16));
  for (let s = 0; s < samples; s++) {
    const idx = Math.floor(rnd() * wallets.length);
    const w = wallets[idx];
    const hw = holders.find((h) => h.address === w.holder);
    const t0 = now_ns();
    const p = C.present(w, hw, keysFn(), fx.issuer.revoked, challenge);
    pt.push(el(t0));
    const t1 = now_ns();
    const ok = C.verify(p, cv, challenge).ok;
    vt.push(el(t1));
    if (!ok) throw new Error('verification failed unexpectedly');
    sizes.push(C.presentationSize(p));
    sibs.push(p.nonRevocation.siblings.length);
    if (withOnchain && s === 0) {
      gasOnchain = Number(await fx.reg.verifyAttribute.estimateGas(...onchainArgs(fx, p, w, recs[1], recs[1])));
      const okc = await fx.reg.verifyAttribute(...onchainArgs(fx, p, w, recs[1], recs[1]));
      if (!okc) throw new Error('on-chain verification failed');
    }
  }
  // RPC part: what the verifier reads (2 eth_call + latest block) from the local node
  const rpc = [];
  for (let s = 0; s < Math.min(samples, 50); s++) { const t = now_ns(); await chainView(fx, 1, recs); rpc.push(el(t)); }
  return { verify_ms: stats(vt), present_ms: stats(pt), size_bytes: stats(sizes), smt_siblings: stats(sibs), rpc_ms: stats(rpc), onchain_gas: gasOnchain };
}

(async () => {
  const prov = provider();
  const holders = Array.from({ length: 32 }, () => randomWallet());
  const out = { meta: { samples: SAMPLES, cpu: require('os').cpus()[0].model, node: process.version }, byB: [], byR: [], byD: [], baselines: [], multiproofAblation: [], smtDepthStats: [] };

  // ---------------- E4a: vary B (r = 1024, d = 3)
  for (const B of BS) {
    const sc = await scenario(prov, B, QUICK ? 64 : 1024, holders);
    const m = await measure(sc.fx, sc.wallets, sc.recs, holders, () => randomKeys(3), SAMPLES, prov, true);
    out.byB.push({ B, build_ms: sc.buildMs, ...m });
    console.log('B', B, 'verify med', m.verify_ms.median.toFixed(3), 'ms size', m.size_bytes.median, 'gas', m.onchain_gas, 'build', sc.buildMs.toFixed(0));
  }
  // ---------------- E4b: vary r (B = 1024, d = 3)
  for (const r of RS) {
    const sc = await scenario(prov, QUICK ? 256 : 1024, r, holders);
    const m = await measure(sc.fx, sc.wallets, sc.recs, holders, () => randomKeys(3), SAMPLES, prov, true);
    out.byR.push({ r, log2r: r ? Math.log2(r) : 0, smt_build_ms: sc.buildMs, ...m });
    console.log('r', r, 'verify med', m.verify_ms.median.toFixed(3), 'sibs', m.smt_siblings.mean.toFixed(2), 'gas', m.onchain_gas);
  }
  // ---------------- E4c: vary d (B = 1024, r = 1024)
  const scD = await scenario(prov, QUICK ? 256 : 1024, QUICK ? 64 : 1024, holders);
  for (const d of DS) {
    const m = await measure(scD.fx, scD.wallets, scD.recs, holders, () => randomKeys(d), SAMPLES, prov, false);
    out.byD.push({ d, ...m });
    // ablation: compact multiproof vs d independent single proofs (bytes of attribute-proof material)
    let multi = 0, indep = 0;
    for (let s = 0; s < 100; s++) {
      const w = scD.wallets[Math.floor(rnd() * scD.wallets.length)];
      const at = C.attrTree(w.attrs, w.seed);
      const idx = randomKeys(d).map((k) => C.SCHEMA_KEYS.indexOf(k));
      multi += 32 * at.multiproof(idx).length;
      indep += 32 * at.height * d;
    }
    out.multiproofAblation.push({ d, multiproof_bytes: multi / 100, independent_bytes: indep / 100 });
    console.log('d', d, 'size', m.size_bytes.median, 'verify', m.verify_ms.median.toFixed(3));
  }

  // ---------------- baselines: full-document disclosure verifiers (same node)
  const owner = devWallet(0, prov);
  const { contract: pc } = await deploy(owner, 'Baselines.sol', 'PerCredentialRegistry');
  const { contract: bm } = await deploy(owner, 'Baselines.sol', 'BatchMerkleRegistry');
  const { contract: sl } = await deploy(owner, 'Baselines.sol', 'StatusListRegistry');
  const B0 = QUICK ? 256 : 1024;
  const docs = makeRecords(B0, 77).map((r) => JSON.stringify(r));
  const hashes = docs.map((d) => H.keccak256(H.toBytes(d)));
  for (let i = 0; i < B0; i += 512) await send(pc.issueBatch(hashes.slice(i, i + 512).map(H.bytesToHex)));
  const tree = new MerkleTree(hashes);
  const root = H.bytesToHex(tree.root);
  await send(bm.anchor(root));
  await send(sl.anchor(root));
  for (const [name, c] of [['PerCredential', pc], ['BatchMerkle', bm], ['StatusList', sl]]) {
    const crypto_ms = [], total_ms = [], sizes = [];
    for (let s = 0; s < Math.min(SAMPLES, 100); s++) {
      const i = Math.floor(rnd() * B0);
      const doc = docs[i];
      const t0 = now_ns();
      const h = H.keccak256(H.toBytes(doc));
      let pathH = [];
      if (name !== 'PerCredential') { pathH = tree.proof(i); rootFromProof(h, i, pathH); }
      crypto_ms.push(el(t0));
      const t1 = now_ns();
      let ok;
      if (name === 'PerCredential') ok = await c.isValid(H.bytesToHex(h));
      else ok = await c.verify(H.bytesToHex(h), i, pathH.map(H.bytesToHex), root);
      total_ms.push(el(t1));
      if (!ok) throw new Error('baseline verify failed');
      sizes.push(H.toBytes(doc).length + 32 * pathH.length + (name === 'PerCredential' ? 0 : 32 + 4));
    }
    const gas = name === 'PerCredential'
      ? Number(await c.isValid.estimateGas(H.bytesToHex(hashes[0])))
      : Number(await c.verify.estimateGas(H.bytesToHex(hashes[0]), 0, tree.proof(0).map(H.bytesToHex), root));
    out.baselines.push({ scheme: name, B: B0, crypto_ms: stats(crypto_ms), rpc_ms: stats(total_ms), size_bytes: stats(sizes), onchain_gas: gas, disclosed_attributes: C.SCHEMA_KEYS.length });
    console.log('baseline', name, 'size', stats(sizes).median, 'gas', gas);
  }

  fs.writeFileSync(path.join(__dirname, '..', 'results', 'verify.json'), JSON.stringify(out, null, 2));
  console.log('wrote results/verify.json');
})().catch((e) => { console.error(e); process.exit(1); });
