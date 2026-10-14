'use strict';
// External deployment experiment (reviewer request): runs EpochCred against a PUBLIC test network and records
// inclusion latency, gas and fees from real receipts. Run it yourself (it needs a funded test account):
//
//   RPC_URL=https://ethereum-sepolia-rpc.publicnode.com PRIVATE_KEY=0x... NETWORK=sepolia \
//     node experiments/deploy_testnet.js
//
// Optional: EPOCHS (default 10), BATCH (default 256), REVOKE_PER_EPOCH (default 4), CONFIRMATIONS (default 1).
// Output: results/testnet_<network>.json and ../paper/tables/tab_testnet.tex (the paper includes it if present).
const fs = require('fs');
const path = require('path');
const { ethers, artifact } = require('../offchain/lib/chain');
const C = require('../offchain/lib/credential');
const H = require('../offchain/lib/hash');
const { makeRecords } = require('../offchain/lib/data');

const RPC = process.env.RPC_URL;
const PK = process.env.PRIVATE_KEY;
const NETWORK = process.env.NETWORK || 'testnet';
const EPOCHS = Number(process.env.EPOCHS || 10);
const BATCH = Number(process.env.BATCH || 256);
const REV = Number(process.env.REVOKE_PER_EPOCH || 4);
const CONF = Number(process.env.CONFIRMATIONS || 1);
if (!RPC || !PK) { console.error('set RPC_URL and PRIVATE_KEY (a funded TEST-network key, never a mainnet key)'); process.exit(1); }

(async () => {
  const prov = new ethers.JsonRpcProvider(RPC, undefined, { pollingInterval: 1000 });
  const net = await prov.getNetwork();
  const signer = new ethers.Wallet(PK, prov);
  console.log(`network ${NETWORK} chainId ${net.chainId}, account ${signer.address}, balance ${ethers.formatEther(await prov.getBalance(signer.address))}`);
  const rows = [];
  async function timed(label, txp) {
    const t0 = Date.now();
    const tx = await txp;
    const sent = Date.now();
    const rc = await tx.wait(CONF);
    const done = Date.now();
    const fee = rc.gasUsed * (rc.gasPrice ?? rc.effectiveGasPrice ?? 0n);
    const row = { label, txHash: rc.hash, block: rc.blockNumber, gasUsed: Number(rc.gasUsed), gasPriceGwei: Number(ethers.formatUnits(rc.gasPrice ?? 0n, 'gwei')),
      feeEth: Number(ethers.formatEther(fee)), submit_ms: sent - t0, inclusion_ms: done - sent };
    rows.push(row);
    console.log(label, row.gasUsed, 'gas', (row.inclusion_ms / 1000).toFixed(1), 's', row.txHash);
    return rc;
  }
  const a = artifact('EpochCredRegistry.sol', 'EpochCredRegistry');
  const factory = new ethers.ContractFactory(a.abi, a.bytecode, signer);
  const t0 = Date.now();
  const reg = await factory.deploy(false);
  const dep = await reg.deploymentTransaction().wait(CONF);
  rows.push({ label: 'deploy', txHash: dep.hash, block: dep.blockNumber, gasUsed: Number(dep.gasUsed), inclusion_ms: Date.now() - t0 });
  const address = await reg.getAddress();
  console.log('registry', address);
  const officers = Array.from({ length: 5 }, () => ethers.Wallet.createRandom());
  const issuerId = ethers.id(`epochcred-${Date.now()}`);
  await timed('registerIssuer', reg.registerIssuer(issuerId, officers.map((o) => o.address), 3));
  const issuer = new C.Issuer({ issuerId, officers, threshold: 3, chainId: Number(net.chainId), registry: address });
  const holder = ethers.Wallet.createRandom().address;
  const recs = makeRecords(BATCH * EPOCHS, 5);
  let prevWallets = [];
  const epochLog = []; // published data of every epoch (what auditors and holders need, assumption A2)
  const revokedSoFar = [];
  for (let e = 0; e < EPOCHS; e++) {
    for (const w of prevWallets.slice(0, REV)) { issuer.revoke(w.nullifier); revokedSoFar.push(H.bytesToHex(w.nullifier)); }
    const t = Date.now();
    const b = issuer.buildEpoch(recs.slice(e * BATCH, (e + 1) * BATCH).map((attrs) => ({ attrs, holder, validUntil: 4e9 })));
    const buildMs = Date.now() - t;
    const v = b.value;
    const rc = await timed(`commitEpoch ${e + 1}`, reg.commitEpoch(v.issuerId, v.epoch, v.issuanceRoot, v.revocationRoot, v.count, b.sigs));
    rows[rows.length - 1].build_ms = buildMs;
    const ts = (await prov.getBlock(rc.blockNumber)).timestamp;
    const record = { issuanceRoot: v.issuanceRoot, revocationRoot: v.revocationRoot, timestamp: ts, count: v.count, prevHead: v.prevHead };
    epochLog.push({ epoch: v.epoch, txHash: rc.hash, block: rc.blockNumber, signed_value: { ...v }, signatures: b.sigs, record, digest: C.recordDigest(record),
      published_revocation_set: [...revokedSoFar].sort(), records: { generator: 'makeRecords', n: BATCH * EPOCHS, seed: 5, slice: [e * BATCH, (e + 1) * BATCH] } });
    issuer.confirm(v, ts);
    prevWallets = b.wallets;
  }
  const commits = rows.filter((r) => r.label.startsWith('commitEpoch'));
  const incl = commits.map((r) => r.inclusion_ms / 1000).sort((x, y) => x - y);
  const summary = { network: NETWORK, chainId: Number(net.chainId), registry: address, epochs: EPOCHS, batch: BATCH, revocationsPerEpoch: REV, confirmations: CONF,
    commit_gas_mean: commits.reduce((s, r) => s + r.gasUsed, 0) / commits.length, inclusion_s_median: incl[Math.floor(incl.length / 2)], inclusion_s_max: incl[incl.length - 1],
    fee_eth_total: commits.reduce((s, r) => s + (r.feeEth || 0), 0), date: new Date().toISOString() };
  const out = path.join(__dirname, '..', 'results', `testnet_${NETWORK}.json`);
  fs.writeFileSync(out, JSON.stringify({ summary, rows }, null, 2));
  // epoch records, signatures and published revocation sets (no private keys are written)
  fs.writeFileSync(path.join(__dirname, '..', 'results', `testnet_${NETWORK}_epochs.json`),
    JSON.stringify({ registry: address, issuerId, chainId: Number(net.chainId), threshold: 3, officers: officers.map((o) => o.address), epochs: epochLog }, null, 2));
  const { tab } = require('./make_testnet_table').build(NETWORK);
  console.log('summary', summary, '\nwrote', out, 'and', tab);
})().catch((e) => { console.error(e); process.exit(1); });
