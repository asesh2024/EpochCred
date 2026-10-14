'use strict';
// Rebuilds the published epoch data of an EXISTING test-network deployment from the chain itself
// (no private key needed): issuer registration, every EpochCommitted event, and the officer signatures
// from each commitEpoch transaction's calldata. Use it for deployments made before deploy_testnet.js
// started saving results/testnet_<network>_epochs.json.
//
//   RPC_URL=https://ethereum-sepolia-rpc.publicnode.com NETWORK=sepolia node experiments/fetch_testnet_epochs.js
//
// Reads the registry address and transaction hashes from results/testnet_<network>.json.
// Note: the revocation SETS (lists of nullifiers) are off-chain data and cannot be recovered from the chain;
// only their SMT roots are on chain.
const fs = require('fs');
const path = require('path');
const { ethers, artifact } = require('../offchain/lib/chain');
const C = require('../offchain/lib/credential');

const RPC = process.env.RPC_URL;
const NETWORK = process.env.NETWORK || 'sepolia';
if (!RPC) { console.error('set RPC_URL to the test network RPC endpoint'); process.exit(1); }

(async () => {
  const res = path.join(__dirname, '..', 'results');
  const run = JSON.parse(fs.readFileSync(path.join(res, `testnet_${NETWORK}.json`), 'utf8'));
  const prov = new ethers.JsonRpcProvider(RPC, undefined, { staticNetwork: true });
  const iface = new ethers.Interface(artifact('EpochCredRegistry.sol', 'EpochCredRegistry').abi);
  const registry = run.summary.registry;
  const out = { network: NETWORK, chainId: run.summary.chainId, registry, source: 'chain logs and transaction calldata', epochs: [] };
  for (const row of run.rows) {
    if (!row.txHash || row.label === 'deploy') continue;
    const [tx, rc] = await Promise.all([prov.getTransaction(row.txHash), prov.getTransactionReceipt(row.txHash)]);
    const call = iface.parseTransaction({ data: tx.data });
    const logs = rc.logs.filter((l) => l.address.toLowerCase() === registry.toLowerCase()).map((l) => iface.parseLog(l)).filter(Boolean);
    if (call.name === 'registerIssuer') {
      out.issuerId = call.args[0];
      out.officers = [...call.args[1]];
      out.threshold = Number(call.args[2]);
      out.registerTx = row.txHash;
      continue;
    }
    const ev = logs.find((l) => l.name === 'EpochCommitted');
    if (!ev) continue;
    const a = ev.args;
    const record = { issuanceRoot: a.issuanceRoot, revocationRoot: a.revocationRoot, timestamp: Number(a.timestamp), count: Number(a.count), prevHead: a.prevHead };
    const digest = C.recordDigest(record);
    out.epochs.push({ epoch: Number(a.epoch), txHash: row.txHash, block: rc.blockNumber, gasUsed: Number(rc.gasUsed), record, digest,
      digest_matches_event: digest.toLowerCase() === String(a.digest).toLowerCase(), signatures: call.args[call.args.length - 1] });
  }
  const file = path.join(res, `testnet_${NETWORK}_epochs.json`);
  fs.writeFileSync(file, JSON.stringify(out, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
  const bad = out.epochs.filter((e) => !e.digest_matches_event).length;
  console.log(`wrote ${file}: ${out.epochs.length} epochs, ${bad} digest mismatches`);
})().catch((e) => { console.error(e); process.exit(1); });
