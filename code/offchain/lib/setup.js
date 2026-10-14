'use strict';
// Shared fixture: deploy a registry on the running node, register an issuer with n officers / threshold k.
const { ethers, provider, devWallet, deploy, send, randomWallet } = require('./chain');
const { Issuer } = require('./credential');

async function setupRegistry({ n = 5, k = 3, storeFull = false, prov = provider() } = {}) {
  const accreditor = devWallet(0, prov);
  const relayer = devWallet(1, prov);
  const { contract: reg, gas: deployGas, address } = await deploy(accreditor, 'EpochCredRegistry.sol', 'EpochCredRegistry', [storeFull]);
  const officers = Array.from({ length: n }, () => randomWallet());
  const issuerId = ethers.hexlify(require('./rng').rand32());
  const regGas = (await send(reg.registerIssuer(issuerId, officers.map((o) => o.address), k))).gas;
  const chainId = Number((await prov.getNetwork()).chainId);
  const issuer = new Issuer({ issuerId, officers, threshold: k, chainId, registry: address });
  return { prov, accreditor, relayer, reg, regRelayer: reg.connect(relayer), address, issuer, officers, deployGas, regGas, chainId };
}

/** build + commit an epoch; returns gas, wallets, on-chain record */
async function commitEpoch(fx, requests, signers) {
  const b = fx.issuer.buildEpoch(requests, signers);
  const v = b.value;
  const tx = await fx.regRelayer.commitEpoch(v.issuerId, v.epoch, v.issuanceRoot, v.revocationRoot, v.count, b.sigs);
  const r = await tx.wait();
  const blk = await fx.prov.getBlock(r.blockNumber);
  const rec = fx.issuer.confirm(v, blk.timestamp);
  return { gas: Number(r.gasUsed), calldataBytes: ethers.getBytes(tx.data).length, wallets: b.wallets, rec, value: v, build: b };
}

/** what a verifier reads from chain: two eth_calls (+ the records, taken from EpochCommitted logs).
 *  All reads are pinned to ONE block number, so digest, head, frozen flag and 'now' are mutually consistent. */
async function chainView(fx, epoch, recs) {
  const bn = await fx.prov.getBlockNumber();
  const [issDigest, iss, blk] = await Promise.all([
    fx.reg.epochDigest(fx.issuer.issuerId, epoch, { blockTag: bn }),
    fx.reg.issuers(fx.issuer.issuerId, { blockTag: bn }),
    fx.prov.getBlock(bn),
  ]);
  const latest = Number(iss.epoch);
  return { issRec: recs[epoch], issDigest, latestRec: recs[latest], head: iss.head, now: blk.timestamp, frozen: iss.frozen };
}

module.exports = { setupRegistry, commitEpoch, chainView };
