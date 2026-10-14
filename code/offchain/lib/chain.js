'use strict';
// Thin helpers around an anvil (or any EVM JSON-RPC) node using the vendored ethers bundle.
const fs = require('fs');
const path = require('path');
const ethers = require('../vendor/ethers.umd.min.js');

const RPC = process.env.RPC_URL || 'http://127.0.0.1:8545';
const MNEMONIC = 'test test test test test test test test test test test junk'; // anvil default dev accounts

function artifact(file, name) {
  const p = path.join(__dirname, '..', '..', 'out', file, `${name}.json`);
  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

function provider() {
  return new ethers.JsonRpcProvider(RPC, undefined, { staticNetwork: true, cacheTimeout: -1, pollingInterval: 50 });
}

const LOCAL_CHAIN_IDS = new Set([31337n, 1337n]);
/** anvil's public development accounts: only ever usable against a LOCAL node */
async function assertLocal(prov) {
  const { chainId } = await prov.getNetwork();
  if (!LOCAL_CHAIN_IDS.has(BigInt(chainId))) {
    throw new Error(`refusing to run local experiments against chain ${chainId} (RPC_URL=${RPC}). ` +
      'Unset RPC_URL or point it to http://127.0.0.1:8545; public networks are only for experiments/deploy_testnet.js.');
  }
}

function devWallet(i, prov) {
  return ethers.HDNodeWallet.fromPhrase(MNEMONIC, undefined, `m/44'/60'/0'/0/${i}`).connect(prov);
}

async function deploy(signer, file, name, args = []) {
  if (signer.provider && !signer.__checkedLocal) { await assertLocal(signer.provider); signer.__checkedLocal = true; }
  const a = artifact(file, name);
  const f = new ethers.ContractFactory(a.abi, a.bytecode, signer);
  const c = await f.deploy(...args);
  const rcpt = await c.deploymentTransaction().wait();
  return { contract: c, gas: Number(rcpt.gasUsed), address: await c.getAddress() };
}

async function send(txPromise) {
  const tx = await txPromise;
  const r = await tx.wait();
  return { gas: Number(r.gasUsed), receipt: r, calldataBytes: ethers.getBytes(tx.data).length };
}

const { privKey } = require('./rng');
/** fresh key pair (deterministic when EPOCHCRED_SEED is set) */
function randomWallet() {
  return new ethers.Wallet(privKey('w'));
}

module.exports = { ethers, provider, devWallet, deploy, send, artifact, RPC, randomWallet, assertLocal };
