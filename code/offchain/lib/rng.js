'use strict';
// Randomness source. Experiments set EPOCHCRED_SEED so every run is bit-for-bit reproducible
// (same salts, secrets, keys, signatures -> identical gas). Without the variable, the OS CSPRNG is
// used; a production deployment MUST NOT set EPOCHCRED_SEED.
const crypto = require('crypto');
const { keccak256 } = require('./keccak');

const SEED = process.env.EPOCHCRED_SEED;
let counter = 0n;
const enc = new TextEncoder();

function rand32() {
  if (SEED === undefined) return new Uint8Array(crypto.randomBytes(32));
  const label = enc.encode(`${SEED}|${counter++}`);
  return keccak256(label);
}

/** a deterministic private key for a named role when seeded, random otherwise */
function privKey(label) {
  if (SEED === undefined) return '0x' + crypto.randomBytes(32).toString('hex');
  const h = keccak256(enc.encode(`${SEED}|key|${label}|${counter++}`));
  return '0x' + Buffer.from(h).toString('hex');
}

module.exports = { rand32, privKey, seeded: SEED !== undefined };
