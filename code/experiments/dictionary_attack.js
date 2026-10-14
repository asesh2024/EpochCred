'use strict';
// E7: privacy of undisclosed attributes. Many prior systems publish/disclose per-field hashes H(value)
// without per-attribute salts. Low-entropy academic attributes are then recoverable by enumeration.
// We measure actual recovery rate and time against (a) unsalted leaves and (b) EpochCred salted leaves.
const fs = require('fs');
const path = require('path');
const H = require('../offchain/lib/hash');
const C = require('../offchain/lib/credential');
const { makeRecords } = require('../offchain/lib/data');

const N = Number(process.env.N || 200);
const recs = makeRecords(N, 31337);

const dict = {
  cgpa: Array.from({ length: 1001 }, (_, i) => (i / 100).toFixed(2)),
  graduationYear: Array.from({ length: 101 }, (_, i) => String(1950 + i)),
  classification: ['First Class with Distinction', 'First Class', 'Second Class', 'Pass Class', 'Third Class'],
  dateOfBirth: (() => {
    const out = [];
    for (let y = 1990; y <= 2010; y++) for (let m = 1; m <= 12; m++) for (let d = 1; d <= 31; d++)
      out.push(`${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`);
    return out;
  })(),
  program: ['B.Tech', 'M.Tech', 'MBA', 'B.Sc', 'M.Sc', 'BBA', 'Ph.D'].flatMap((d) =>
    ['Computer Science and Engineering', 'Electronics and Communication Engineering', 'Mechanical Engineering', 'Civil Engineering', 'Data Science', 'Finance', 'Mathematics', 'Physics', 'Marketing', 'Computer Science'].map((m) => `${d} ${m}`)),
};

const results = [];
for (const [attr, candidates] of Object.entries(dict)) {
  // precompute the dictionary once (attacker side), then look up every target
  const t0 = process.hrtime.bigint();
  const table = new Map(candidates.map((v) => [H.bytesToHex(H.attrLeafUnsalted(attr, v)), v]));
  const buildMs = Number(process.hrtime.bigint() - t0) / 1e6;
  let recovered = 0;
  for (const r of recs) if (table.get(H.bytesToHex(H.attrLeafUnsalted(attr, r[attr]))) === r[attr]) recovered++;
  // salted: same dictionary, attacker does not know the 256-bit salt; try the dictionary with a zero salt and
  // with 10^4 random salt guesses per target for the first 20 targets (all must fail)
  let saltedHits = 0;
  let trials = 0;
  const t1 = process.hrtime.bigint();
  for (const r of recs.slice(0, 20)) {
    const seed = C.rand32();
    const j = C.SCHEMA_KEYS.indexOf(attr);
    const target = H.bytesToHex(H.attrLeaf(C.deriveSalt(seed, j), attr, r[attr]));
    if (table.has(target)) saltedHits++;
    for (let g = 0; g < 10000 / candidates.length + 1; g++) {
      const guessSalt = C.rand32();
      for (const v of candidates) { trials++; if (H.bytesToHex(H.attrLeaf(guessSalt, attr, v)) === target) saltedHits++; }
    }
  }
  const saltedMs = Number(process.hrtime.bigint() - t1) / 1e6;
  const row = {
    attribute: attr, dictionarySize: candidates.length, entropyBits: Math.log2(candidates.length), targets: N,
    unsalted_recovered: recovered, unsalted_rate: recovered / N, unsalted_table_ms: buildMs,
    unsalted_ms_per_target: buildMs / N,
    salted_recovered: saltedHits, salted_trials: trials, salted_ms: saltedMs,
    salted_success_bound: `2^-256 per guess (salt unknown); dictionary of 2^${Math.log2(candidates.length).toFixed(1)} useless`,
  };
  results.push(row);
  console.log(attr, `unsalted ${recovered}/${N} in ${buildMs.toFixed(1)} ms`, `salted ${saltedHits} hits / ${trials} trials`);
}
fs.writeFileSync(path.join(__dirname, '..', 'results', 'dictionary.json'), JSON.stringify(results, null, 2));
console.log('wrote results/dictionary.json');
