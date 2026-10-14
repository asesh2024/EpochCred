'use strict';
// Builds paper/tables/tab_testnet.tex (and testnet macros) from results/testnet_<network>.json.
// Called by deploy_testnet.js; can also be run on its own to regenerate the table without redeploying:
//   node experiments/make_testnet_table.js sepolia
// Reports first and subsequent epochs SEPARATELY (never a mean over different epoch types), next to the
// local (pre-Glamsterdam, Prague-rules) figures for the same transaction types when results/gas.json exists.
const fs = require('fs');
const path = require('path');

const fmt = (x) => (x == null || Number.isNaN(x) ? '--' : Math.round(x).toLocaleString('en-US').replace(/,/g, '{,}'));
const median = (xs) => { const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };

function build(network) {
  const res = path.join(__dirname, '..', 'results');
  const j = JSON.parse(fs.readFileSync(path.join(res, `testnet_${network}.json`), 'utf8'));
  const { summary, rows } = j;
  const get = (l) => rows.find((r) => r.label === l);
  const commits = rows.filter((r) => r.label.startsWith('commitEpoch'));
  const first = commits[0];
  const later = commits.slice(1);
  const laterGas = later.map((r) => r.gasUsed);
  const incl = commits.map((r) => r.inclusion_ms / 1000);
  const gasPrices = commits.map((r) => r.gasPriceGwei).filter((x) => x != null);
  let local = null;
  try {
    const g = JSON.parse(fs.readFileSync(path.join(res, 'gas.json'), 'utf8'));
    const row = g.issuance.find((r) => r.B === summary.batch) || g.issuance.find((r) => r.B === 256) || g.issuance[g.issuance.length - 1];
    local = { deploy: g.deploy.EpochCred, register: g.deploy.registerIssuer_n5, first: row.epochCred_k3_first_txGas, later: row.epochCred_k3_txGas, B: row.B };
  } catch (e) { /* local results not available */ }
  const L = (x) => (local ? fmt(x) : '--');
  const dl = get('deploy');
  const rg = get('registerIssuer');
  const tex = `\\begin{tabular}{lrr}
\\toprule
Gas unless stated & Sepolia & Local node\\\\
\\midrule
Registry deployment & ${fmt(dl && dl.gasUsed)} & ${L(local && local.deploy)}\\\\
Issuer onboarding, $n{=}5$ & ${fmt(rg && rg.gasUsed)} & ${L(local && local.register)}\\\\
First epoch & ${fmt(first && first.gasUsed)} & ${L(local && local.first)}\\\\
Later epochs, median & ${fmt(median(laterGas))} & ${L(local && local.later)}\\\\
Later epochs, min--max & ${fmt(Math.min(...laterGas))}--${fmt(Math.max(...laterGas))} & --\\\\
Epochs committed & ${summary.epochs} & --\\\\
Inclusion, median / max (s) & ${median(incl).toFixed(1)} / ${Math.max(...incl).toFixed(1)} & --\\\\
Gas price paid, median (gwei) & ${gasPrices.length ? median(gasPrices).toPrecision(2) : '--'} & --\\\\
\\bottomrule
\\end{tabular}
`;
  fs.mkdirSync(path.join(__dirname, '..', '..', 'paper', 'tables'), { recursive: true });
  const tab = path.join(__dirname, '..', '..', 'paper', 'tables', 'tab_testnet.tex');
  fs.writeFileSync(tab, tex);
  const macros = {
    tnFirst: fmt(first && first.gasUsed), tnLater: fmt(median(laterGas)), tnLaterMin: fmt(Math.min(...laterGas)), tnLaterMax: fmt(Math.max(...laterGas)),
    tnRegister: fmt(rg && rg.gasUsed), tnDeploy: fmt(dl && dl.gasUsed), tnInclMed: median(incl).toFixed(1), tnInclMax: Math.max(...incl).toFixed(1),
    tnEpochs: String(summary.epochs), tnBatch: String(summary.batch), tnRev: String(summary.revocationsPerEpoch), tnRegistry: summary.registry,
    tnLaterDelta: local ? fmt(median(laterGas) - local.later) : '--', tnLocalLater: local ? fmt(local.later) : '--', tnLocalRegister: local ? fmt(local.register) : '--',
    tnDate: summary.date.slice(0, 10), tnChain: String(summary.chainId), tnConf: String(summary.confirmations),
  };
  fs.writeFileSync(path.join(__dirname, '..', '..', 'paper', 'tables', 'testnet_numbers.tex'),
    Object.entries(macros).map(([k, v]) => `\\newcommand{\\${k}}{${v}}`).join('\n') + '\n');
  return { tab, macros };
}

module.exports = { build };
if (require.main === module) {
  const net = process.argv[2] || 'sepolia';
  const { tab, macros } = build(net);
  console.log('wrote', tab, macros);
}
