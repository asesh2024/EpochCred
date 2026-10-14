#!/usr/bin/env bash
# Reproduces every result, figure and table of the paper, then compiles the PDF.
#   ./scripts/run_all.sh           full run  (about 30-45 min on a laptop)
#   QUICK=1 ./scripts/run_all.sh   smoke test (about 5 min, smaller sweeps; numbers differ from the paper)
# Optional: SOLC=/path/to/solc-0.8.24 to use a local compiler instead of Foundry's auto-download.
set -euo pipefail
cd "$(dirname "$0")/.."          # -> code/
CODE_DIR="$(pwd)"
PAPER_DIR="$CODE_DIR/../paper"
mkdir -p results
# deterministic randomness for experiments (same salts/keys/signatures -> identical gas on every run).
# Never set EPOCHCRED_SEED in a real deployment.
export EPOCHCRED_SEED="${EPOCHCRED_SEED:-epochcred-2026}"
# all local experiments talk to the local anvil node, never to a public network left in the environment
if [[ -n "${RPC_URL:-}" && "$RPC_URL" != "http://127.0.0.1:8545" ]]; then
  echo "note: ignoring RPC_URL=$RPC_URL for the local experiments (deploy_testnet.js uses it separately)"
fi
export RPC_URL=http://127.0.0.1:8545
unset PRIVATE_KEY
USE_SOLC=()
if [[ -n "${SOLC:-}" ]]; then USE_SOLC=(--use "$SOLC"); fi

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

for tool in forge anvil node python3; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool (see RUN_ON_WSL.md)"; exit 1; }
done

step "1/12 compile contracts (forge build)"
forge build "${USE_SOLC[@]}"

step "2/12 start a local EVM node (anvil) on :8545"
ANVIL_PID=""
if curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:8545 >/dev/null 2>&1; then
  echo "WARNING: an RPC node is already listening on :8545; stop it (pkill anvil) for bit-for-bit reproducible gas numbers"
else
  # Prague gas rules pinned (pre-Glamsterdam; a future Foundry default would change every gas figure);
  # fixed genesis time; block timestamps then advance by exactly 12 s per block (set below), so the
  # hash-chained epoch digests, the signatures over them and therefore every gas figure are identical on reruns
  anvil --silent --hardfork prague --gas-limit 300000000 --timestamp 1767225600 > results/anvil.log 2>&1 &
  ANVIL_PID=$!
  trap '[[ -n "$ANVIL_PID" ]] && kill $ANVIL_PID 2>/dev/null || true' EXIT
  for _ in $(seq 1 50); do
    curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:8545 >/dev/null 2>&1 && break
    sleep 0.2
  done
  curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"anvil_setBlockTimestampInterval","params":[12]}' http://127.0.0.1:8545 >/dev/null
fi

step "3/12 cross-implementation vectors + Solidity unit/fuzz tests"
node experiments/gen_vectors.js
forge test "${USE_SOLC[@]}"

step "4/12 security and correctness checks (attacks + valid-path / documented-behaviour cases)"
node experiments/security_tests.js

step "5/12 gas experiments E1-E3 (issuance, threshold, revocation)"
node experiments/gas_experiments.js

step "6/12 verification experiments E4 (latency, size, baselines)"
node experiments/verify_experiments.js
node experiments/revocation_compare.js

step "7/12 dictionary attack E5"
node experiments/dictionary_attack.js

step "8/12 SMT proof-length law (Proposition 1)"
node experiments/smt_stats.js

step "9/12 verification breakdown, issuer throughput, signing time"
node experiments/breakdown.js

step "10/12 anchoring-policy simulation E6"
if [[ -n "${QUICK:-}" ]]; then python3 analysis/policy_sim.py --quick; else python3 analysis/policy_sim.py; fi
step "11/12 figures and tables"
python3 analysis/make_figures.py
# processed data: synthetic input records (CSV + checksums), a worked example epoch, SHA256SUMS of all results
node experiments/export_data.js
# public test-network table (only if a deployment was run, see RUN_ON_WSL.md section 10)
if [[ -f results/testnet_sepolia.json ]]; then node experiments/make_testnet_table.js sepolia >/dev/null && echo "testnet table: paper/tables/tab_testnet.tex"; fi

step "12/12 compile the paper (only if the manuscript sources are present; they are not in the public repository)"
if [[ ! -f "$PAPER_DIR/main.tex" ]]; then
  echo "no paper/main.tex - figures are in paper/figs/, tables and numbers in paper/tables/"
elif command -v latexmk >/dev/null; then
  (cd "$PAPER_DIR" && latexmk -pdf -interaction=nonstopmode -quiet main.tex) && echo "PDF: $(cd "$PAPER_DIR" && pwd)/main.pdf"
  # response letters cross-reference main.aux (xr package), so they are built after the paper
  for f in response_to_reviewers response_to_review2; do
    [[ -f "$PAPER_DIR/$f.tex" ]] && (cd "$PAPER_DIR" && latexmk -pdf -interaction=nonstopmode -quiet "$f.tex") >/dev/null 2>&1 && echo "PDF: $PAPER_DIR/$f.pdf"
  done
else
  echo "latexmk not found - skipping PDF build (install TeX Live, see RUN_ON_WSL.md)"
fi
step "done - raw results in code/results/, figures in paper/figs/, tables in paper/tables/"
