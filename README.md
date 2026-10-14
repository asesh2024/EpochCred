# EpochCred

**Quorum-endorsed, epoch-anchored academic credential registry for the EVM — with selective disclosure, rollback-evident revocation and cost–freshness-aware anchoring.**

This repository contains the Solidity contracts, the off-chain reference library, every experiment script, the raw results and the processed data behind the paper. A single script regenerates every number, table and figure reported in the paper. The manuscript itself is under review and is not part of this repository.

---

## The idea in one paragraph

Most blockchain registries for academic certificates store one hash per certificate, signed by one issuer key, and revoke by writing a flag. In EpochCred an institution publishes **one 32-byte digest per epoch**, endorsed by **k of its n officers** (independent ECDSA / EIP-712 signatures). The digest is hash-chained to the previous epoch and binds:

- a **two-level Merkle root** of the epoch's credentials (credential leaves over *salted* attribute commitments → selective disclosure), and
- the root of a **depth-256 sparse Merkle tree (SMT)** of revocation nullifiers.

If a later root silently drops a revoked credential, anyone can submit an **on-chain fraud proof** that freezes the issuer. Rollback is made *publicly evident and penalised*, not prevented. An **adaptive anchoring rule** taken from TCP acknowledgment-delay theory decides when to close an epoch, trading gas against freshness. It is provably 2-competitive.

Only Keccak-256 and `ecrecover` are used; there is no new cryptography.

```
 officers (k of n) ──sign──►  D_e = H( R_iss , R_rev , t_e , B , D_{e-1} )  ──commitEpoch──►  EpochCredRegistry
                                  │        │                       │
           credential Merkle root ┘        └ revocation SMT root   └ hash chain to previous epoch

 holder ──presentation (disclosed attributes + Merkle paths + SMT non-membership proof)──► verifier ──reads D_e──► chain
```

## Headline results

Local EVM node (anvil, Prague rules), seed `epochcred-2026`, fixed node clock, so the gas figures are identical on every rerun.

| Metric | Result |
|---|---|
| Amortised on-chain anchoring cost, k = 3 | **80.1 gas / credential** (1,024 per epoch), **20.0** (4,096 per epoch) |
| Subsequent issuance epoch, 1,024 credentials | EpochCred k=3: 82,072 · k=1: 68,338 · single-signer root registry: 60,645 |
| Quorum overhead (k = 3 vs single signer) | 21,427 gas per epoch (35 %) |
| Revoking 1,024 credentials | EpochCred 82,060 · word-grouped bitstring 393,522 · per-index bitstring 1.10 M · per-certificate registry 6.2 M · batch Merkle + list 23.4 M |
| On-chain non-revocation check (1,024 revoked) | SMT 16,939 gas (48,774 without the lowest-bit shortcut) · root-anchored status list 14,417 |
| Fraud proof (1,025 revoked) | 151,380 gas |
| Anchoring policy vs. hindsight optimum | adaptive **1.17×** (max 1.21×) · best fixed period 1.72× |
| Dictionary attack on unsalted grade / birth-date fields | 100 % recovered; salted commitments resist it |
| Security & correctness checks | **49 / 49** (39 attacks + 10 valid-path / documented-behaviour cases) |

### Public test-network deployment (Sepolia)

| | |
|---|---|
| Registry | [`0x249f6E19e591a4d379EE0D457790B147772c8582`](https://sepolia.etherscan.io/address/0x249f6E19e591a4d379EE0D457790B147772c8582) |
| `registerIssuer` (5 officers, k = 3) | 1,354,177 gas |
| `commitEpoch`, first / subsequent (256 credentials, 4 revocations) | 276,288 / 178,752 – 178,776 gas |
| Median inclusion time | 10.3 s |

Sepolia has used the *Glamsterdam* gas schedule since 6 Oct 2026. EIP-8037 reprices new storage slots, so Sepolia gas figures are higher than the local Prague figures. The paper explains the difference.

## Repository layout

```
EpochCred/
├── code/
│   ├── src/                  Solidity: CredLib, EpochCredRegistry, Baselines (B1–B4, B3*)
│   ├── test/                 Foundry tests: cross-implementation vectors + fuzzing (1,000 runs)
│   ├── offchain/lib/         JavaScript reference library: issuer, holder, verifier, Merkle, SMT, Keccak
│   ├── offchain/vendor/      ethers v6 bundle (no npm install needed)
│   ├── experiments/          security, gas, verification, revocation, privacy, SMT, testnet scripts
│   ├── analysis/             anchoring-policy simulation + figure/table generator (Python)
│   ├── results/              raw JSON results and transaction receipts used in the paper
│   ├── data/                 synthetic input records (CSV + checksums), worked example epoch, SHA256SUMS
│   ├── lib/forge-std/        Foundry standard library (vendored)
│   └── scripts/run_all.sh    reproduces everything
├── paper/                    created by run_all.sh: generated figures (figs/) and tables (tables/; numbers.tex holds every number in the text)
└── LICENSE
```

## Quick start

Requirements: **Foundry** (forge, anvil), **Node.js ≥ 18**, **Python 3** with `numpy` and `matplotlib`, and, for figures, nothing else (LaTeX is not needed). There are no npm dependencies.

```bash
git clone https://github.com/asesh2024/EpochCred.git
cd EpochCred/code

QUICK=1 ./scripts/run_all.sh     # smoke test, ~5 min (smaller sweeps; numbers differ from the paper)
./scripts/run_all.sh             # full reproduction, ~30–45 min
```

The script compiles the contracts, starts a local anvil node (Prague rules, fixed clock), runs the Foundry tests and all experiments, and writes the figures to `paper/figs/` and the tables and inline numbers to `paper/tables/`. It always uses the local node, even if `RPC_URL` is set in your shell.

Installation on Ubuntu or WSL 2:
```bash
curl -L https://foundry.paradigm.xyz | bash && foundryup      # forge, anvil
sudo apt install -y nodejs python3-numpy python3-matplotlib    # Node.js >= 18
```

### Processed data
`code/data/datasets/` holds the synthetic input records of every experiment (CSV, with SHA-256 checksums in `MANIFEST.json`), `code/data/example_epoch/` a worked two-epoch example (signed epochs, published revocation sets, wallets, presentations, verifier output), and `code/data/SHA256SUMS` checksums of all data and results (`cd code && sha256sum -c data/SHA256SUMS`). Regenerate with `EPOCHCRED_SEED=epochcred-2026 node experiments/export_data.js`. The Sepolia epoch records are in `code/results/testnet_sepolia_epochs.json`.

### Running individual pieces

```bash
cd code
forge build && forge test                 # contracts + unit/fuzz tests
node experiments/security_tests.js        # 49 attack / correctness checks (needs anvil running)
node experiments/gas_experiments.js       # issuance, quorum and revocation gas
python3 analysis/policy_sim.py            # anchoring-policy simulation
```
For bit-identical gas, start anvil as `run_all.sh` does: `--hardfork prague --timestamp 1767225600`, then `anvil_setBlockTimestampInterval 12`, with `EPOCHCRED_SEED=epochcred-2026`.

### Deploying to a public test network

```bash
cd code
read -s -p "Test-network private key: " PRIVATE_KEY; echo; export PRIVATE_KEY
RPC_URL=https://ethereum-sepolia-rpc.publicnode.com NETWORK=sepolia node experiments/deploy_testnet.js
unset PRIVATE_KEY RPC_URL
```
Use a throw-away **test-network** key only. Never set `EPOCHCRED_SEED` for a real deployment, because it makes salts and keys deterministic.

## Scope and limitations

- **Rollback-evident, not rollback-proof.** Removing a committed revocation is detected and the issuer is frozen. Verifiers are exposed until a challenge is included on chain, and the paper quantifies this window.
- **Quorum, not threshold signatures.** The contract checks k independent ECDSA signatures; there is no aggregate signature.
- **Privacy.** Unlinkability holds against public observers of the chain. Verifiers see the disclosed attributes and the presentation.
- **Research prototype.** The contracts have not been audited. Do not use them in production without an independent security review.

## Citation

The paper is under review. Until it is published, please cite the repository:

```bibtex
@misc{epochcred2026,
  title  = {EpochCred: Quorum-Endorsed Epoch Anchoring for Scalable Academic Credential Verification},
  author = {Pavani, Paladugu and Tripathy, Asesh Kumar},
  year   = {2026},
  howpublished = {\url{https://github.com/asesh2024/EpochCred}}
}
```

## Licence

Code: MIT (see [LICENSE](LICENSE)). `code/offchain/vendor/ethers.umd.min.js` and `code/lib/forge-std` keep their own MIT / Apache-2.0 licences.
