#!/usr/bin/env python3
"""Builds every data figure of the paper (vector PDF) and LaTeX table snippets from results/*.json."""
import json
import math
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.join(os.path.dirname(__file__), "..")
RES = os.path.join(ROOT, "results")
FIG = os.environ.get("FIG_DIR", os.path.join(ROOT, "..", "paper", "figs"))
TAB = os.environ.get("TAB_DIR", os.path.join(ROOT, "..", "paper", "tables"))
os.makedirs(FIG, exist_ok=True)
os.makedirs(TAB, exist_ok=True)

# fixed categorical order (colour follows the scheme, never its rank); markers/linestyles as secondary encoding
COL = {"EpochCred": "#2a78d6", "PerCredential": "#eb6834", "BatchMerkle": "#1baf7a", "StatusList": "#eda100",
       "k1": "#e87ba4", "k5": "#6250d6", "full": "#008300", "opt": "#5f5e5a", "ref": "#8a8984", "B4": "#e34948"}
MK = {"EpochCred": "o", "PerCredential": "s", "BatchMerkle": "^", "StatusList": "D", "k1": "v", "k5": "P", "full": "X", "B4": "*"}
INK, INK2, GRID = "#1f1f1e", "#5f5e5a", "#e4e3df"

plt.rcParams.update({
    "font.family": "serif", "font.size": 8.5, "axes.titlesize": 9, "axes.labelsize": 8.5, "legend.fontsize": 7.5,
    "xtick.labelsize": 7.5, "ytick.labelsize": 7.5, "axes.edgecolor": INK2, "axes.labelcolor": INK, "text.color": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False, "lines.linewidth": 1.6, "lines.markersize": 4.5,
    "legend.frameon": False, "savefig.bbox": "tight", "savefig.pad_inches": 0.02, "pdf.fonttype": 42,
})
W1, W2 = 3.4, 7.0  # single / double column width (inches)


def load(name):
    return json.load(open(os.path.join(RES, name)))


def save(fig, name):
    fig.savefig(os.path.join(FIG, name))
    plt.close(fig)
    print("figure", name)


def tex(name, body):
    open(os.path.join(TAB, name), "w").write(body)
    print("table", name)


def fmt(x, nd=0):
    return f"{x:,.{nd}f}".replace(",", "{,}")


gas, ver, pol, dic, sec = load("gas.json"), load("verify.json"), load("policy.json"), load("dictionary.json"), load("security_tests.json")
rc = load("revocation_compare.json")

# ===================================================================== Fig: issuance gas per credential
iss = gas["issuance"]
B = np.array([r["B"] for r in iss])
fig, ax = plt.subplots(1, 2, figsize=(W2, 3.3))
series = [("PerCredential", "perCred_singleTx", "B1 per-credential (1 tx each)", "-"),
          ("PerCredential", "perCred_batchTx", "B1 per-credential (batched tx)", "--"),
          ("BatchMerkle", "batchMerkle", "B2 batch Merkle / B3 status list", "-"),
          ("B4", "singleSignerRoot", "B4 single-signer root registry", "-."),
          ("k1", "epochCred_k1", "EpochCred $k{=}1$", "-"),
          ("EpochCred", "epochCred_k3", "EpochCred $k{=}3$ (proposed)", "-"),
          ("k5", "epochCred_k5", "EpochCred $k{=}5$", "-"),
          ("full", "epochCred_k3_full", "EpochCred $k{=}3$, full storage (ablation)", ":")]
for c, key, lab, ls in series:
    ax[0].plot(B, [r[key] for r in iss], ls, color=COL[c], marker=MK.get(c, "o"), label=lab, ms=3.5)
ax[0].set_xscale("log", base=2); ax[0].set_yscale("log")
ax[0].set_xlabel("credentials per batch / epoch, $B$"); ax[0].set_ylabel("gas per credential")
ax[0].set_title("(a) Amortised issuance gas")
h_, l_ = ax[0].get_legend_handles_labels()
fig.tight_layout(rect=[0, 0.16, 1, 1])
fig.legend(h_, l_, loc="lower center", ncol=3, fontsize=6.8, bbox_to_anchor=(0.5, 0.0))
oc = load("offchain_costs.json")
tb = [r["B"] for r in oc["throughput"]]
ax[1].plot(tb, [r["creds_per_s"] for r in oc["throughput"]], "-", color=COL["EpochCred"], marker="o", label="EpochCred issuer (16 attributes, $k{=}3$)")
ax[1].set_ylim(bottom=0)
ax[1].set_xscale("log", base=2); ax[1].set_xlabel("credentials per epoch, $B$"); ax[1].set_ylabel("credentials / s (one core)")
ax[1].set_title("(b) Off-chain epoch construction throughput"); ax[1].legend(loc="lower right")
save(fig, "fig_issuance_gas.pdf")

# ===================================================================== Fig: threshold k
th = gas["threshold"]
ks = np.array([r["k"] for r in th]); gs = np.array([r["gas_steady"] for r in th]); g1st = np.array([r["gas_first"] for r in th])
a1, a0 = np.polyfit(ks, gs, 1)
fig, ax = plt.subplots(1, 2, figsize=(W2, 2.3))
ax[0].plot(ks, g1st / 1e3, "--", color=COL["k5"], marker="s", label="first epoch (cold storage)")
ax[0].plot(ks, gs / 1e3, "-", color=COL["EpochCred"], marker="o", label="steady state")
ax[0].plot(ks, (a0 + a1 * ks) / 1e3, ":", color=COL["ref"], label=f"fit: {a0/1e3:.1f}k + {a1/1e3:.2f}k$\\cdot k$")
ax[0].set_xlabel("quorum size $k$ (of $n{=}10$ officers)"); ax[0].set_ylabel("commitEpoch gas (×1000)")
ax[0].set_title("(a) On-chain cost of $k$-of-$n$ endorsement"); ax[0].legend()
sg = oc["signing"]
ax[1].fill_between([r["k"] for r in sg], [r["p05"] for r in sg], [r["p95"] for r in sg], color=COL["EpochCred"], alpha=0.15, lw=0, label="5–95th pct.")
ax[1].plot([r["k"] for r in sg], [r["median_ms"] for r in sg], "-", color=COL["EpochCred"], marker="o", label="EIP-712 signing, $k$ officers (median of 60)")
ax[1].set_ylim(bottom=0)
ax[1].set_xlabel("quorum size $k$"); ax[1].set_ylabel("time (ms)"); ax[1].set_title("(b) Off-chain endorsement time"); ax[1].legend(loc="upper left")
save(fig, "fig_threshold.pdf")

# ===================================================================== Fig: revocation
rv = gas["revocation"]
R = np.array([r["r"] for r in rv])
fig, ax = plt.subplots(1, 2, figsize=(W2, 3.2))
ax[0].plot(R, [r["perCred_total"] for r in rv], "-", color=COL["PerCredential"], marker="s", label="B1 per-credential flag")
ax[0].plot(R, [r["batchMerkle_total"] for r in rv], "-", color=COL["BatchMerkle"], marker="^", label="B2 revocation list")
ax[0].plot(R, [r["statusList_total"] for r in rv], "-", color=COL["StatusList"], marker="D", label="B3 on-chain bitstring, per index")
ax[0].plot(R, [r["statusListWords_total"] for r in rv], "--", color=COL["StatusList"], marker="d", label="B3* on-chain bitstring, word-grouped")
ax[0].plot(R, [r["singleSignerRoot_total"] for r in rv], "-.", color=COL["B4"], marker="*", label="B4 single-signer root (SMT or status list)")
ax[0].plot(R, [r["epochCred_total"] for r in rv], "-", color=COL["EpochCred"], marker="o", label="EpochCred quorum root, $k{=}3$")
ax[0].set_xscale("log"); ax[0].set_yscale("log"); ax[0].set_xlabel("revocations in one epoch, $r$"); ax[0].set_ylabel("total gas")
ax[0].set_title("(a) On-chain revocation cost")
ax[1].plot([r["smt_size"] for r in rv], [r["smt_update_ms"] for r in rv], "-", color=COL["EpochCred"], marker="o", label="SMT rebuild (depth 256)")
ax[1].set_xscale("log"); ax[1].set_yscale("log"); ax[1].set_xlabel("revoked nullifiers in tree"); ax[1].set_ylabel("time (ms)")
ax[1].set_title("(b) Off-chain revocation-tree update"); ax[1].legend()
h_, l_ = ax[0].get_legend_handles_labels()
fig.tight_layout(rect=[0, 0.2, 1, 1])
fig.legend(h_, l_, loc="lower center", ncol=3, fontsize=6.8, bbox_to_anchor=(0.5, 0.0))
save(fig, "fig_revocation.pdf")

# ===================================================================== Fig: verification
bB, bR = ver["byB"], ver["byR"]
fig, ax = plt.subplots(1, 3, figsize=(W2, 2.3))
xb = [r["B"] for r in bB]
for a_, rows, xs, xl in ((ax[0], bB, xb, "epoch size $B$ ($r{=}1024$)"), (ax[1], bR, [max(r["r"], 1) for r in bR], "revoked set size $r$ ($B{=}1024$)")):
    med = [r["verify_ms"]["median"] for r in rows]; lo = [r["verify_ms"]["p05"] for r in rows]; hi = [r["verify_ms"]["p95"] for r in rows]
    a_.fill_between(xs, lo, hi, color=COL["EpochCred"], alpha=0.15, lw=0, label="5–95th pct.")
    a_.plot(xs, med, "-", color=COL["EpochCred"], marker="o", label="verify (median)")
    pm = [r["present_ms"]["median"] for r in rows]
    a_.plot(xs, pm, "--", color=COL["k5"], marker="s", label="present (median)")
    a_.set_xscale("log", base=2); a_.set_xlabel(xl); a_.set_ylabel("time (ms)"); a_.set_ylim(bottom=0)
ax[0].set_title("(a) Latency vs. $B$"); ax[1].set_title("(b) Latency vs. $r$"); ax[0].legend(fontsize=6.6)
ax[2].plot([max(r["r"], 1) for r in bR], [r["onchain_gas"] / 1e3 for r in bR], "-", color=COL["EpochCred"], marker="o", label="EpochCred verifyAttribute")
for bl in ver["baselines"]:
    c = bl["scheme"]
    ax[2].axhline(bl["onchain_gas"] / 1e3, color=COL[c], ls="--", lw=1.1, label={"PerCredential": "B1", "BatchMerkle": "B2", "StatusList": "B3"}[c] + " verify")
ax[2].set_xscale("log", base=2); ax[2].set_xlabel("revoked set size $r$"); ax[2].set_ylabel("gas (×1000)")
ax[2].set_title("(c) On-chain verification gas"); ax[2].legend(fontsize=6.4); ax[2].set_ylim(bottom=0)
fig.tight_layout(w_pad=1.2)
save(fig, "fig_verification.pdf")

# ===================================================================== Fig: presentation size vs disclosed attributes
bD, ab = ver["byD"], ver["multiproofAblation"]
fig, ax = plt.subplots(1, 2, figsize=(W2, 2.3))
ds = [r["d"] for r in bD]
ax[0].plot(ds, [r["size_bytes"]["median"] for r in bD], "-", color=COL["EpochCred"], marker="o", label="EpochCred presentation")
for bl in ver["baselines"]:
    c = bl["scheme"]
    if c == "StatusList":
        continue
    ax[0].axhline(bl["size_bytes"]["median"], color=COL[c], ls="--", lw=1.1,
                  label={"PerCredential": "B1 full document (16 attr.)", "BatchMerkle": "B2/B3 document + path"}[c])
ax[0].set_xlabel("disclosed attributes $d$ (of 16)"); ax[0].set_ylabel("bytes"); ax[0].set_ylim(bottom=0)
ax[0].set_title("(a) Presentation size"); ax[0].legend(fontsize=6.6, loc="lower right")
ax[1].plot([r["d"] for r in ab], [r["independent_bytes"] for r in ab], "--", color=COL["ref"], marker="s", label="$d$ independent proofs")
ax[1].plot([r["d"] for r in ab], [r["multiproof_bytes"] for r in ab], "-", color=COL["EpochCred"], marker="o", label="compact multiproof (ours)")
ax[1].set_xlabel("disclosed attributes $d$"); ax[1].set_ylabel("attribute-proof bytes"); ax[1].set_title("(b) Multiproof ablation"); ax[1].legend()
save(fig, "fig_disclosure.pdf")

# ===================================================================== Fig: SMT siblings — exact expectation vs measurement
sd = load("smt_stats.json")
rs = np.array([r["r"] for r in sd]); emp = np.array([r["mean"] for r in sd]); ci = np.array([r["ci95"] for r in sd])


def exp_sib(r):
    return sum(1 - (1 - 2.0 ** -j) ** r for j in range(1, 257))


rr = np.unique(np.round(np.logspace(0, math.log10(rs.max()), 60)).astype(int))
hm = np.array([r["hashes_mean"] for r in sd]); hci = np.array([r["hashes_ci95"] for r in sd])
fig, ax = plt.subplots(figsize=(W1, 2.5))
ax.plot(rr, [exp_sib(x) for x in rr], "-", color=COL["EpochCred"], label="siblings, Prop. 1 (exact)")
ax.errorbar(rs, emp, yerr=ci, fmt="o", color=COL["EpochCred"], ms=3.5, capsize=2, label="siblings, measured")
ax.plot(rr, [exp_sib(x) + 1 for x in rr], "--", color=COL["PerCredential"], label="hashes, Prop. 2 (exact)")
ax.errorbar(rs, hm, yerr=hci, fmt="s", color=COL["PerCredential"], ms=3.5, capsize=2, label="hashes, measured")
ax.plot(rr, np.log2(rr), ":", color=COL["ref"], label="$\\log_2 r$")
ax.set_xscale("log", base=2); ax.set_xlabel("revoked nullifiers $r$"); ax.set_ylabel("count per non-membership proof")
ax.legend(loc="upper left", fontsize=6.6); ax.set_title("Communication vs. computation (membership: 256 hashes)")
save(fig, "fig_smt_siblings.pdf")

# ===================================================================== Fig: J(T) stationary validation
st = pol["stationary"]
T = np.array(st["T"])
fig, ax = plt.subplots(figsize=(W1, 2.3))
Tf = np.logspace(np.log10(T.min()), np.log10(T.max()), 200)
G = pol["gas_model"]["G"]; lam, mu = st["lam"], st["mu"]; w, rho = pol["params"]["w"], pol["params"]["rho"]
ax.plot(Tf, (G / Tf + (lam * w + mu * rho) * Tf / 2) / 1e3, "-", color=COL["EpochCred"], label="analytic $J(T)$")
ax.errorbar(T, np.array(st["sim_mean"]) / 1e3, yerr=np.array(st["sim_sd"]) / 1e3, fmt="s", color=COL["PerCredential"], ms=3.5, capsize=2, label="simulated (10 runs)")
ax.axvline(st["Tstar"], color=COL["ref"], ls=":", lw=1.1)
ax.annotate(f"$T^*={st['Tstar']:.2f}$ h", (st["Tstar"], st["Jstar"] / 1e3), xytext=(6, 22), textcoords="offset points", fontsize=7.5, color=INK2)
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("anchoring period $T$ (h)"); ax.set_ylabel("cost rate (×1000 gas-eq. / h)")
ax.set_title(f"Stationary workload, $\\lambda={lam:g}$/h"); ax.legend()
save(fig, "fig_cost_curve.pdf")

# ===================================================================== Fig: seasonal trace + policy comparison
tr = pol["trace"]; seas = pol["seasonal"]
fig, ax = plt.subplots(1, 2, figsize=(W2, 2.45), gridspec_kw={"width_ratios": [1.55, 1]})
arr = np.array(tr["arrivals_per_hour"]); hrs = np.arange(len(arr))
days = 14
m = hrs < days * 24
ax[0].bar(hrs[m] / 24, arr[m], width=1 / 24, color=COL["ref"], alpha=0.6, label="credential requests / h")
ax[0].set_yscale("symlog", linthresh=10)
ymax = max(arr[m].max(), 10) * 1.6
for name, y, c in (("APT", ymax * 1.5, COL["EpochCred"]), ("FixedT*", ymax * 4.0, COL["PerCredential"])):
    ts = [t / 24 for t in tr[name] if t < days * 24]
    ax[0].plot(ts, [y] * len(ts), "|", color=c, ms=7, mew=1.2, label={"APT": f"APT anchors ({len(ts)})", "FixedT*": f"fixed-$T^*$ anchors ({len(ts)})"}[name])
ax[0].set_xlabel("day"); ax[0].set_ylabel("requests / h (symlog)"); ax[0].set_title("(a) Seasonal workload and anchor times (first 14 days)")
ax[0].legend(loc="upper left", fontsize=6.4, ncol=1, bbox_to_anchor=(0.0, 1.0), framealpha=0.9); ax[0].set_ylim(0, ymax * 60)
summ = seas["summary"]
names = list(summ.keys())
vals = [summ[n]["total"]["mean"] / 1e6 for n in names]; err = [summ[n]["total"]["sd"] / 1e6 for n in names]
colors = [COL["PerCredential"], COL["StatusList"], COL["BatchMerkle"], COL["EpochCred"], COL["opt"]]
y = np.arange(len(names))
ax[1].barh(y, vals, xerr=err, color=colors, height=0.62, capsize=2, edgecolor="white", linewidth=1.5)
for i, (v, n) in enumerate(zip(vals, names)):
    ax[1].text(v * 1.08, i, f"{summ[n]['ratio_to_opt']['mean']:.2f}× opt", va="center", fontsize=6.8, color=INK2)
ax[1].set_yticks(y); ax[1].set_yticklabels(names, fontsize=7); ax[1].invert_yaxis(); ax[1].set_xscale("log")
ax[1].set_xlabel("total cost, 30 days (×10$^6$ gas-eq.)"); ax[1].set_title("(b) Policy cost (mean ± sd)"); ax[1].set_xlim(right=max(vals) * 4)
save(fig, "fig_policy.pdf")

# ===================================================================== Fig: T* landscape
tg = pol["tstar_grid"]
fig, ax = plt.subplots(figsize=(W1, 2.4))
Z = np.array(tg["Tstar"])
cs = ax.contourf(tg["lam"], tg["w"], Z, levels=[0, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16, 24.01], cmap="Blues_r")
cl = ax.contour(tg["lam"], tg["w"], Z, levels=[0.25, 1, 4, 16], colors="white", linewidths=0.7)
ax.clabel(cl, fmt=lambda v: f"{v:g} h", fontsize=6.5)
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("issuance rate $\\lambda$ (credentials / h)"); ax.set_ylabel("delay penalty $w$ (gas-eq. / cred·h)")
cb = fig.colorbar(cs, ax=ax); cb.set_label("$T^*$ (h), capped at $\\Delta$", fontsize=7.5); cb.ax.tick_params(labelsize=6.5)
ax.set_title("Optimal anchoring period $T^*$"); ax.grid(False)
save(fig, "fig_tstar.pdf")

# ===================================================================================== TABLES
d = gas["deploy"]
row = {r["B"]: r for r in iss}
r1024 = row.get(1024, iss[-1]); r1 = row[1]
rvm = {r["r"]: r for r in rv}
rlast = rv[-1]
onv = [x for x in ver['byR'] if x['r'] == 1024][0]['onchain_gas'] if any(x['r'] == 1024 for x in ver['byR']) else ver['byR'][-1]['onchain_gas']
tex("tab_gas_summary.tex", rf"""\begin{{tabular}}{{lrrrrr}}
\toprule
Operation & B1 Per-cred. & B2 Batch Merkle & B3 / B3$^\ast$ Status list & B4 Single-signer root & \textbf{{EpochCred}} ($k{{=}}3$)\\
\midrule
Deployment (gas) & {fmt(d['PerCredential'])} & {fmt(d['BatchMerkle'])} & {fmt(d['StatusList'])} & {fmt(d['SingleSignerRoot'])} & {fmt(d['EpochCred'])}\\
Issuer onboarding, $n{{=}}5$ (gas) & -- & -- & -- & -- & {fmt(d['registerIssuer_n5'])}\\
Issue 1 credential, steady state (gas/cred.) & {fmt(r1['perCred_singleTx'])} & {fmt(r1['batchMerkle'])} & {fmt(r1['statusList'])} & {fmt(r1['singleSignerRoot'])} & {fmt(r1['epochCred_k3'])}\\
Issue, $B{{=}}{r1024['B']}$, steady state (amortised gas/cred.) & {fmt(r1024['perCred_batchTx'])} & {fmt(r1024['batchMerkle'],1)} & {fmt(r1024['statusList'],1)} & {fmt(r1024['singleSignerRoot'],1)} & {fmt(r1024['epochCred_k3'],1)}\\
Revoke $r{{=}}1$, steady state (gas) & {fmt(rvm[1]['perCred_total'])} & {fmt(rvm[1]['batchMerkle_total'])} & {fmt(rvm[1]['statusList_total'])} / {fmt(rvm[1]['statusListWords_total'])} & {fmt(rvm[1]['singleSignerRoot_total'])} & {fmt(rvm[1]['epochCred_total'])}\\
Revoke $r{{=}}{rlast['r']}$ (gas, total) & {fmt(rlast['perCred_total'])} & {fmt(rlast['batchMerkle_total'])} & {fmt(rlast['statusList_total'])} / {fmt(rlast['statusListWords_total'])} & {fmt(rlast['singleSignerRoot_total'])} & {fmt(rlast['epochCred_total'])}\\
Verify on-chain (gas) & {fmt(ver['baselines'][0]['onchain_gas'])} & {fmt(ver['baselines'][1]['onchain_gas'])} & {fmt(ver['baselines'][2]['onchain_gas'])} & see \cref{{tab:revcmp}} & {fmt(onv)}\\
Attributes revealed to verifier & 16/16 & 16/16 & 16/16 & $d$/16 & $d$/16\\
Independent signers per write & 1 & 1 & 1 & 1 & $k$ of $n$\\
Rollback of revocation detectable on chain & n/a & no & no & no & yes (fraud proof)\\
\bottomrule
\end{{tabular}}
""")


# per-epoch transaction gas by epoch type (reviewer request: never mix first and steady-state epochs)
iss1024 = r1024
def ov(a, b):
    return f"{fmt(a - b)} ({100 * (a - b) / b:.1f}\\%)"
k1_rev = rlast.get("epochCred_k1_total", float("nan"))
tex("tab_epochs.tex", rf"""\begin{{tabular}}{{lrrrrr}}
\toprule
Commitment transaction (gas) & B4 single signer & \sys{{}} $k{{=}}1$ & \sys{{}} $k{{=}}3$ & \sys{{}} $k{{=}}5$ & \sys{{}} $k{{=}}3$ full storage\\
\midrule
First epoch of an issuer, $B{{=}}{iss1024['B']}$ & {fmt(iss1024['singleSignerRoot_first_txGas'])} & {fmt(iss1024['epochCred_k1_first_txGas'])} & {fmt(iss1024['epochCred_k3_first_txGas'])} & {fmt(iss1024['epochCred_k5_first_txGas'])} & {fmt(iss1024['epochCred_k3_full_first_txGas'])}\\
Subsequent issuance epoch, $B{{=}}{iss1024['B']}$ & {fmt(iss1024['singleSignerRoot_txGas'])} & {fmt(iss1024['epochCred_k1_txGas'])} & {fmt(iss1024['epochCred_k3_txGas'])} & {fmt(iss1024['epochCred_k5_txGas'])} & {fmt(iss1024['epochCred_k3_full_txGas'])}\\
Revocation-only epoch ($r{{=}}{rlast['r']}$) & {fmt(rlast['singleSignerRoot_total'])} & {fmt(k1_rev)} & {fmt(rlast['epochCred_total'])} & -- & --\\
\midrule
\multicolumn{{6}}{{l}}{{Differences between subsequent issuance epochs (same epoch type, same $B$):}}\\
\multicolumn{{3}}{{l}}{{\quad \sys{{}} $k{{=}}1$ vs.\ B4 (ECDSA authorisation, EIP-712 hashing, event)}} & \multicolumn{{3}}{{r}}{{{ov(iss1024['epochCred_k1_txGas'], iss1024['singleSignerRoot_txGas'])}}}\\
\multicolumn{{3}}{{l}}{{\quad \sys{{}} $k{{=}}3$ vs.\ $k{{=}}1$ (two more signatures)}} & \multicolumn{{3}}{{r}}{{{ov(iss1024['epochCred_k3_txGas'], iss1024['epochCred_k1_txGas'])}}}\\
\multicolumn{{3}}{{l}}{{\quad \sys{{}} $k{{=}}3$ vs.\ B4 (whole quorum overhead)}} & \multicolumn{{3}}{{r}}{{{ov(iss1024['epochCred_k3_txGas'], iss1024['singleSignerRoot_txGas'])}}}\\
\bottomrule
\end{{tabular}}
""")


# ETH cost per 1000 credentials (+ 10 revocations) at assumed gas prices
import math
def sig3(x):
    return f"{x:.{max(0, 2 - math.floor(math.log10(x)))}f}"
prices = [0.05, 1, 10, 30]
lines = []
for name, per1000 in (("B1 per-credential, 1 tx each", 1000 * r1["perCred_singleTx"] + 10 * rvm.get(1, rv[0])["perCred_total"]),
                      ("B1 per-credential, batched", 1000 * r1024["perCred_batchTx"] + 10 * rvm.get(1, rv[0])["perCred_total"]),
                      ("B2 batch Merkle (1 batch)", 1000 * r1024["batchMerkle"] + 10 * rvm.get(1, rv[0])["batchMerkle_total"]),
                      ("EpochCred $k{=}3$ (1 epoch)", r1024["epochCred_k3_txGas"])):
    lines.append(f"{name} & {fmt(per1000)} & " + " & ".join(sig3(per1000 * p * 1e-9) for p in prices) + r"\\")
tex("tab_cost_eth.tex", r"""\begin{tabular}{lrrrrr}
\toprule
 & & \multicolumn{4}{c}{ETH at an assumed gas price of} \\ \cmidrule(l){3-6}
Scheme & Gas & 0.05 gwei & 1 gwei & 10 gwei & 30 gwei\\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
""")

# verification latency summary
def vrow(lbl, r):
    return f"{lbl} & {r['verify_ms']['median']:.2f} & {r['verify_ms']['p95']:.2f} & {r['present_ms']['median']:.2f} & {r['rpc_ms']['median']:.2f} & {int(r['size_bytes']['median'])} & {r['smt_siblings']['mean']:.1f}\\\\"
lines = [vrow(f"$B{{=}}{r['B']}$, $r{{=}}1024$, $d{{=}}3$", r) for r in bB] + [r"\midrule"] + [vrow(f"$B{{=}}1024$, $r{{=}}{r['r']}$, $d{{=}}3$", r) for r in bR]
tex("tab_verify.tex", r"""\begin{tabular}{lrrrrrr}
\toprule
Configuration & \multicolumn{2}{c}{Verify (ms)} & Present & RPC reads & Size & SMT \\ \cmidrule(lr){2-3}
 & median & p95 & (ms) & (ms) & (B) & siblings\\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
""")

# baselines verification
lines = []
for bl in ver["baselines"]:
    nm = {"PerCredential": "B1 per-credential", "BatchMerkle": "B2 batch Merkle", "StatusList": "B3 status list"}[bl["scheme"]]
    lines.append(f"{nm} & {bl['crypto_ms']['median']:.3f} & {int(bl['size_bytes']['median'])} & 16/16 & {fmt(bl['onchain_gas'])}\\\\")
ref = [x for x in bD if x["d"] == 4][0] if any(x["d"] == 4 for x in bD) else bD[0]
lines.append(f"EpochCred ($d{{=}}4$) & {ref['verify_ms']['median']:.3f} & {int(ref['size_bytes']['median'])} & 4/16 & {fmt(onv)}\\\\")  # B=1024, r=1024, as in the caption
tex("tab_baseline_verify.tex", r"""\begin{tabular}{lrrrr}
\toprule
Scheme & Local check (ms) & Bytes sent & Attributes revealed & On-chain verify (gas)\\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
""")

# dictionary attack
lines = []
for r in dic:
    lines.append(f"\\texttt{{{r['attribute']}}} & {fmt(r['dictionarySize'])} & {r['entropyBits']:.1f} & {r['unsalted_recovered']}/{r['targets']} & {r['unsalted_table_ms']:.1f} & {r['salted_recovered']}/{fmt(r['salted_trials'])}\\\\")
tex("tab_dictionary.tex", r"""\begin{tabular}{lrrrrr}
\toprule
Attribute & Candidates & Entropy & \multicolumn{2}{c}{Unsalted field hashes} & Salted (ours)\\ \cmidrule(lr){4-5}
 & & (bits) & recovered & time (ms) & hits / trials (20 targets)\\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
""")

# policy
lines = []
for n in names:
    s = summ[n]
    lat = s.get("mean_latency_h", {"mean": float("nan")})["mean"]
    latstr = "--" if n == "Offline optimum" else ("$\\approx 0$" if n == "Immediate" else f"{lat:.2f}")
    lines.append(f"{n} & {fmt(s['anchors']['mean'])} & {s['anchor_gas']['mean']/1e6:.2f} & {s['penalty']['mean']/1e6:.2f} & {s['total']['mean']/1e6:.2f} $\\pm$ {s['total']['sd']/1e6:.2f} & {s['ratio_to_opt']['mean']:.3f} & {s['ratio_to_opt']['max']:.3f} & {latstr}\\\\")
tex("tab_policy.tex", r"""\begin{tabular}{lrrrrrrr}
\toprule
Policy & Anchors & Anchor gas & Penalty & Total & \multicolumn{2}{c}{Ratio to OPT} & Mean wait\\ \cmidrule(lr){6-7}
 & & ($10^6$) & ($10^6$) & ($10^6$ gas-eq.) & mean & max & (h)\\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
""")

# security tests
lines = []
for t_ in sec:
    ok = r"\cmark" if t_["pass"] else r"\xmark"
    kind = "A" if t_.get("kind", "attack") == "attack" else "C"
    lines.append(f"{t_['id']} & {kind} & {t_['name']} & {t_['threat']} & {t_['expected']} & {ok}\\\\")
tex("tab_security.tex", r"""\begin{tabular}{p{0.55cm}p{0.3cm}p{7.3cm}p{4.5cm}p{1.6cm}c}
\toprule
ID & & Check (A = attack, C = correctness / documented behaviour) & Threat / property & Expected & Pass\\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
""")



# revocation structure comparison
lines = []
for row in rc["rows"]:
    s_, l_ = row["smt"], row["statusList"]
    lines.append(f"{fmt(row['r'])} & {s_.get('proof_bytes_mean', s_['proof_bytes']):.1f} / {int(s_['proof_bytes'])} & {s_['mean_hashes_nonmember']:.1f} & {s_['check_ms']*1000:.0f} & {fmt(s_['onchain_check_gas'])} & {int(l_['proof_bytes'])} & {int(l_['hashes'])} & {l_['check_ms']*1000:.0f} & {fmt(l_['onchain_check_gas'])}\\\\")
tex("tab_revcompare.tex", r"""\begin{tabular}{rrrrrrrrr}
\toprule
 & \multicolumn{4}{c}{Nullifier SMT (EpochCred)} & \multicolumn{4}{c}{Root-anchored status list (131{,}072 entries)}\\ \cmidrule(lr){2-5}\cmidrule(lr){6-9}
Revoked $r$ & bytes (mean / median) & mean hashes & check ($\mu$s, median) & on-chain gas & bytes & hashes & check ($\mu$s, median) & on-chain gas\\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
""")

# implementation effects (ticks, delay)
lines = [f"{r['tick_min']} & {r['delay_min']} & {r['apt_overshoot_mean']:.2f} / {r['apt_overshoot_max']:.2f} & {r['apt_ratio']:.3f} & {r['fixed_ratio']:.3f} & {r['apt_rev_mean_h']:.2f} / {r['apt_rev_p95_h']:.2f} / {r['apt_rev_max_h']:.2f} & {r['fixed_rev_mean_h']:.2f} / {r['fixed_rev_p95_h']:.2f} / {r['fixed_rev_max_h']:.2f} & {r.get('apt_max_final_age_h', float('nan')):.1f} & {r.get('apt_blocked', 0):.0f}\\\\" for r in pol["impl"]]
tex("tab_impl.tex", r"""\begin{tabular}{rrrrrrrrr}
\toprule
Tick & Delay & APT overshoot $1{+}\varepsilon$ & \multicolumn{2}{c}{Cost ratio to OPT} & \multicolumn{2}{c}{Revocation request $\rightarrow$ final (h): mean / p95 / max} & Max age & Deferred\\ \cmidrule(lr){4-5}\cmidrule(lr){6-7}
(min) & (min) & mean / max & APT & fixed $T^\ast$ & APT & fixed $T^\ast$ & of final (h) & triggers\\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
""")

# w-sensitivity
lines = [f"{fmt(r['w'])} & {r['T_fixed']:.2f} & {r['apt_mean']:.3f} / {r['apt_max']:.3f} & {r['fixed_mean']:.3f} / {r['fixed_max']:.3f}\\\\" for r in pol["w_sweep"]]
tex("tab_wsweep.tex", r"""\begin{tabular}{rrrr}
\toprule
$w$ (gas-eq./cred$\cdot$h) & fixed $T^\ast$ (h) & APT & Fixed $T^\ast$\\
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
""")

# numbers used inline in the text
gm = pol["gas_model"]
rc1024 = [x for x in rc["rows"] if x["r"] == 1024][0] if any(x["r"] == 1024 for x in rc["rows"]) else rc["rows"][-1]
bk = {r["step"]: r["median_ms"] for r in load("breakdown.json")}
macros = {
    "gZero": fmt(gm["g0"]), "gOne": fmt(gm["g1"]), "gRsq": f"{gm['r2']:.4f}", "Gthree": fmt(gm["G"]),
    "TstarStat": f"{st['Tstar']:.2f}", "secPass": str(sum(t['pass'] for t in sec)), "secTotal": str(len(sec)),
    "aptRatio": f"{summ['APT (adaptive)']['ratio_to_opt']['mean']:.2f}", "aptRatioMax": f"{summ['APT (adaptive)']['ratio_to_opt']['max']:.2f}",
    "fixRatio": f"{[summ[n] for n in names if n.startswith('Fixed T')][0]['ratio_to_opt']['mean']:.2f}",
    "dayRatio": f"{summ['Fixed 24 h']['ratio_to_opt']['mean']:.2f}", "immRatio": f"{summ['Immediate']['ratio_to_opt']['mean']:.1f}",
    "verMedK": f"{[x for x in bB if x['B']==1024][0]['verify_ms']['median']:.2f}" if any(x['B']==1024 for x in bB) else "",
    "issPerCredK": fmt(r1024["epochCred_k3"], 1), "issPerCredOne": fmt(r1["perCred_singleTx"]), "perCredBatch": fmt(r1024["perCred_batchTx"]),
    "revEpoch": fmt(rlast["epochCred_total"]), "revB": fmt(rlast["batchMerkle_total"]), "revA": fmt(rlast["perCred_total"]), "revC": fmt(rlast["statusList_total"]), "rMax": fmt(rlast["r"]),
    "maxB": fmt(iss[-1]["B"]), "issMaxB": fmt(iss[-1]["epochCred_k3"], 1), "cpu": ver["meta"]["cpu"].replace("(R)", "").replace("@", "at"),
    "nodeVer": ver["meta"]["node"], "brkSig": f"{bk['holder signature recovery']:.2f}", "brkSmt": f"{bk['SMT non-membership (256 levels)']:.2f}",
    "brkRest": f"{bk['record digests (2)'] + bk['attribute leaves + multiproof'] + bk['credential leaf + issuance path']:.2f}",
    "smtAll": str(sum(r['withinCI'] for r in sd)), "smtN": str(len(sd)), "hashAll": str(sum(r['hashesWithinCI'] for r in sd)),
    "secAttacks": str(sum(1 for t_ in sec if t_.get('kind') == 'attack')), "secValid": str(sum(1 for t_ in sec if t_.get('kind') != 'attack')),
    "revCopt": fmt(rlast["statusListWords_total"]), "wordsTouched": str(rlast["words_touched"]), "revBfour": fmt(rlast["singleSignerRoot_total"]),
    "quorumOverhead": fmt(r1024["epochCred_k3_txGas"] - r1024["singleSignerRoot_txGas"]),
    "quorumOverheadPct": f"{100 * (r1024['epochCred_k3_txGas'] - r1024['singleSignerRoot_txGas']) / r1024['singleSignerRoot_txGas']:.0f}",
    "kThreeOverKOnePct": f"{100 * (r1024['epochCred_k3_txGas'] - r1024['epochCred_k1_txGas']) / r1024['epochCred_k1_txGas']:.0f}",
    "kOneOverBfour": fmt(r1024["epochCred_k1_txGas"] - r1024["singleSignerRoot_txGas"]),
    "firstEpochKThree": fmt(r1024["epochCred_k3_first_txGas"]), "steadyEpochKThree": fmt(r1024["epochCred_k3_txGas"]),
    "steadyEpochBfour": fmt(r1024["singleSignerRoot_txGas"]),
    "implMaxAge": f"{max(r.get('apt_max_final_age_h', 0) for r in pol['impl']):.1f}",
    "fraudGenMs": f"{rc['fraud'][-1].get('proof_gen_ms', 0):.0f}",
    "smtCheckGas": fmt(rc1024["smt"]["onchain_check_gas"]), "slCheckGas": fmt(rc1024["statusList"]["onchain_check_gas"]),
    "smtProofBytes": str(int(rc1024["smt"]["proof_bytes"])), "smtProofBytesMean": f"{rc1024['smt'].get('proof_bytes_mean', rc1024['smt']['proof_bytes']):.0f}",
    "smtProofBytesExp": f"{32 * (sum(1 - (1 - 2.0 ** -j) ** rc1024['r'] for j in range(1, 257)) + 1):.0f}", "slProofBytes": str(int(rc1024["statusList"]["proof_bytes"])),
    "fraudGas": fmt(rc["fraud"][-1]["gas"]), "fraudR": fmt(rc["fraud"][-1]["r"]), "gResid": fmt(max(abs(gs - (a0 + a1 * ks)))),
    "onchainVerify": fmt(onv),
    "smtNaiveGas": fmt(rc1024["smt"].get("onchain_check_gas_naive", 0)),
    "rpcMs": f"{[x for x in ver['byB'] if x['B'] == 1024][0]['rpc_ms']['median']:.0f}" if any(x['B'] == 1024 for x in ver['byB']) else f"{ver['byB'][-1]['rpc_ms']['median']:.0f}",
    "dictMin": f"{min(r['unsalted_table_ms'] for r in dic):.1f}", "dictMax": f"{max(r['unsalted_table_ms'] for r in dic):.0f}",
    "dictTrials": f"{sum(r['salted_trials'] for r in dic)/1e6:.2f}",
    "firstEpochExtra": f"{(th[2]['gas_first'] - th[2]['gas_steady'])/1000:.0f}",
    "thrRate": fmt(np.median([r["creds_per_s"] for r in oc["throughput"] if r["B"] >= 1024]), 0),
    "thrBig": f"{max(r['B'] for r in oc['throughput'])/ max(1, [r['creds_per_s'] for r in oc['throughput'] if r['B']==max(x['B'] for x in oc['throughput'])][0]):.0f}",
    "implRatioSixty": f"{max(r['apt_ratio'] for r in pol['impl']):.2f}", "implOvershootSixty": f"{max(r['apt_overshoot_max'] for r in pol['impl']):.2f}",
    "aptRevP": f"{[r for r in pol['impl'] if r['tick_min']==10 and r['delay_min']==15][0]['apt_rev_p95_h']:.2f}",
    "fixRevP": f"{[r for r in pol['impl'] if r['tick_min']==10 and r['delay_min']==15][0]['fixed_rev_p95_h']:.2f}", "samples": str(ver["meta"]["samples"]),
}
tex("numbers.tex", "\n".join(f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in macros.items()) + "\n")
