#!/usr/bin/env python3
"""E8: cost-freshness optimal anchoring (Section 4.5 / 7.6).

Uses the MEASURED gas model G(k) = g0 + g1*k (steady-state commitEpoch gas, results/gas.json) and compares
anchoring policies on stationary and seasonal (convocation-burst) workloads:
  P1 immediate (one anchor per event)   P2 fixed daily      P3 fixed T* (analytic, average rates)
  P4 APT adaptive (proposed)            P5 offline optimum (dynamic programme, hindsight lower bound)
All costs are expressed in gas-equivalent units, so the result is independent of the gas price.
"""
import json
import os
import sys

import numpy as np

ROOT = os.path.join(os.path.dirname(__file__), "..")
RES = os.path.join(ROOT, "results")


def gas_model():
    g = json.load(open(os.path.join(RES, "gas.json")))
    ks = np.array([r["k"] for r in g["threshold"]], float)
    gs = np.array([r["gas_steady"] for r in g["threshold"]], float)
    g1, g0 = np.polyfit(ks, gs, 1)
    pred = g0 + g1 * ks
    r2 = 1 - ((gs - pred) ** 2).sum() / ((gs - gs.mean()) ** 2).sum()
    return float(g0), float(g1), float(r2)


# ------------------------------------------------------------------ workload generation (bins of DT hours)
DT = 1 / 6  # 10-minute bins
HORIZON_H = 30 * 24
NB = int(HORIZON_H / DT)


def seasonal_rates():
    t = np.arange(NB) * DT
    lam = np.full(NB, 2.0)  # background issuance: 2 credentials / hour
    day = t / 24.0
    work = ((day % 7) < 5) & ((t % 24) >= 9) & ((t % 24) < 17)
    lam[work] = 8.0  # office hours on weekdays
    for d0 in (9, 23):  # two convocation days: 6-hour bursts of 300 credentials / hour
        burst = (t >= d0 * 24 + 10) & (t < d0 * 24 + 16)
        lam[burst] = 300.0
    mu = np.full(NB, 0.05)  # revocations / hour
    return lam, mu


def sample(lam, mu, rng, emergencies=2):
    a = rng.poisson(lam * DT)  # issuance arrivals per bin
    r = rng.poisson(mu * DT)  # ordinary revocations per bin
    emerg = np.zeros(NB, bool)
    emerg[rng.choice(NB, emergencies, replace=False)] = True  # e.g. fraud discovered: revoke immediately
    return a, r, emerg


# ------------------------------------------------------------------ policies
def run_policy(kind, a, r, emerg, G, w, rho, delta_h, T=None, tick=1, delay_h=0.0):
    """simulate on the bin grid; arrivals assumed at bin centre; returns dict of metrics.

    Daemon semantics (stated in the paper, Prop. 3): items are assigned to the batch that is open when a commitment
    is TRIGGERED; a triggered commitment becomes final exactly delay_h later; at most ONE commitment is in flight, so a
    trigger (threshold, heartbeat or emergency) that occurs while one is in flight waits until it is final; the
    heartbeat fires when the time since the last TRIGGER reaches delta_h, which keeps the age of the latest FINAL
    commitment <= delta_h for a constant delay; at the horizon every pending item is flushed by a final commitment
    (the same convention as the offline optimum)."""
    pend_w = 0.0  # pending weighted count (w*n_issue + rho*n_rev)
    pend_age_cost = 0.0
    anchors = 0
    penalty = 0.0
    last = 0
    lat_num = 0.0
    lat_cnt = 0
    pend_issue_times = []
    pend_rev_times = []
    min_gap = int(np.ceil(delay_h / DT - 1e-9)) if kind in ("apt", "fixed") else 0
    emerg_pending = False
    triggers = []
    blocked = 0
    rev_exposure = []  # request -> commitment finalised (hours), ordinary revocations
    overshoot = []  # accrued penalty / G at threshold-triggered APT commitments
    for i in range(NB):
        # accrue penalty for already-pending items over this bin
        penalty += pend_w * DT
        pend_age_cost += pend_w * DT
        # new arrivals (enter at bin centre -> half-bin penalty)
        nw = w * a[i] + rho * r[i]
        penalty += nw * DT / 2
        pend_age_cost += nw * DT / 2
        pend_w += nw
        if a[i]:
            pend_issue_times.append((i, a[i]))
        if r[i]:
            pend_rev_times.append((i, r[i]))
        anchor = False
        if emerg[i] or emerg_pending:
            anchor = True
        elif kind == "immediate":
            anchor = (a[i] + r[i]) > 0
        elif kind == "fixed":
            anchor = (i + 1) % max(1, int(round(T / DT))) == 0
        elif kind == "apt":
            anchor = ((i + 1) % tick == 0) and pend_age_cost >= G
            if anchor:
                overshoot.append(pend_age_cost / G)
        if (i + 1 - last) * DT >= delta_h - 1e-9:
            anchor = True  # heartbeat: keep the revocation root fresher than the verifiers' bound
        if anchor and min_gap and triggers and (i + 1 - last) < min_gap:
            # one commitment already in flight: wait until it is final
            emerg_pending = emerg_pending or bool(emerg[i])
            blocked += 1
            anchor = False
        if anchor:
            emerg_pending = False
            triggers.append((i + 1) * DT)
            if kind == "immediate" and not emerg[i]:
                anchors += int(a[i] + r[i]) if (a[i] + r[i]) > 0 else 1
            else:
                anchors += 1
            for (j, n) in pend_issue_times:
                lat_num += n * ((i - j) + 0.5) * DT
                lat_cnt += n
            pend_issue_times = []
            for (j, n) in pend_rev_times:
                rev_exposure.extend([((i - j) + 0.5) * DT + delay_h] * int(n))
            pend_rev_times = []
            pend_w = 0.0
            pend_age_cost = 0.0
            last = i + 1
    if pend_w > 0 and kind != "immediate":  # terminal flush at the horizon (same convention as offline_opt)
        anchors += 1
        for (j, n) in pend_rev_times:
            rev_exposure.extend([((NB - 1 - j) + 0.5) * DT + delay_h] * int(n))
        triggers.append(NB * DT)
    gaps = np.diff([0.0] + triggers) if triggers else np.array([0.0])
    if kind == "immediate":  # each event anchored in its own tx -> essentially no waiting
        penalty = 0.0
        lat_num = 0.0
        rev_exposure = [delay_h] * int(r.sum())
    # every commitment (any policy, including OPT) is finalised delay_h after it is triggered:
    penalty += delay_h * float(w * a.sum() + rho * r.sum())
    ex = np.array(rev_exposure) if rev_exposure else np.zeros(1)
    return dict(anchors=anchors, anchor_gas=anchors * G, penalty=penalty, total=anchors * G + penalty,
                mean_latency_h=lat_num / max(lat_cnt, 1) + delay_h,
                rev_exposure_mean_h=float(ex.mean()), rev_exposure_p95_h=float(np.percentile(ex, 95)), rev_exposure_max_h=float(ex.max()),
                overshoot_mean=float(np.mean(overshoot)) if overshoot else 1.0, overshoot_max=float(np.max(overshoot)) if overshoot else 1.0,
                max_trigger_gap_h=float(gaps.max()), blocked_triggers=blocked)


def offline_opt(a, r, emerg, G, w, rho, delta_h, delay_h=0.0):
    """hindsight-optimal anchor schedule by DP over bins (anchors at bin ends)."""
    W = int(round(delta_h / DT))
    wt = w * a + rho * r  # weight per bin
    t_mid = (np.arange(NB) + 0.5) * DT
    S0 = np.concatenate([[0], np.cumsum(wt)])
    S1 = np.concatenate([[0], np.cumsum(wt * t_mid)])
    emerg_idx = np.concatenate([[0], np.cumsum(emerg.astype(int))])
    f = np.full(NB + 1, np.inf)
    f[0] = 0.0
    arg = np.zeros(NB + 1, int)
    for j in range(1, NB + 1):
        lo = max(0, j - W)
        i = np.arange(lo, j)
        tj = j * DT
        pen = (S0[j] - S0[i]) * tj - (S1[j] - S1[i])
        # an emergency in bins [i, j-2] would be skipped -> forbidden (it must be anchored in its own bin)
        bad = (emerg_idx[j - 1] - emerg_idx[i]) > 0
        cost = f[i] + G + pen
        cost[bad] = np.inf
        k = int(np.argmin(cost))
        f[j] = cost[k]
        arg[j] = i[k]
    n, j = 0, NB
    while j > 0:
        j = arg[j]
        n += 1
    extra = delay_h * float(w * a.sum() + rho * r.sum())
    return dict(anchors=n, anchor_gas=n * G, penalty=f[NB] - n * G + extra, total=float(f[NB]) + extra)


def main(quick=False):
    g0, g1, r2 = gas_model()
    k = 3
    G = g0 + g1 * k
    out = dict(gas_model=dict(g0=g0, g1=g1, r2=r2, k=k, G=G))
    w, rho = 1000.0, 50000.0  # gas-equivalent penalty per credential-hour / per revoked-credential-hour
    delta = 24.0
    out["params"] = dict(w=w, rho=rho, delta_h=delta, horizon_h=HORIZON_H, bin_h=DT)

    # ---- (a) stationary validation of J(T) = G/T + (lam w + mu rho) T/2
    lam0, mu0 = 20.0, 0.05
    Ts = np.array([1 / 6, 1 / 3, 0.5, 2 / 3, 1, 1.5, 2, 3, 4, 6, 8, 12, 16, 24])  # multiples of the 10-min bin
    rng = np.random.default_rng(1)
    lam_v = np.full(NB, lam0)
    mu_v = np.full(NB, mu0)
    sims = []
    for T in Ts:
        vals = []
        for s in range(3 if quick else 10):
            a, rr, _ = sample(lam_v, mu_v, rng, emergencies=0)
            em = np.zeros(NB, bool)
            m = run_policy("fixed", a, rr, em, G, w, rho, 1e9, T=T)
            vals.append(m["total"] / HORIZON_H)
        sims.append((float(np.mean(vals)), float(np.std(vals))))
    Tstar = float(np.sqrt(2 * G / (lam0 * w + mu0 * rho)))
    out["stationary"] = dict(lam=lam0, mu=mu0, T=Ts.tolist(), sim_mean=[s[0] for s in sims], sim_sd=[s[1] for s in sims],
                             analytic=[float(G / T + (lam0 * w + mu0 * rho) * T / 2) for T in Ts], Tstar=Tstar,
                             Jstar=float(np.sqrt(2 * G * (lam0 * w + mu0 * rho))))
    print(f"G={G:.0f} gas (g0={g0:.0f}, g1={g1:.0f}, R2={r2:.5f}); T*={Tstar:.3f} h")

    # ---- (b) T* landscape
    lams = np.logspace(-1, 3, 41)
    ws = np.logspace(1, 5, 41)
    out["tstar_grid"] = dict(lam=lams.tolist(), w=ws.tolist(),
                             Tstar=[[float(min(np.sqrt(2 * G / (l * ww + mu0 * rho)), delta)) for l in lams] for ww in ws])

    # ---- (c) seasonal workload: policy comparison over seeds
    lam, mu = seasonal_rates()
    lam_bar, mu_bar = lam.mean(), mu.mean()
    T_avg = float(np.sqrt(2 * G / (lam_bar * w + mu_bar * rho)))
    T_avg_bin = max(DT, round(T_avg / DT) * DT)
    seeds = 5 if quick else 20
    pols = {"Immediate": [], "Fixed 24 h": [], f"Fixed T*={T_avg_bin:.2f} h": [], "APT (adaptive)": [], "Offline optimum": []}
    for s in range(seeds):
        rng = np.random.default_rng(100 + s)
        a, rr, em = sample(lam, mu, rng)
        pols["Immediate"].append(run_policy("immediate", a, rr, em, G, w, rho, delta))
        pols["Fixed 24 h"].append(run_policy("fixed", a, rr, em, G, w, rho, delta, T=24.0))
        pols[f"Fixed T*={T_avg_bin:.2f} h"].append(run_policy("fixed", a, rr, em, G, w, rho, delta, T=T_avg_bin))
        pols["APT (adaptive)"].append(run_policy("apt", a, rr, em, G, w, rho, delta))
        pols["Offline optimum"].append(offline_opt(a, rr, em, G, w, rho, delta))
        print("seed", s, {k_: round(v[-1]["total"] / 1e6, 2) for k_, v in pols.items()})
    summ = {}
    for name, rows in pols.items():
        summ[name] = {m: dict(mean=float(np.mean([r_[m] for r_ in rows])), sd=float(np.std([r_[m] for r_ in rows])))
                      for m in rows[0].keys()}
    opt = np.array([r_["total"] for r_ in pols["Offline optimum"]])
    for name, rows in pols.items():
        ratio = np.array([r_["total"] for r_ in rows]) / opt
        summ[name]["ratio_to_opt"] = dict(mean=float(ratio.mean()), max=float(ratio.max()))
    out["seasonal"] = dict(lam_mean=float(lam_bar), mu_mean=float(mu_bar), T_avg=T_avg, seeds=seeds, summary=summ,
                           rate_profile=lam[: int(14 * 24 / DT)].tolist())

    # ---- (c2) robustness: competitive ratio of APT vs fixed-T* across delay penalties w
    sweep = []
    for w_ in (100.0, 300.0, 1000.0, 3000.0, 10000.0):
        Tw = float(np.sqrt(2 * G / (lam_bar * w_ + mu_bar * rho)))
        Twb = min(delta, max(DT, round(Tw / DT) * DT))
        ra, rf = [], []
        for s in range(3 if quick else 8):
            rng = np.random.default_rng(500 + s)
            a, rr, em = sample(lam, mu, rng)
            o = offline_opt(a, rr, em, G, w_, rho, delta)["total"]
            ra.append(run_policy("apt", a, rr, em, G, w_, rho, delta)["total"] / o)
            rf.append(run_policy("fixed", a, rr, em, G, w_, rho, delta, T=Twb)["total"] / o)
        sweep.append(dict(w=w_, T_fixed=Twb, apt_mean=float(np.mean(ra)), apt_max=float(np.max(ra)),
                          fixed_mean=float(np.mean(rf)), fixed_max=float(np.max(rf))))
        print("w", w_, sweep[-1])
    out["w_sweep"] = sweep

    # ---- (c3) implementation effects: decision tick (overshoot) and commit/finality delay
    impl = []
    T_star_bin = T_avg_bin
    for tick_bins in (1, 3, 6):
        for d in (0.0, 0.25):
            rows = dict(apt=[], fixed=[], ratio_apt=[], ratio_fixed=[])
            for s in range(3 if quick else 8):
                rng = np.random.default_rng(900 + s)
                a, rr, em = sample(lam, mu, rng)
                o = offline_opt(a, rr, em, G, w, rho, delta, delay_h=d)["total"]
                ra = run_policy("apt", a, rr, em, G, w, rho, delta, tick=tick_bins, delay_h=d)
                rf = run_policy("fixed", a, rr, em, G, w, rho, delta, T=T_star_bin, delay_h=d)
                rows["apt"].append(ra); rows["fixed"].append(rf)
                rows["ratio_apt"].append(ra["total"] / o); rows["ratio_fixed"].append(rf["total"] / o)
            m = lambda key, pol: float(np.mean([x[key] for x in rows[pol]]))
            impl.append(dict(tick_min=int(round(tick_bins * DT * 60)), delay_min=int(round(d * 60)),
                             apt_ratio=float(np.mean(rows["ratio_apt"])), fixed_ratio=float(np.mean(rows["ratio_fixed"])),
                             apt_overshoot_mean=m("overshoot_mean", "apt"), apt_overshoot_max=float(np.max([x["overshoot_max"] for x in rows["apt"]])),
                             apt_rev_mean_h=m("rev_exposure_mean_h", "apt"), apt_rev_p95_h=m("rev_exposure_p95_h", "apt"), apt_rev_max_h=float(np.max([x["rev_exposure_max_h"] for x in rows["apt"]])),
                             fixed_rev_mean_h=m("rev_exposure_mean_h", "fixed"), fixed_rev_p95_h=m("rev_exposure_p95_h", "fixed"), fixed_rev_max_h=float(np.max([x["rev_exposure_max_h"] for x in rows["fixed"]])),
                             apt_max_final_age_h=float(np.max([x["max_trigger_gap_h"] for x in rows["apt"]])),
                             apt_blocked=float(np.mean([x["blocked_triggers"] for x in rows["apt"]]))))
            print("impl", impl[-1])
    out["impl"] = impl

    # ---- (d) one realisation trace for the figure (anchor times of APT vs fixed T*)
    rng = np.random.default_rng(100)
    a, rr, em = sample(lam, mu, rng)
    trace = {}
    for name, kind, T in (("APT", "apt", None), ("FixedT*", "fixed", T_avg_bin)):
        times = []
        pend = 0.0
        pw = 0.0
        last = 0
        for i in range(NB):
            pend += pw * DT
            nw = w * a[i] + rho * rr[i]
            pend += nw * DT / 2
            pw += nw
            anc = em[i] or (kind == "apt" and pend >= G) or (kind == "fixed" and (i + 1) % max(1, int(round(T / DT))) == 0) or ((i + 1 - last) * DT >= delta - 1e-9)
            if anc:
                times.append((i + 1) * DT)
                pend = 0.0
                pw = 0.0
                last = i + 1
        trace[name] = times
    trace["arrivals_per_hour"] = (np.add.reduceat(a, np.arange(0, NB, 6))).tolist()
    out["trace"] = trace

    json.dump(out, open(os.path.join(RES, "policy.json"), "w"), indent=1)
    print("wrote results/policy.json")


if __name__ == "__main__":
    main(quick="--quick" in sys.argv)
