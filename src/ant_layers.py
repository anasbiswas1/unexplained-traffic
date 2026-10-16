"""Layered detection on ANT (notebook 01b): corrected model endpoints, the step-level matcher v2, and the layered
detector made of the per-task allowlist and the matcher.

Harness traffic and model endpoints. A host reached in at least a set share of runs in every Claude Code folder,
whatever that folder's model backend, is traffic of the agent software itself (harness traffic), not a model endpoint.
A folder's model endpoint is, among the hosts it reaches in at least that share of its runs and that are not harness
hosts, the one with the most upload bytes.

Matcher v2 changes two things in the matcher of notebook 01 (ant_floor.StepMatcher), and nothing else:
  1. harness traffic is not tied to logged steps, so it gets a run-level budget: a run's harness upload is explained up
     to rate x run duration, where rate is the upper quantile of (harness upload / run duration) over training runs;
     any excess is spread over the run's harness rows in proportion to their upload;
  2. content a tool fetched can come back in the next model call, so the model-endpoint growth budget also allows the
     bytes downloaded from non-endpoint, non-harness, non-DNS hosts in the previous step.

Layered detector. Each detector gives a run one score, its unexplained upload bytes summed over the run. The layered
detector takes two scores, the per-task allowlist's and matcher v2's, and is calibrated as a whole (layered_alarm): a
run is ranked against the calibration runs on each score and keeps its better rank; it is interrupted when at most an
alpha share of the calibration runs plus itself rank as high or higher on that measure. A benign run is then
interrupted with probability at most alpha, the same level as each detector alone.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from ant_floor import (CLASSES, StepMatcher, allow_global, allow_per_task, allowlist_unexplained, common_domains,
                       prior_max, shuffle_types)

CLASSES2 = CLASSES + ("harness",)


# ---------------------------------------------------------------- harness hosts and model endpoints

def host_table(flows: pd.DataFrame, n_runs: pd.Series) -> pd.DataFrame:
    """Per (agent, named public host): runs reached, share of the folder's runs, upload and download bytes."""
    pub = flows[(flows.name != "") & ~flows.server_private & (flows.server_port != 53)]
    h = pub.groupby(["agent", "name"]).agg(runs=("uid", "nunique"), flows=("flow", "size"),
                                           up_bytes=("up_bytes", "sum"), down_bytes=("down_bytes", "sum")).reset_index()
    h["run_share"] = h.runs / h.agent.map(n_runs)
    h["up_share"] = h.up_bytes / h.groupby("agent").up_bytes.transform("sum")
    return h.sort_values(["agent", "up_bytes"], ascending=[True, False]).reset_index(drop=True)


def harness_hosts(h: pd.DataFrame, family: str, share: float) -> set:
    folders = sorted(a for a in h.agent.unique() if family in a)
    if len(folders) < 2:
        return set()
    always = [set(h[(h.agent == a) & (h.run_share >= share)].name) for a in folders]
    return set.intersection(*always)


def model_endpoints(h: pd.DataFrame, harness: set, share: float) -> dict:
    c = h[(h.run_share >= share) & ~h.name.isin(harness)]
    return c.sort_values("up_bytes", ascending=False).drop_duplicates("agent").set_index("agent").name.to_dict()


# ---------------------------------------------------------------- classes and the step-class table v2

def classify2(P: pd.DataFrame, backend: dict, common: set, harness: set, family: str) -> np.ndarray:
    named = (P.name.astype(str) != "").to_numpy()
    is_backend = P.host.to_numpy() == P.agent.map(backend).fillna("").to_numpy()
    is_harness = P.host.isin(harness).to_numpy() & P.agent.str.contains(family, regex=False).to_numpy()
    return np.select([P.server_port.to_numpy() == 53, P.server_private.to_numpy(dtype=bool), is_backend, is_harness,
                      named & P.regdom.isin(common).to_numpy(), named],
                     ["dns", "local", "backend", "harness", "common", "rare"], "unnamed")


def step_class_table2(P: pd.DataFrame, steps: pd.DataFrame) -> pd.DataFrame:
    """As ant_floor.step_class_table, plus 'inflow_prev': bytes downloaded from non-endpoint, non-harness, non-DNS
    hosts in the previous step of the same run."""
    sc = P.groupby(["uid", "step", "cls"], as_index=False).up_bytes.sum().rename(columns={"up_bytes": "up"})
    sc = sc.sort_values(["cls", "uid", "step"]).reset_index(drop=True)
    sc["prior"] = 0.0
    b = (sc.cls == "backend").to_numpy()
    sc.loc[b, "prior"] = prior_max(sc.uid.to_numpy()[b], sc.step.to_numpy()[b], sc.up.to_numpy(dtype=float)[b])
    inflow = P[~P.cls.isin(["backend", "harness", "dns"])].groupby(["uid", "step"]).down_bytes.sum()
    st = steps[["uid", "step"]].sort_values(["uid", "step"]).copy()
    st["inflow"] = pd.MultiIndex.from_frame(st[["uid", "step"]]).map(inflow).fillna(0.0).to_numpy(dtype=float)
    st["inflow_prev"] = st.groupby("uid").inflow.shift(1).fillna(0.0)
    sc = sc.merge(st[["uid", "step", "inflow_prev"]], on=["uid", "step"], how="left")
    return sc.merge(steps[["uid", "step", "type", "dur", "part"]], on=["uid", "step"], how="left")


# ---------------------------------------------------------------- matcher v2

class StepMatcherV2(StepMatcher):
    def base(self, cls, prior, inflow_prev) -> np.ndarray:
        cls = np.asarray(cls)
        return np.where(cls == self.GROWTH, np.asarray(prior, dtype=float) + np.asarray(inflow_prev, dtype=float), 0.0)

    def fit2(self, steps: pd.DataFrame, sc: pd.DataFrame, run_dur: pd.Series):
        s = sc[sc.cls != "harness"].copy()
        s["prior"] = self.base(s.cls, s.prior, s.inflow_prev)
        self.fit(steps, s)
        h = sc[sc.cls == "harness"].groupby("uid").up.sum()
        r = (h / run_dur.reindex(h.index)).replace([np.inf, -np.inf], np.nan).dropna()
        self.harness_rate = float(r.quantile(self.q)) if len(r) else 0.0
        return self

    def step_unexplained(self, sc: pd.DataFrame, types=None) -> np.ndarray:
        types = sc.type.to_numpy() if types is None else np.asarray(types)
        u = self.unexplained(types, sc.cls.to_numpy(), sc.up.to_numpy(), self.base(sc.cls, sc.prior, sc.inflow_prev))
        return np.where(sc.cls.to_numpy() == "harness", 0.0, u)

    def harness_unexplained(self, sc: pd.DataFrame, run_dur: pd.Series) -> np.ndarray:
        """Excess of each run's harness upload over rate x duration, spread over its harness rows by upload."""
        out = np.zeros(len(sc))
        hm = (sc.cls == "harness").to_numpy()
        if not hm.any():
            return out
        hs = sc[hm]
        tot = hs.groupby("uid").up.sum()
        excess = (tot - self.harness_rate * run_dur.reindex(tot.index).fillna(0.0)).clip(lower=0.0)
        w = (hs.up / hs.uid.map(tot).replace(0, np.nan)).fillna(0.0)
        out[hm] = (w * hs.uid.map(excess)).to_numpy(dtype=float)
        return out


# ---------------------------------------------------------------- one evaluation

def evaluate2(pieces: pd.DataFrame, steps: pd.DataFrame, backend: dict, harness: set, train_uids, eval_uids, S: dict,
              seed: int):
    """Fit on train_uids and score eval_uids. Returns (per-step table with upload and the unexplained bytes of each
    detector, fitted matcher, evaluated step-class rows, evaluated steps, run durations)."""
    tr, ev = set(train_uids), set(eval_uids)
    fam = S["harness_family"]
    P = pieces[pieces.uid.isin(tr | ev)].copy()
    common = common_domains(P, tr, S["common_share"])
    P["cls"] = classify2(P, backend, common, harness, fam)
    st_all = steps[steps.uid.isin(tr | ev)]
    run_dur = st_all.groupby("uid").dur.sum()
    sc = step_class_table2(P, st_all)
    m = StepMatcherV2(S["rho"], S["smoothing"], S["budget_quantile"], S["min_cells"])
    m.fit2(steps[steps.uid.isin(tr)], sc[sc.uid.isin(tr)], run_dur)
    sce = sc[sc.uid.isin(ev)].copy()
    hx = m.harness_unexplained(sce, run_dur)
    sce["u_matcher"] = m.step_unexplained(sce) + hx
    ste = steps[steps.uid.isin(ev)].copy()
    sh = shuffle_types(ste, seed)[["uid", "step", "type"]].rename(columns={"type": "type_shuffled"})
    sce = sce.merge(sh, on=["uid", "step"], how="left")
    sce["u_shuffled"] = m.step_unexplained(sce, sce.type_shuffled.to_numpy()) + hx
    pe, pt = P[P.uid.isin(ev)].copy(), P[P.uid.isin(tr)]
    pa = pe.assign(cls=np.where(pe.cls == "harness", "common", pe.cls))
    pe["u_task"] = allowlist_unexplained(pa, allow_per_task(pt), True)
    pe["u_global"] = allowlist_unexplained(pa, allow_global(pt), False)
    a1 = pe.groupby(["uid", "step"], as_index=False)[["up_bytes", "u_task", "u_global"]].sum()
    a1 = a1.rename(columns={"up_bytes": "up"})
    a2 = sce.groupby(["uid", "step"], as_index=False)[["u_matcher", "u_shuffled"]].sum()
    t = a1.merge(a2, on=["uid", "step"], how="outer")
    for c in ("up", "u_task", "u_global", "u_matcher", "u_shuffled"):
        t[c] = t[c].fillna(0.0).astype(float)
    t = t.merge(ste[["uid", "step", "part", "type", "dur"]], on=["uid", "step"], how="left")
    return t, m, sce, ste, run_dur


# ---------------------------------------------------------------- simulated leaks, scored for all detectors

def leak_scores(t: pd.DataFrame, m: StepMatcherV2, sce: pd.DataFrame, picks: pd.DataFrame, attack: str, X: float,
                run_dur: pd.Series) -> pd.DataFrame:
    """Per picked run, each detector's run score after X upload bytes are added.
    'model_call': inside the model endpoint's upload of the picked step; the run's endpoint rows are rescored, since a
                  larger upload also raises the reference for later steps.
    'new_host':   to a host never seen before (class rare), in the picked step.
    'harness':    inside the harness channel; the run's harness budget is rescored."""
    base = t.groupby("uid")[["u_task", "u_global", "u_matcher"]].sum()
    rows_b = {u: d.sort_values("step") for u, d in sce[sce.cls == "backend"].groupby("uid")}
    rare = sce[sce.cls == "rare"].groupby(["uid", "step"]).up.sum()
    hup = sce[sce.cls == "harness"].groupby("uid").up.sum()
    out = []
    for u, st, g in picks[["uid", "step", "type"]].itertuples(index=False):
        task, glob, mat = base.loc[u, "u_task"], base.loc[u, "u_global"], base.loc[u, "u_matcher"]
        if attack == "model_call":
            b = rows_b[u]
            steps_b, up = b.step.to_numpy(), b.up.to_numpy(dtype=float)
            up2 = up.copy()
            up2[np.flatnonzero(steps_b == st)[0]] += X
            cls, uid, infl = np.full(len(up), "backend"), np.full(len(up), u), b.inflow_prev.to_numpy(dtype=float)
            f0 = m.unexplained(b.type.to_numpy(), cls, up, m.base(cls, prior_max(uid, steps_b, up), infl))
            f1 = m.unexplained(b.type.to_numpy(), cls, up2, m.base(cls, prior_max(uid, steps_b, up2), infl))
            mat += float(f1.sum() - f0.sum())
        elif attack == "new_host":
            u0 = float(rare.get((u, st), 0.0))
            mat += float((m.unexplained([g], ["rare"], [u0 + X]) - m.unexplained([g], ["rare"], [u0]))[0])
            task += X
            glob += X
        elif attack == "harness":
            h0, budget = float(hup.get(u, 0.0)), m.harness_rate * float(run_dur.get(u, 0.0))
            mat += max(0.0, h0 + X - budget) - max(0.0, h0 - budget)
        else:
            raise ValueError(attack)
        out.append(dict(uid=u, u_task=float(task), u_global=float(glob), u_matcher=float(mat)))
    return pd.DataFrame(out)


def pick_harness_runs(sce: pd.DataFrame, uids) -> pd.DataFrame:
    """Runs (among uids) with harness traffic, one row each, in the shape pick_steps returns."""
    h = sce[(sce.cls == "harness") & sce.uid.isin(set(uids))]
    first = h.sort_values(["uid", "step"]).drop_duplicates("uid")
    return first[["uid", "step", "type"]].reset_index(drop=True)


def layered_alarm(cal, test, alpha: float) -> np.ndarray:
    """Alarm for each test run of a detector made of several run scores (columns), calibrated as a whole.
    Within the set of calibration runs plus the test run, each run gets, per score, the number of runs scoring at least
    as high (itself included), and keeps its smallest count over the scores. The test run's conformal p-value is the
    share of that set whose smallest count is at most its own; the alarm fires when it is at most alpha. The set is
    symmetric in the calibration runs and the test run, so a benign test run raises an alarm with probability at most
    alpha."""
    cal, test = np.asarray(cal, dtype=float), np.asarray(test, dtype=float)
    n = len(cal)
    if n == 0:
        return np.zeros(len(test), dtype=bool)
    base = (cal[None, :, :] >= cal[:, None, :]).sum(1)
    q_cal = (base[None, :, :] + (test[:, None, :] >= cal[None, :, :])).min(2)
    q_test = (1 + (cal[None, :, :] >= test[:, None, :]).sum(1)).min(1)
    p = (1 + (q_cal <= q_test[:, None]).sum(1)) / (n + 1)
    return p <= alpha


def paired_diff(a: np.ndarray, b: np.ndarray, n_boot=2000, seed=1):
    """Mean of (a - b) over paired runs with a 95% bootstrap interval (resampling runs)."""
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    d = a - b
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(d), size=(n_boot, len(d)))
    lo, hi = np.percentile(d[idx].mean(1), [2.5, 97.5])
    return float(d.mean()), float(lo), float(hi)
