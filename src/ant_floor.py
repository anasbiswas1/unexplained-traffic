"""The benign floor on ANT (notebook 01): logged steps, traffic pieces, the step-level matcher and the allowlists.

Steps. The records of an episode are sorted by start time. Record i opens a step that runs until the next record
starts; the last step runs to the end of the capture; traffic before the first record is the 'prelude'. This is ANT's
own segmentation. Each step has the record's macro group label as its type.

Parts. Every step falls in one part: 'before_record' (the prelude), 'coarse' (a step longer than L seconds, where the
record is too coarse to say what happened) or 'logged_step' (a step of at most L seconds).

Pieces. The upload and download payload bytes of one flow inside one step.

Destination classes. dns (server port 53), local (private, loopback or link-local server address), backend (the
agent folder's model endpoint host), common (a named host whose registered domain was reached in at least a set share
of training episodes), rare (any other named host), unnamed (no name recovered).

Step-level matcher, fitted on training episodes only. For each step type g and class c: the share r(g,c) of steps of
type g that upload any bytes of class c (smoothed towards the class's overall share), and a byte budget B(g,c). For the
model endpoint, a model call resends the conversation so far, so its upload grows through a run: the budget applies to
the growth of the step's model-endpoint upload over the largest model-endpoint upload of any earlier step in the same
run. For every other class the budget applies to the step's upload itself. A budget is the upper quantile of the
training values for (g, c) when there are enough of them, else of class c over all step types, else the largest
training value of class c. In an evaluated step, class-c upload is unexplained in full if r(g,c) is below rho, and
otherwise only the part above the budget.

Allowlists (baselines). Per-task: a host is allowed for an episode if a training episode of the same task reached it.
Global: a registered domain is allowed if any training episode reached it. Both always allow the agent's own model
endpoint, DNS and private addresses.
"""
from __future__ import annotations

import hashlib
import math
from functools import lru_cache

import numpy as np
import pandas as pd

CLASSES = ("backend", "dns", "local", "common", "rare", "unnamed")
PARTS = ("before_record", "coarse", "logged_step")

_EXTRACT = None


def _extractor():
    global _EXTRACT
    if _EXTRACT is None:
        import tldextract
        _EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    return _EXTRACT


@lru_cache(maxsize=None)
def regdomain(name: str) -> str:
    if not name:
        return ""
    r = _extractor()(name)
    dom = getattr(r, "top_domain_under_public_suffix", None)
    if dom is None:
        dom = ".".join(x for x in (r.domain, r.suffix) if x)
    return dom or name


def instance_half(instance: str, salt: str = "unexplained-traffic-01") -> int:
    return int(hashlib.sha256(f"{salt}:{instance}".encode()).hexdigest(), 16) % 2


# ---------------------------------------------------------------- steps and pieces (one episode)

def episode_steps(records: pd.DataFrame, cap_first: float, cap_last: float) -> pd.DataFrame:
    """Steps of one episode. records: rows with t, macro_group_label, role, message_index (any order)."""
    r = records.sort_values(["t", "message_index"])
    t = r.t.to_numpy(dtype=float)
    lo = min(cap_first, t[0]) if len(t) else cap_first
    hi = max(cap_last, t[-1]) if len(t) else cap_last
    starts = np.concatenate([[lo], t])
    ends = np.concatenate([t, [hi + 1e-6]])
    return pd.DataFrame(dict(step=np.arange(len(starts), dtype=np.int32), start=starts, end=ends, dur=ends - starts,
                             type=["prelude"] + r.macro_group_label.astype(str).tolist(),
                             role=["prelude"] + r.role.astype(str).tolist(),
                             message_index=np.concatenate([[-1], r.message_index.to_numpy()]).astype(np.int64)))


def episode_pieces(packets: pd.DataFrame, flows: pd.DataFrame, steps: pd.DataFrame) -> pd.DataFrame:
    """Payload bytes and packets of each flow inside each step (only pairs with traffic)."""
    cols = ["step", "flow", "up_bytes", "down_bytes", "up_pkts", "down_pkts"]
    if packets.empty:
        return pd.DataFrame(columns=cols)
    si = np.searchsorted(steps.start.to_numpy(), packets.ts.to_numpy(), side="right") - 1
    g = pd.DataFrame(dict(step=np.clip(si, 0, None).astype(np.int32), flow=packets.flow.to_numpy(),
                          up=packets.up.to_numpy(), plen=packets.plen.to_numpy(dtype=np.int64)))
    a = g.groupby(["step", "flow", "up"]).plen.agg(["sum", "count"]).unstack("up", fill_value=0)
    out = pd.DataFrame(index=a.index)
    for d, name in ((1, "up"), (0, "down")):
        out[f"{name}_bytes"] = a[("sum", d)] if ("sum", d) in a.columns else 0
        out[f"{name}_pkts"] = a[("count", d)] if ("count", d) in a.columns else 0
    return out.reset_index()[cols].astype({c: np.int64 for c in cols[2:]})


def pieces_job(job: dict) -> dict:
    """Worker: steps and pieces of one episode from its stored packet and flow tables."""
    packets = pd.read_parquet(job["packets"])
    flows = pd.read_parquet(job["flows"])
    recs = pd.DataFrame(job["records"])
    steps = episode_steps(recs, job["cap_first"], job["cap_last"])
    pieces = episode_pieces(packets, flows, steps)
    keep = ["flow", "proto", "server_ip", "server_port", "name", "server_private"]
    pieces = pieces.merge(flows[keep], on="flow", how="left")
    steps.insert(0, "uid", job["uid"])
    pieces.insert(0, "uid", job["uid"])
    return dict(uid=job["uid"], steps=steps, pieces=pieces)


# ---------------------------------------------------------------- classes, parts, step-class table

def add_hosts(pieces: pd.DataFrame) -> pd.DataFrame:
    p = pieces.copy()
    p["host"] = np.where(p.name.astype(str) != "", p.name.astype(str), p.server_ip.astype(str))
    names = p.name.astype(str)
    uniq = {n: regdomain(n) for n in names.unique()}
    p["regdom"] = names.map(uniq)
    p.loc[p.regdom == "", "regdom"] = p.loc[p.regdom == "", "server_ip"].astype(str)
    return p


def classify(pieces: pd.DataFrame, backend: dict, common: set) -> np.ndarray:
    named = pieces.name.astype(str) != ""
    is_backend = pieces.host.to_numpy() == pieces.agent.map(backend).fillna("").to_numpy()
    return np.select([pieces.server_port.to_numpy() == 53, pieces.server_private.to_numpy(dtype=bool), is_backend,
                      named.to_numpy() & pieces.regdom.isin(common).to_numpy(), named.to_numpy()],
                     ["dns", "local", "backend", "common", "rare"], "unnamed")


def add_parts(steps: pd.DataFrame, L: float) -> pd.DataFrame:
    s = steps.copy()
    s["part"] = np.where(s.type == "prelude", "before_record", np.where(s.dur > L, "coarse", "logged_step"))
    return s


def common_domains(pieces: pd.DataFrame, uids, share: float) -> set:
    p = pieces[pieces.uid.isin(set(uids)) & (pieces.name.astype(str) != "")]
    n = len(set(uids))
    counts = p.groupby("regdom").uid.nunique()
    return set(counts[counts >= share * n].index)


def prior_max(uid: np.ndarray, step: np.ndarray, up: np.ndarray) -> np.ndarray:
    """For rows of one class sorted by (uid, step): the largest upload of any earlier row of the same run (0 if none)."""
    out = np.zeros(len(up), dtype=float)
    if len(up) == 0:
        return out
    starts = np.r_[True, uid[1:] != uid[:-1]]
    run_max = 0.0
    for i in range(len(up)):
        if starts[i]:
            run_max = 0.0
        out[i] = run_max
        run_max = max(run_max, float(up[i]))
    return out


def step_class_table(pieces: pd.DataFrame, steps: pd.DataFrame) -> pd.DataFrame:
    """One row per (uid, step, class) with upload bytes, joined to the step's type, duration and part. 'prior' is the
    largest upload of the same class in any earlier step of the run (used for the model endpoint only)."""
    sc = pieces.groupby(["uid", "step", "cls"], as_index=False).up_bytes.sum().rename(columns={"up_bytes": "up"})
    sc = sc.sort_values(["cls", "uid", "step"]).reset_index(drop=True)
    sc["prior"] = 0.0
    b = (sc.cls == "backend").to_numpy()
    sc.loc[b, "prior"] = prior_max(sc.uid.to_numpy()[b], sc.step.to_numpy()[b], sc.up.to_numpy(dtype=float)[b])
    return sc.merge(steps[["uid", "step", "type", "dur", "part"]], on=["uid", "step"], how="left")


# ---------------------------------------------------------------- the matcher

class StepMatcher:
    GROWTH = "backend"

    def __init__(self, rho=0.05, smoothing=20.0, quantile=0.99, min_cells=30):
        self.rho, self.A, self.q, self.min_cells = rho, smoothing, quantile, min_cells

    def _budget(self, v: pd.Series) -> float:
        return float(v.quantile(self.q)) if len(v) >= self.min_cells else float(v.max())

    def fit(self, steps: pd.DataFrame, sc: pd.DataFrame):
        live = steps[steps.dur > 0]
        n_g = live.groupby("type").size()
        pos = sc[sc.up > 0].copy()
        pos["v"] = np.where(pos.cls == self.GROWTH, pos.up - pos.prior, pos.up).astype(float)
        k_gc = pos.groupby(["type", "cls"]).size()
        self.r_glob = (pos.groupby("cls").size() / max(len(live), 1)).reindex(list(CLASSES), fill_value=0.0)
        rates = {}
        for (g, c), k in k_gc.items():
            rates[(g, c)] = (k + self.A * self.r_glob[c]) / (n_g.get(g, 0) + self.A)
        for g, n in n_g.items():
            for c in CLASSES:
                if (g, c) not in rates:
                    rates[(g, c)] = (self.A * self.r_glob[c]) / (n + self.A)
        self.rates = rates
        self.budget_glob = {c: self._budget(v) for c, v in pos.groupby("cls").v}
        self.budget = {(g, c): float(v.quantile(self.q)) for (g, c), v in pos.groupby(["type", "cls"]).v
                       if len(v) >= self.min_cells}
        return self

    def rate(self, g, c):
        return self.rates.get((g, c), float(self.r_glob.get(c, 0.0)))

    def budget_of(self, g, c):
        return self.budget.get((g, c), self.budget_glob.get(c, 0.0))

    def unexplained(self, types, classes, up, prior=None) -> np.ndarray:
        keys = list(zip(types, classes))
        uniq = {k: (self.rate(*k), self.budget_of(*k)) for k in set(keys)}
        r = np.array([uniq[k][0] for k in keys], dtype=float)
        b = np.maximum(np.array([uniq[k][1] for k in keys], dtype=float), 0.0)
        up = np.asarray(up, dtype=float)
        base = np.zeros(len(up)) if prior is None else np.asarray(prior, dtype=float)
        base = np.where(np.asarray(classes) == self.GROWTH, base, 0.0)
        return np.where(r >= self.rho, np.maximum(0.0, up - base - b), up)


# ---------------------------------------------------------------- the allowlists

def allow_per_task(train_pieces: pd.DataFrame) -> set:
    return set(zip(train_pieces.task.to_numpy(), train_pieces.host.to_numpy()))


def allow_global(train_pieces: pd.DataFrame) -> set:
    return set(train_pieces.regdom.unique())


def allowlist_unexplained(pieces: pd.DataFrame, allowed: set, per_task: bool) -> np.ndarray:
    always = pieces.cls.isin(["backend", "dns", "local"]).to_numpy()
    if per_task:
        ok = np.fromiter(((t, h) in allowed for t, h in zip(pieces.task.to_numpy(), pieces.host.to_numpy())),
                         dtype=bool, count=len(pieces))
    else:
        ok = pieces.regdom.isin(allowed).to_numpy()
    return np.where(always | ok, 0.0, pieces.up_bytes.to_numpy(dtype=float))


# ---------------------------------------------------------------- one evaluation (a fold, or ANT's own split)

def evaluate(pieces: pd.DataFrame, steps: pd.DataFrame, backend: dict, train_uids, eval_uids, S: dict, seed: int):
    """Fit on train_uids, score eval_uids. Returns (per-step table of upload and unexplained bytes per method,
    the fitted matcher, the evaluated step-class rows, the evaluated steps)."""
    tr, ev = set(train_uids), set(eval_uids)
    P = pieces[pieces.uid.isin(tr | ev)].copy()
    common = common_domains(P, tr, S["common_share"])
    P["cls"] = classify(P, backend, common)
    sc = step_class_table(P, steps[steps.uid.isin(tr | ev)])
    m = StepMatcher(S["rho"], S["smoothing"], S["budget_quantile"], S["min_cells"])
    m.fit(steps[steps.uid.isin(tr)], sc[sc.uid.isin(tr)])
    sce = sc[sc.uid.isin(ev)].copy()
    sce["u_matcher"] = m.unexplained(sce.type.to_numpy(), sce.cls.to_numpy(), sce.up.to_numpy(), sce.prior.to_numpy())
    ste = steps[steps.uid.isin(ev)].copy()
    sh = shuffle_types(ste, seed)[["uid", "step", "type"]].rename(columns={"type": "type_shuffled"})
    sce = sce.merge(sh, on=["uid", "step"], how="left")
    sce["u_shuffled"] = m.unexplained(sce.type_shuffled.to_numpy(), sce.cls.to_numpy(), sce.up.to_numpy(),
                                      sce.prior.to_numpy())
    pe, pt = P[P.uid.isin(ev)].copy(), P[P.uid.isin(tr)]
    pe["u_task"] = allowlist_unexplained(pe, allow_per_task(pt), True)
    pe["u_global"] = allowlist_unexplained(pe, allow_global(pt), False)
    a1 = pe.groupby(["uid", "step"], as_index=False)[["up_bytes", "u_task", "u_global"]].sum()
    a1 = a1.rename(columns={"up_bytes": "up"})
    a2 = sce.groupby(["uid", "step"], as_index=False)[["u_matcher", "u_shuffled"]].sum()
    t = a1.merge(a2, on=["uid", "step"], how="outer")
    for c in ("up", "u_task", "u_global", "u_matcher", "u_shuffled"):
        t[c] = t[c].fillna(0.0).astype(float)
    t = t.merge(ste[["uid", "step", "part", "type", "dur"]], on=["uid", "step"], how="left")
    return t, m, sce, ste


# ---------------------------------------------------------------- shares and intervals

def episode_sums(df: pd.DataFrame, cols) -> pd.DataFrame:
    """Per (uid, part): upload bytes and the unexplained bytes of each method column."""
    return df.groupby(["uid", "agent", "part"], as_index=False)[["up"] + list(cols)].sum()


def shares(ep: pd.DataFrame, cols, by=None) -> pd.DataFrame:
    keys = ([by] if by else []) + ["part"]
    g = ep.groupby(keys)[["up"] + list(cols)].sum()
    tot = ep.groupby([by] if by else lambda _: "all")[["up"] + list(cols)].sum()
    out = []
    for k, row in g.iterrows():
        k = k if isinstance(k, tuple) else (k,)
        out.append(dict(zip(keys, k), up_bytes=row.up, **{f"{c}_share": (row[c] / row.up if row.up else np.nan)
                                                          for c in cols}))
    for k, row in tot.iterrows():
        d = {by: k} if by else {}
        out.append(dict(d, part="all", up_bytes=row.up, **{f"{c}_share": (row[c] / row.up if row.up else np.nan)
                                                            for c in cols}))
    return pd.DataFrame(out)


def boot_ratio_diff(ep: pd.DataFrame, a: str, b: str, n_boot=2000, seed=1):
    """Point estimate and 95% interval of sum(a)/sum(up) - sum(b)/sum(up), resampling episodes."""
    e = ep.groupby("uid")[["up", a, b]].sum()
    up, A, B = e.up.to_numpy(float), e[a].to_numpy(float), e[b].to_numpy(float)
    point = (A.sum() - B.sum()) / up.sum()
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(e), size=(n_boot, len(e)))
    reps = (A[idx].sum(1) - B[idx].sum(1)) / up[idx].sum(1)
    lo, hi = np.percentile(reps, [2.5, 97.5])
    return float(point), float(lo), float(hi)


def boot_ratio(ep: pd.DataFrame, a: str, n_boot=2000, seed=1):
    e = ep.groupby("uid")[["up", a]].sum()
    up, A = e.up.to_numpy(float), e[a].to_numpy(float)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(e), size=(n_boot, len(e)))
    reps = A[idx].sum(1) / up[idx].sum(1)
    lo, hi = np.percentile(reps, [2.5, 97.5])
    return float(A.sum() / up.sum()), float(lo), float(hi)


def conformal_threshold(scores, alpha: float) -> float:
    s = np.sort(np.asarray(scores, dtype=float))
    k = math.ceil((len(s) + 1) * (1 - alpha))
    return float(s[k - 1]) if 1 <= k <= len(s) else float("inf")


def shuffle_types(steps: pd.DataFrame, seed: int) -> pd.DataFrame:
    """Permute step types among the record steps (not the prelude) of each episode."""
    s = steps.copy()
    rng = np.random.default_rng(seed)
    idx = np.flatnonzero((s.type != "prelude").to_numpy())
    types = s.type.to_numpy().copy()
    uids = s.uid.to_numpy()
    for u in pd.unique(uids[idx]):
        pos = idx[uids[idx] == u]
        types[pos] = types[rng.permutation(pos)]
    s["type"] = types
    return s


# ---------------------------------------------------------------- simulated injections

def pick_steps(steps_ev: pd.DataFrame, sc_ev: pd.DataFrame, which: str, seed: int) -> pd.DataFrame:
    """One logged step per run, chosen at random: 'backend' = a logged step with model-endpoint upload,
    'any' = any logged step of positive duration."""
    s = steps_ev[(steps_ev.part == "logged_step") & (steps_ev.dur > 0)][["uid", "step", "type"]]
    if which == "backend":
        has = sc_ev[(sc_ev.cls == "backend") & (sc_ev.up > 0) & (sc_ev.part == "logged_step")]
        s = s.merge(has[["uid", "step"]].drop_duplicates(), on=["uid", "step"])
    rng = np.random.default_rng(seed)
    return s.iloc[rng.permutation(len(s))].drop_duplicates("uid").reset_index(drop=True)


def injection_delta(matcher: StepMatcher, sc_ev: pd.DataFrame, picks: pd.DataFrame, cls: str, X: float):
    """Rise in each picked run's unexplained bytes when X upload bytes of class cls are added to its picked step.
    For the model endpoint the whole run is rescored, since a larger upload also raises the reference for later
    steps."""
    if cls != matcher.GROWTH:
        cur = sc_ev[sc_ev.cls == cls].groupby(["uid", "step"]).up.sum()
        u0 = cur.reindex(pd.MultiIndex.from_frame(picks[["uid", "step"]])).fillna(0).to_numpy(dtype=float)
        t, c = picks.type.to_numpy(), np.full(len(picks), cls)
        return matcher.unexplained(t, c, u0 + X) - matcher.unexplained(t, c, u0)
    runs = {u: d.sort_values("step") for u, d in sc_ev[sc_ev.cls == cls].groupby("uid")}
    out = np.zeros(len(picks))
    for k, (u, st) in enumerate(picks[["uid", "step"]].itertuples(index=False)):
        d = runs[u]
        steps, types, up = d.step.to_numpy(), d.type.to_numpy(), d.up.to_numpy(dtype=float)
        up2 = up.copy()
        up2[np.flatnonzero(steps == st)[0]] += X
        c = np.full(len(up), cls)
        uid = np.full(len(up), u)
        before = matcher.unexplained(types, c, up, prior_max(uid, steps, up)).sum()
        after = matcher.unexplained(types, c, up2, prior_max(uid, steps, up2)).sum()
        out[k] = after - before
    return out
