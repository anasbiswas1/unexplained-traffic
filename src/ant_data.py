"""ANT data access (notebook 01): the episode listing, the per-message records, and capture extraction.

The dataset (huggingface.co/datasets/benzenenene/ANT) is laid out as
    <split>/<agent folder>/<scenario>/<Axxxx>/{messages.jsonl, network.pcap}
where Axxxx is the task instance: the first two digits are the task number and the same instance identifier recurs
across agent folders. An episode is one (agent folder, instance) pair.

Extraction runs one episode at a time: download the capture to local disk, read it with ant_capture, write the packet
and flow tables to the project data folder, delete the capture. A small JSON summary is written last and marks the
episode as done, so an interrupted run resumes where it stopped. A job may name a local copy of the dataset
('local_source', the dataset root on disk); captures are then read from it instead of downloaded.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import re
import shutil
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

import ant_capture

REPO_ID = "benzenenene/ANT"
PATH_RE = re.compile(r"^(train|val|test)/([^/]+)/([^/]+)/(A\d{4})/(network\.pcap|messages\.jsonl)$")
MESSAGE_FIELDS = ["message_index", "message_id", "role", "start_time", "macro_group_id", "macro_group_label",
                  "task_group", "category", "agent", "split"]


def hf_token():
    try:
        from google.colab import userdata
        tok = userdata.get("HF_TOKEN")
        if tok:
            return tok
    except Exception:
        pass
    return os.environ.get("HF_TOKEN") or None


def list_episodes(token=None, files=None) -> pd.DataFrame:
    """One row per episode with the repository paths of its two files ('' when a file is missing)."""
    if files is None:
        from huggingface_hub import list_repo_files
        files = list_repo_files(REPO_ID, repo_type="dataset", token=token)
    eps: dict[tuple, dict] = {}
    for f in files:
        m = PATH_RE.match(f)
        if not m:
            continue
        split, agent, scenario, inst, fname = m.groups()
        key = (split, agent, scenario, inst)
        row = eps.setdefault(key, dict(split=split, agent=agent, scenario=scenario, instance=inst,
                                       task=int(inst[1:3]), pcap="", messages=""))
        row["pcap" if fname == "network.pcap" else "messages"] = f
    df = pd.DataFrame(list(eps.values()), columns=["split", "agent", "scenario", "instance", "task", "pcap",
                                                   "messages"])
    df["uid"] = df.agent + "/" + df.instance
    return df.sort_values(["agent", "instance"]).reset_index(drop=True)


def to_epoch(series: pd.Series) -> pd.Series:
    t = pd.to_datetime(series, utc=True, format="ISO8601")
    return (t - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()


def download_messages(local_dir: str, token=None, max_workers: int = 8) -> str:
    from huggingface_hub import snapshot_download
    return snapshot_download(REPO_ID, repo_type="dataset", allow_patterns=["*/messages.jsonl"], local_dir=local_dir,
                             token=token, max_workers=max_workers)


def read_messages(episodes: pd.DataFrame, local_dir: str) -> pd.DataFrame:
    """All per-message records, keyed by the episode identity taken from the folder path."""
    frames = []
    for ep in episodes.itertuples(index=False):
        if not ep.messages:
            continue
        path = Path(local_dir) / ep.messages
        recs = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not recs:
            continue
        d = pd.DataFrame(recs)
        for c in MESSAGE_FIELDS:
            if c not in d.columns:
                d[c] = None
        d = d[MESSAGE_FIELDS].rename(columns={"agent": "record_agent", "split": "record_split"})
        d.insert(0, "uid", ep.uid)
        d.insert(1, "agent", ep.agent)
        d.insert(2, "instance", ep.instance)
        frames.append(d)
    m = pd.concat(frames, ignore_index=True)
    m["t"] = to_epoch(m.start_time)
    if m.t.isna().any():
        print(f"read_messages: {int(m.t.isna().sum())} records without a start time dropped")
        m = m[m.t.notna()]
    m["macro_group_label"] = m.macro_group_label.fillna("unlabelled").astype(str)
    return m.sort_values(["uid", "t", "message_index"]).reset_index(drop=True)


def alignment(messages: pd.DataFrame, infos: pd.DataFrame, slack: float = 1.0) -> pd.Series:
    """Per episode, the share of record start times that fall inside the capture's time span (plus slack seconds)."""
    m = messages.merge(infos[["uid", "first_ts", "last_ts"]], on="uid", how="inner")
    inside = (m.t >= m.first_ts - slack) & (m.t <= m.last_ts + slack)
    return inside.groupby(m.uid).mean()


def episode_paths(out_root: str, uid: str) -> dict:
    agent, inst = uid.split("/")
    base = Path(out_root) / agent / inst
    return dict(packets=f"{base}.packets.parquet", flows=f"{base}.flows.parquet", info=f"{base}.info.json")


def extract_episode(job: dict) -> dict:
    """Download, read and store one capture. Returns the capture summary, or a dict with an 'error' key."""
    uid, paths = job["uid"], episode_paths(job["out_root"], job["uid"])
    if os.path.exists(paths["info"]):
        with open(paths["info"]) as fh:
            return {**json.load(fh), "cached": True}
    if job.get("local_source"):
        local, tmp = os.path.join(job["local_source"], job["pcap"]), None
    else:
        from huggingface_hub import hf_hub_download
        tmp = os.path.join(job["tmp_root"], uid.replace("/", "__"))
        os.makedirs(tmp, exist_ok=True)
        local = None
        for attempt in range(4):
            try:
                local = hf_hub_download(REPO_ID, filename=job["pcap"], repo_type="dataset", local_dir=tmp,
                                        cache_dir=os.path.join(tmp, ".hf_cache"), token=job.get("token"))
                break
            except Exception as e:
                if attempt == 3:
                    shutil.rmtree(tmp, ignore_errors=True)
                    return dict(uid=uid, error=f"download: {e!r}"[:500])
                time.sleep(5 * 2 ** attempt)
    try:
        size = os.path.getsize(local)
        packets, flows, info = ant_capture.read_capture(local)
    except Exception as e:
        return dict(uid=uid, error=f"parse: {e!r}"[:500])
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(os.path.dirname(paths["info"]), exist_ok=True)
    packets.to_parquet(paths["packets"], index=False)
    flows.to_parquet(paths["flows"], index=False)
    info.update(uid=uid, pcap_bytes=size)
    with open(paths["info"], "w") as fh:
        json.dump(info, fh)
    return info


def run_pool(fn, jobs: list, workers: int, every: int = 100, label: str = "") -> list:
    """Run fn over jobs in fresh worker processes, printing a progress line every `every` results."""
    out, t0 = [], time.time()
    ctx = mp.get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
        futs = [ex.submit(fn, j) for j in jobs]
        for k, f in enumerate(as_completed(futs), 1):
            out.append(f.result())
            if k % every == 0 or k == len(jobs):
                errs = sum(1 for r in out if isinstance(r, dict) and r.get("error"))
                print(f"{label}{k}/{len(jobs)} done, {errs} errors, {time.time() - t0:.0f} s", flush=True)
    return out
