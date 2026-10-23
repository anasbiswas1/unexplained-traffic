"""Warm agent homes: one template home per agent version, copied (never shared) into each run's home before the agent
starts, so that every benign run is a returning user with a warm home, not a first launch.

A template is made by one trivial task run of the agent through the gateway, in its own run namespace, from an empty
home, and saved only when the home is complete:
  - Codex starts a sync of its plugin catalogue (github.com/openai/plugins) in the background at every launch. It
    fetches into a temporary .codex/.tmp/plugins-clone-* folder and moves the result to .codex/.tmp/plugins, with the
    commit in .codex/.tmp/plugins.sha, only at the end; when the agent exits first, the fetched data (about 25 MB) is
    left behind unused and the next launch fetches it again. The warm-up's first model call is therefore held at the
    gateway (--hold-until) until plugins.sha exists. A home with a finished sync only checks the remote commit at the
    next launch (git ls-remote, about 40 KB) and fetches again only when the catalogue has changed upstream, so a
    template is made fresh at the start of each gate or collection session.
  - Claude Code needs no hold.
  - No file in the template may contain the API key.
Templates live under data/harness/homes/<agent>-<version>/ (git-ignored): home/ and manifest.json.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time

COMMANDS = {"claude": "claude", "codex": "codex"}


def parse_version(text: str) -> str:
    m = re.search(r"\b(\d+\.\d+\.\d+)\b", text)
    if not m:
        raise RuntimeError(f"no version in: {text.strip()[:200]}")
    return m.group(1)


def agent_version(agent: str) -> str:
    out = subprocess.run([COMMANDS[agent], "--version"], capture_output=True, text=True, timeout=60)
    return parse_version(out.stdout + out.stderr)


def template_dir(root: str, agent: str, version: str) -> str:
    return os.path.join(root, f"{agent}-{version}")


def tree_bytes(path: str) -> int:
    total = 0
    for base, _, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(base, name)).st_size
            except OSError:
                pass
    return total


def hold_file(agent: str, home: str) -> str | None:
    """The file whose appearance ends the warm-up hold, or None when the agent needs no hold."""
    return os.path.join(home, ".codex", ".tmp", "plugins.sha") if agent == "codex" else None


def codex_sync_state(home: str) -> dict:
    tmp = os.path.join(home, ".codex", ".tmp")
    sha_file = os.path.join(tmp, "plugins.sha")
    sha = None
    if os.path.isfile(sha_file):
        with open(sha_file) as f:
            sha = f.read().strip() or None
    clones = sorted(d for d in os.listdir(tmp) if d.startswith("plugins-clone-")) if os.path.isdir(tmp) else []
    repo = os.path.join(tmp, "plugins")
    return dict(sha=sha, repo_bytes=tree_bytes(repo), repo_has_git=os.path.isdir(os.path.join(repo, ".git")),
                leftover_clones=clones, synced=bool(sha) and os.path.isdir(os.path.join(repo, ".git")) and not clones)


def find_secret(root: str, secret: str) -> list[str]:
    """Files under root that contain secret."""
    if not secret:
        return []
    needle = secret.encode()
    hits = []
    for base, _, files in os.walk(root):
        for name in files:
            path = os.path.join(base, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as f:
                    if needle in f.read():
                        hits.append(os.path.relpath(path, root))
            except OSError:
                pass
    return hits


def template_problems(agent: str, home: str, secret: str) -> list[str]:
    problems = []
    if not os.path.isdir(home) or not os.listdir(home):
        problems.append("home is empty")
    if agent == "codex":
        state = codex_sync_state(home)
        if not state["synced"]:
            problems.append(f"Codex plugin catalogue sync not finished: {state}")
    leaks = find_secret(home, secret)
    if leaks:
        problems.append(f"API key found in {leaks}")
    return problems


def save_template(run_home: str, root: str, agent: str, version: str, manifest: dict, secret: str) -> str:
    """Copies a warm-up run's home to the template folder, replacing any older template of the same version."""
    problems = template_problems(agent, run_home, secret)
    if problems:
        raise RuntimeError(f"{agent} {version} home not saved: {'; '.join(problems)}")
    dest = template_dir(root, agent, version)
    staging = dest + ".new"
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    shutil.copytree(run_home, os.path.join(staging, "home"), symlinks=True)
    meta = dict(manifest, agent=agent, version=version, saved=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                home_bytes=tree_bytes(os.path.join(staging, "home")))
    if agent == "codex":
        meta["codex_plugins"] = codex_sync_state(os.path.join(staging, "home"))
    with open(os.path.join(staging, "manifest.json"), "w") as f:
        json.dump(meta, f, indent=1, default=str)
    shutil.rmtree(dest, ignore_errors=True)
    os.rename(staging, dest)
    return dest


def load_template(root: str, agent: str, version: str) -> dict:
    dest = template_dir(root, agent, version)
    with open(os.path.join(dest, "manifest.json")) as f:
        meta = json.load(f)
    return dict(meta, path=dest, home=os.path.join(dest, "home"))


def copy_template(template_home: str, dest_home: str) -> None:
    """A private copy of the template for one run; the run's home must not exist yet or be empty."""
    if os.path.isdir(dest_home) and os.listdir(dest_home):
        raise RuntimeError(f"run home is not empty: {dest_home}")
    if os.path.isdir(dest_home):
        os.rmdir(dest_home)
    shutil.copytree(template_home, dest_home, symlinks=True)
