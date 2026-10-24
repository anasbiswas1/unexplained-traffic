"""Benign collection pilot on the existing harness. Run as root on the VM, from the repository root, inside tmux, with
the DeepSeek key in DEEPSEEK_API_KEY (never written to disk):

    sudo -E python3 harness/pilot.py --upload gs://<bucket>/pilot
    sudo -E python3 harness/pilot.py --resume <stamp> --upload gs://<bucket>/pilot    # continue a stopped pilot

It runs the ten benign tasks in pilot_tasks.py with both agents (Claude Code and Codex on deepseek-flash), each task
three times, always through the gateway, each run from a private copy of that agent version's warm template home, in
its own network namespace, one run at a time: 10 tasks x 2 agents x 3 repeats = 60 runs. Nothing in this step injects
or leaks anything; every run is benign.

Each agent keeps its default tool set next to the four benign MCP tools. Under the settings here, tested with the
pinned versions: Claude Code in print mode runs its Read tool inside the workspace and read-only Bash commands, and
refuses Read outside the workspace, Write, Edit, WebFetch and WebSearch; Codex (workspace-write sandbox, approval never,
web search disabled) runs shell commands that read anywhere and write in the workspace, with network blocked inside
the sandbox. The MCP tool log sees only MCP calls, so every tool call, built-in or MCP, is also taken from the agent's
own event output (Claude Code --output-format stream-json, Codex exec --json); switching to that output leaves every
request byte for byte the same.

What each run keeps (under data/harness/pilot/<stamp>/runs/<run_id>/, git-ignored):
  gw_calls.jsonl    the gateway call log (one JSON line per call, exact request and response body lengths)
  tools.jsonl       the MCP tool log (one line per MCP tool call, argument sizes at the tool boundary)
  agent_tools.jsonl every tool call from the agent's event output: tool, built-in or MCP, input and output sizes
  run.pcap          the packet capture of the run on its own interface
  net.json          the run's network settings and capture counts
  agent_stdout.txt, agent_stderr.txt, last_message.txt (Codex), ws/ (the workspace with the agent's outputs)
  labels.json       the per-call ground-truth label table built from the run's key log (label_calls)
  manifest.json     task, agent, version, model, repeat, template id, start and end times, exit status, model-call
                    statuses, wire verdict, bytes per host, drops, labels summary, tool-call counts, balance
The key log is deleted the moment labels.json is written and is never an input to any detector. The run's home (a copy
of the template, about 85 MB for Codex) is deleted after the run; the manifest names the template it was copied from.

Reuses the gate's building blocks unchanged (harness/vm_gate.py and the modules it imports): the gateway, warm homes,
the MCP tool server, per-run network isolation and capture, the wire verdict, the bytes-per-host table, the
background-download rule and the upstream-drop detection. The new pieces are the benign task set, the per-run labels,
the agent tool-call record, the cost guard on the DeepSeek balance, the run manifests, resume, and the pilot marks.

Pilot quality marks, fixed before the run and reported at the end (kept runs: not a flagged first attempt, not a run
that stopped on an error):
  Q1 at least 95% of the kept runs are clean on the wire (the gate's wire verdict)
  Q2 every kept run's labels hold: every model-call request body sent to the endpoint has a decrypted length equal to
     the gateway's logged length, every decrypted request is paired with a logged call, and nothing on the model
     host's connections reads as HTTP without the key log
  Q3 no pilot run, flagged first attempts included, has a background download over 1,000,000 bytes from any host
     other than the model host
  Q4 every kept run has a complete manifest
  Q5 at least 95% of the kept runs completed: exit 0, every model call answered 200, and the agent's own result not an
     error
The pilot passes only when Q1 to Q5 pass and the set is complete: every planned run kept, no early stop, and a warm
template made for every agent. A run whose model call the endpoint drops is rerun once; both records are kept, the
first flagged, and the rerun is the run that counts. Codex's upload to ab.chatgpt.com is reported against run time and
model calls.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import homes          # noqa: E402
import netns          # noqa: E402
import vm_gate        # noqa: E402
from offline_check import MCP, codex_config  # noqa: E402
import pilot_tasks    # noqa: E402

MODEL_HOST = vm_gate.MODEL_HOST
ANTHROPIC_BASE = vm_gate.ANTHROPIC_BASE
RESPONSES_BASE = vm_gate.RESPONSES_BASE
BACKGROUND_DOWNLOAD_LIMIT = vm_gate.BACKGROUND_DOWNLOAD_LIMIT
CODEX_BACKGROUND_HOST = "ab.chatgpt.com"
PILOT_ROOT = os.path.join(REPO, "data", "harness", "pilot")
AGENTS = ["claude", "codex"]

# Claude Code may call the four benign workspace tools without asking (the gate allowed only word_count)
ALLOWED_TOOLS = ["mcp__bench__word_count", "mcp__bench__list_dir", "mcp__bench__read_file", "mcp__bench__write_file"]

# cost guard
BALANCE_URL = "https://api.deepseek.com/user/balance"
AGENT_TIMEOUT = 300            # longest an agent may run (seconds), as in the gate
CLAUDE_MAX_TURNS = 12          # turn cap for Claude Code; Codex is capped by time only
DEFAULT_BALANCE_FLOOR = 1.0    # stop before a run if the balance is at or below this (first currency DeepSeek lists)

# pilot quality marks
WIRE_CLEAN_MIN = 0.95
COMPLETED_MIN = 0.95
REPEATS = 3

# run namespaces ut51 to ut250, clear of the gate's fixed indices (11-24, 31-44)
FIRST_INDEX, LAST_INDEX = 51, 250


# ---------------------------------------------------------------- cost guard: DeepSeek balance, read from the VM
def parse_balance(body: dict) -> dict:
    infos = body.get("balance_infos") or []
    total = currency = None
    if infos:
        currency = infos[0].get("currency")
        try:
            total = float(infos[0].get("total_balance"))
        except (TypeError, ValueError):
            total = None
    return dict(is_available=body.get("is_available"), currency=currency, total_balance=total,
                currencies=[i.get("currency") for i in infos], raw=body)


def read_balance(key: str, url: str = BALANCE_URL, timeout: float = 30) -> dict:
    """GET the DeepSeek balance. Returns the parsed balance, or a dict with an error; never raises."""
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}", "Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as r:
            body = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return dict(error=f"HTTP {e.code}", body=e.read()[:300].decode("utf-8", "replace"))
    except Exception as e:
        return dict(error=f"{type(e).__name__}: {e}")
    if not isinstance(body, dict):
        return dict(error="balance reply is not a JSON object")
    return parse_balance(body)


def balance_stop(bal: dict, floor: float) -> str | None:
    """The reason to stop before the next run, or None to go on."""
    if bal.get("error"):
        return f"balance could not be read ({bal['error']})"
    if bal.get("is_available") is False:
        return "DeepSeek reports the balance is not available for API calls"
    if bal.get("total_balance") is None:
        return "the balance reply has no total"
    if bal["total_balance"] <= floor:
        return f"balance {bal['total_balance']} {bal.get('currency') or ''} is at or below the floor {floor}".strip()
    return None


def check_balance(key: str, floor: float, url: str = BALANCE_URL, retry_wait: float = 5.0) -> tuple[dict, str | None]:
    """Reads the balance, once more after a short wait when the read fails, and says whether to stop."""
    bal = read_balance(key, url)
    if bal.get("error"):
        time.sleep(retry_wait)
        bal = read_balance(key, url)
    return bal, balance_stop(bal, floor)


# ---------------------------------------------------------------- ground-truth labels for one run
def is_model_path(path: str) -> bool:
    return (path or "").split("?")[0].endswith(("/v1/messages", "/responses"))


def on_wire(call: dict) -> bool:
    """The gateway sent this call's request to the endpoint: an upstream connection existed and the request head was
    written (a failed upstream connect, or a request the gateway could not frame, never reaches the wire)."""
    return bool(call.get("up_local")) and call.get("req_framing") is not None


def stream_filter(base: str, streams: list) -> str:
    return f"{base} && tcp.stream in {{{', '.join(str(s) for s in streams)}}}"


def decrypted_requests(pcap: str, keylog: str, model_streams: list) -> tuple[list[dict], list[str]]:
    """Every HTTP request tshark reads with the key log on the model host's connections (the gateway's upstream
    connections), in capture order, with the client port of its connection. A frame holding more than one request is
    returned as ambiguous rather than guessed."""
    if not model_streams:
        return [], []
    rows = vm_gate.tshark_rows(pcap, stream_filter("http.request", model_streams),
                               ["frame.number", "tcp.stream", "tcp.srcport", "http.request.method", "http.request.uri",
                                "http.content_length"], keylog=keylog)
    out, ambiguous = [], []
    for row in rows:
        frame, stream, port, method, uri, clen = vm_gate.cols(row, 6)
        if "," in method:
            ambiguous.append(frame)
            continue
        out.append(dict(frame=frame, stream=stream, port=vm_gate.first(port), method=method, uri=uri,
                        content_length=int(clen) if clen.isdigit() else None))
    return out, ambiguous


def pair_calls(calls: list, decrypted: list) -> tuple[list[dict], list[dict]]:
    """Pairs each logged call with the decrypted request the gateway sent for it: same upstream connection (the
    gateway's local port, which is the request's client port in the capture), in order within that connection.
    The gateway writes a call's log line when the call ends, so log order is the order calls finished; order within
    one connection is still the order they were sent, because HTTP/1.1 sends one request at a time per connection.
    Returns the pairs in log order and the decrypted requests no logged call accounts for."""
    by_port = {}
    for d in decrypted:
        by_port.setdefault(d["port"], []).append(d)
    sent = {}
    for c in calls:
        if on_wire(c):
            sent.setdefault(c["up_local"].rsplit(":", 1)[1], []).append(c)
    match = {}
    unpaired = []
    for port in set(by_port) | set(sent):
        cs = sorted(sent.get(port, []), key=lambda c: c.get("t") or 0)
        ds = by_port.get(port, [])
        for i, c in enumerate(cs):
            match[id(c)] = ds[i] if i < len(ds) else None
        unpaired += ds[len(cs):]
    pairs = []
    for c in calls:
        d = match.get(id(c))
        logged = c.get("req_body_bytes", 0)
        dec = d["content_length"] if d else None
        pairs.append(dict(conn=c.get("conn"), seq=c.get("seq"), up_conn=c.get("up_conn"),
                          port=(c.get("up_local") or ":").rsplit(":", 1)[1] or None, method=c.get("method"),
                          path=(c.get("path") or "").split("?")[0], model=is_model_path(c.get("path")),
                          on_wire=on_wire(c), req_framing=c.get("req_framing"), status=c.get("status"),
                          logged=logged, decrypted=dec, frame=d["frame"] if d else None,
                          stream=d["stream"] if d else None,
                          agree=d is not None and (dec if dec is not None else 0) == logged))
    return pairs, unpaired


def label_calls(pcap: str, keylog: str, calls: list, model_streams: list) -> dict:
    """The per-call label table for one run: which decrypted request carried each logged call, and whether its
    decrypted length equals the gateway's logged length (the gate's V4 check, here for a real multi-call run).
    model_streams are the capture's TCP streams to the model host, which carry every call the gateway forwards.

    agreement is measured over model calls sent to the endpoint, the request bodies the byte-budget analysis depends
    on; other calls (for example a connectivity check) and calls that never reached the endpoint are listed but not
    counted. A request sent chunked has no declared length and counts as not agreeing. ok needs agreement 1.0, no
    decrypted request left unpaired, no ambiguous frame, and nothing on the model host's connections readable as HTTP
    without the key log."""
    decrypted, ambiguous = decrypted_requests(pcap, keylog, model_streams)
    plain = vm_gate.tshark_rows(pcap, stream_filter("http", model_streams), ["frame.number"]) if model_streams else []
    pairs, unpaired = pair_calls(calls, decrypted)
    counted = [p for p in pairs if p["model"] and p["on_wire"]]
    agreement = (sum(p["agree"] for p in counted) / len(counted)) if counted else None
    ok = agreement == 1.0 and not unpaired and not ambiguous and not plain
    return dict(model_streams=list(model_streams), decrypted=decrypted, pairs=pairs, unpaired_decrypted=unpaired,
                ambiguous_frames=ambiguous, not_on_wire=[p for p in pairs if not p["on_wire"]],
                model_pairs=len(counted), model_agree=sum(p["agree"] for p in counted), agreement=agreement,
                without_keylog=len(plain), ok=ok)


# ---------------------------------------------------------------- every tool call, from the agent's event output
def utf8_len(value) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def block_text(content) -> str:
    if isinstance(content, str):
        return content
    return "".join(x.get("text", "") for x in content or [] if isinstance(x, dict))


def claude_events(stdout: str) -> dict:
    """Claude Code stream-json: the final result event, its answer, and every tool call with its result. A call made
    inside a subagent carries the id of the subagent's tool call in parent."""
    calls, by_id, result = [], {}, {}
    for line in stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        kind = ev.get("type")
        content = (ev.get("message") or {}).get("content")
        if kind == "assistant" and isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    name = b.get("name", "")
                    rec = dict(tool=name, source="mcp" if name.startswith("mcp__") else "builtin", id=b.get("id"),
                               parent=ev.get("parent_tool_use_id"), input_bytes=utf8_len(b.get("input")),
                               output_bytes=None, is_error=None)
                    calls.append(rec)
                    by_id[b.get("id")] = rec
        elif kind == "user" and isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("tool_use_id") in by_id:
                    by_id[b["tool_use_id"]].update(output_bytes=utf8_len(block_text(b.get("content"))),
                                                   is_error=bool(b.get("is_error")))
        elif kind == "result":
            result = ev
    return dict(answer=str(result.get("result", "")) if result else "", tool_calls=calls,
                result={k: result.get(k) for k in ("subtype", "is_error", "num_turns", "stop_reason",
                                                   "terminal_reason", "api_error_status")} if result else {},
                permission_denials=len(result.get("permission_denials") or []) if result else 0,
                error=None if result and result.get("subtype") == "success" and not result.get("is_error")
                else (f"result {result.get('subtype')}" if result else "no result event"))


CODEX_NOT_TOOLS = {"agent_message", "reasoning", "error", "todo_list"}


def codex_events(stdout: str) -> dict:
    """Codex exec --json: every tool call (shell commands, MCP calls, and any other tool item) and turn failures."""
    calls, errors, usage = [], [], {}
    for line in stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        kind = ev.get("type")
        if kind == "item.completed":
            it = ev.get("item") or {}
            t = it.get("type")
            if t == "command_execution":
                calls.append(dict(tool="command_execution", source="builtin", id=it.get("id"), parent=None,
                                  input_bytes=utf8_len(it.get("command")),
                                  output_bytes=utf8_len(it.get("aggregated_output")),
                                  is_error=it.get("status") == "failed" or it.get("exit_code") not in (0, None)))
            elif t == "mcp_tool_call":
                res = it.get("result") or {}
                calls.append(dict(tool=f"mcp__{it.get('server')}__{it.get('tool')}", source="mcp", id=it.get("id"),
                                  parent=None, input_bytes=utf8_len(it.get("arguments")),
                                  output_bytes=utf8_len(block_text(res.get("content"))),
                                  is_error=bool(it.get("error")) or it.get("status") == "failed"))
            elif t and t not in CODEX_NOT_TOOLS:
                calls.append(dict(tool=t, source="builtin", id=it.get("id"), parent=None, input_bytes=None,
                                  output_bytes=None, is_error=it.get("status") == "failed"))
        elif kind == "turn.failed":
            errors.append(str((ev.get("error") or {}).get("message") or ev)[:300])
        elif kind == "turn.completed":
            usage = ev.get("usage") or {}
    return dict(tool_calls=calls, usage=usage, error="; ".join(errors) if errors else None)


# ---------------------------------------------------------------- one benign run
def seed_workspace(ws: str, task: dict) -> None:
    for rel, content in task.get("inputs", {}).items():
        full = os.path.join(ws, rel)
        os.makedirs(os.path.dirname(full) or ws, exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)


def template_id(meta: dict) -> str:
    sha = (meta.get("codex_plugins") or {}).get("sha")
    return f"{meta['agent']}-{meta['version']}@{meta.get('saved')}" + (f"+plugins:{sha[:12]}" if sha else "")


def delete_keylogs(root: str) -> int:
    removed = 0
    for base, _, files in os.walk(root):
        for f in files:
            if f.endswith(".keys"):
                os.remove(os.path.join(base, f))
                removed += 1
    return removed


def stop_namespace_processes(ns: str) -> int:
    """Kills every process still in a run's namespace (a gateway, agent, tool server or capture left by an interrupted
    run), so nothing outlives the run. Returns how many there were."""
    r = subprocess.run(["ip", "netns", "pids", ns], capture_output=True, text=True)
    pids = [int(p) for p in r.stdout.split() if p.isdigit()]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return len(pids)


def stop_processes_under(path: str) -> int:
    """Kills every process whose command line names a file under path (this pilot's output folder): the last
    safeguard when the pilot stops, for a process whose namespace was already removed."""
    path = os.path.abspath(path)
    killed = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().decode("utf-8", "replace")
        except OSError:
            continue
        if path in cmdline:
            try:
                os.kill(int(pid), signal.SIGKILL)
                killed += 1
            except ProcessLookupError:
                pass
    return killed


def write_json(path: str, data) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1, default=str)
    os.replace(tmp, path)


def run_once(gate: vm_gate.Gate, which: str, task: dict, repeat: int, index: int, template: dict,
             run_dir: str) -> dict:
    """One benign run of one task with one agent, through the gateway, from a copy of the warm template home, in its
    own namespace. Mirrors vm_gate.Gate.agent for the plumbing, with this task's prompt and workspace, the four benign
    MCP tools allowed, and the agent's event output. Writes labels.json from the key log and deletes the key log, then
    deletes the run's home."""
    os.makedirs(run_dir, exist_ok=True)
    home, ws = os.path.join(run_dir, "home"), os.path.join(run_dir, "ws")
    keylog = os.path.join(run_dir, "gw.keys")
    try:
        homes.copy_template(template["home"], home)
        os.makedirs(ws, exist_ok=True)
        seed_workspace(ws, task)
        tool_log = os.path.join(run_dir, "tools.jsonl")
        mcp = {"command": sys.executable, "args": [MCP], "env": {"UT_TOOL_LOG": tool_log, "UT_WORKSPACE": ws}}
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("ANTHROPIC_", "OPENAI_", "CODEX_", "CLAUDE_"))
               and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
        env.update(HOME=home, UT_TOOL_LOG=tool_log, UT_WORKSPACE=ws)
        last_message = os.path.join(run_dir, "last_message.txt")
        start_iso = end_iso = None
        code, out, err, took = "not started", "", "", 0.0
        with netns.RunNet(index) as net:
            cap = net.capture(os.path.join(run_dir, "run.pcap"))
            gw = log = None
            try:
                if which == "claude":
                    gw, log, _ = gate.start_gateway(net, run_dir, "gw", ANTHROPIC_BASE, 8081)
                    cfg = os.path.join(run_dir, "mcp.json")
                    with open(cfg, "w") as f:
                        json.dump({"mcpServers": {"bench": dict(mcp, type="stdio")}}, f)
                    env.update(ANTHROPIC_BASE_URL="http://127.0.0.1:8081", ANTHROPIC_AUTH_TOKEN=gate.key,
                               ANTHROPIC_MODEL="deepseek-flash[1m]", ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-flash[1m]",
                               ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-flash[1m]",
                               ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-flash")
                    cmd = ["claude", "-p", task["prompt"], "--mcp-config", cfg, "--strict-mcp-config",
                           "--allowedTools", ",".join(ALLOWED_TOOLS), "--output-format", "stream-json", "--verbose",
                           "--max-turns", str(CLAUDE_MAX_TURNS)]
                else:
                    gw, log, _ = gate.start_gateway(net, run_dir, "gw", RESPONSES_BASE, 8082)
                    codex_home = os.path.join(home, ".codex")
                    os.makedirs(codex_home, exist_ok=True)
                    with open(os.path.join(codex_home, "config.toml"), "w") as f:
                        f.write(codex_config("http://127.0.0.1:8082", mcp))
                    env.update(CODEX_HOME=codex_home, DEEPSEEK_API_KEY=gate.key)
                    cmd = ["codex", "exec", "--skip-git-repo-check", "--ephemeral", "--json", "-C", ws, "-o",
                           last_message, task["prompt"]]
                t0 = time.time()
                start_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
                try:
                    p = subprocess.run(net.cmd(cmd), env=env, cwd=ws, stdin=subprocess.DEVNULL, capture_output=True,
                                       text=True, timeout=AGENT_TIMEOUT)
                    code, out, err = p.returncode, p.stdout, p.stderr
                except subprocess.TimeoutExpired as e:
                    code = "timeout"
                    out = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
                    err = e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
                took = time.time() - t0
                end_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            finally:
                try:
                    time.sleep(1)
                    if gw:
                        gate.stop(gw)
                    cap.stop()
                finally:
                    leftover = stop_namespace_processes(net.ns)
            meta = net.write_metadata(os.path.join(run_dir, "net.json"))
            fl = vm_gate.flows(cap.path, net.ns_ip)
            events = vm_gate.close_events(cap.path, net.ns_ip)
            wire = vm_gate.wire_facts(cap.path, fl, meta)
            hosts = vm_gate.host_table(cap.path, net.ns_ip, fl)
        with open(os.path.join(run_dir, "agent_stdout.txt"), "w") as f:
            f.write(out)
        with open(os.path.join(run_dir, "agent_stderr.txt"), "w") as f:
            f.write(err)
        calls = vm_gate.read_jsonl(log, "call") if log else []
        model_streams = sorted((s for s, f in fl.items() if f.get("sni") == MODEL_HOST), key=int)
        labels = label_calls(cap.path, keylog, calls, model_streams) if os.path.exists(keylog) else None
        if labels is not None:
            write_json(os.path.join(run_dir, "labels.json"), labels)
    except BaseException:
        shutil.rmtree(home, ignore_errors=True)   # an interrupted run keeps no home copy either
        raise
    finally:
        if os.path.exists(keylog):
            os.remove(keylog)
    if which == "claude":
        ev = claude_events(out)
        answer = ev["answer"]
    else:
        ev = codex_events(out)
        answer = ""
        if os.path.exists(last_message):
            with open(last_message) as f:
                answer = f.read()
    with open(os.path.join(run_dir, "agent_tools.jsonl"), "w") as f:
        for c in ev["tool_calls"]:
            f.write(json.dumps(c) + "\n")
    tools = vm_gate.read_jsonl(tool_log, "tool_call")
    model_calls = [c for c in calls if is_model_path(c.get("path"))]
    statuses = [c.get("status") for c in model_calls]
    endpoint_errors = [c["error"] for c in calls if c.get("error") and c.get("error_side") != "agent"]
    completed = (code == 0 and bool(statuses) and all(s == 200 for s in statuses) and not endpoint_errors
                 and ev["error"] is None)
    background = vm_gate.background_downloads(hosts)
    wire_ok, wire_fails = vm_gate.wire_verdict(wire)
    outputs_written = [o for o in task.get("outputs", []) if os.path.exists(os.path.join(ws, o))]
    mcp_events = [c for c in ev["tool_calls"] if c["source"] == "mcp"]
    shutil.rmtree(home, ignore_errors=True)
    key_found_in = homes.find_secret(run_dir, gate.key)
    return dict(
        run_id=os.path.basename(run_dir), task=task["id"], scenario=task["scenario"], agent=which,
        version=homes.agent_version(which), model="deepseek-flash", repeat=repeat, index=index,
        template_home=template["id"], template_saved=template.get("saved"),
        codex_plugins_sha=template.get("codex_plugins_sha"), start=start_iso, end=end_iso, seconds=round(took, 1),
        exit=code, answer=answer.strip()[-200:], model_calls=len(model_calls), model_statuses=statuses,
        model_request_bytes=sum(c.get("req_body_bytes", 0) for c in model_calls), endpoint_errors=endpoint_errors,
        agent_error=ev["error"], completed=completed, permission_denials=ev.get("permission_denials", 0),
        mcp_tool_calls=[(t["tool"], t["args_bytes"]) for t in tools],
        agent_tool_calls=[(c["tool"], c["source"], c["input_bytes"], c["output_bytes"]) for c in ev["tool_calls"]],
        builtin_tool_calls=len(ev["tool_calls"]) - len(mcp_events), mcp_event_calls=len(mcp_events),
        mcp_log_matches=len(mcp_events) == len(tools), outputs_written=outputs_written,
        wire_clean=wire_ok, wire_fails=wire_fails, wire=wire, hosts=hosts,
        drops=vm_gate.upstream_drops(calls, events), background_over_limit=background,
        codex_ab_chatgpt_up=hosts.get(CODEX_BACKGROUND_HOST, {}).get("up", 0),
        model_flows=len(vm_gate.model_flows(fl)), processes_left_in_namespace=leftover,
        label_agreement=labels["agreement"] if labels else None, labels_ok=bool(labels and labels["ok"]),
        labels_written=labels is not None, key_found_in=key_found_in, has_calls=bool(calls),
        stderr_tail=err.strip()[-300:])


MANIFEST_KEYS = ("run_id", "task", "scenario", "agent", "version", "model", "repeat", "home_template", "start",
                 "end", "exit", "model_statuses", "wire_verdict", "bytes_per_host")


def manifest_complete(manifest: dict) -> bool:
    return (all(manifest.get(k) not in (None, "") for k in MANIFEST_KEYS) and bool(manifest.get("bytes_per_host"))
            and manifest.get("labels_written") is True)


def write_manifest(run_dir: str, record: dict) -> dict:
    """The run manifest: task, agent, version, model, repeat, home template id, start and end times, exit status,
    model-call statuses, wire verdict, bytes per host, drops, labels summary and tool-call counts."""
    manifest = dict(
        run_id=record["run_id"], task=record["task"], scenario=record["scenario"], agent=record["agent"],
        version=record["version"], model=record["model"], repeat=record["repeat"],
        home_template=record["template_home"], home_template_saved=record["template_saved"],
        codex_plugins_sha=record["codex_plugins_sha"], start=record["start"], end=record["end"],
        seconds=record["seconds"], exit=record["exit"], model_calls=record["model_calls"],
        model_statuses=record["model_statuses"], model_request_bytes=record["model_request_bytes"],
        endpoint_errors=record["endpoint_errors"], agent_error=record["agent_error"], completed=record["completed"],
        wire_verdict="clean" if record["wire_clean"] else "fail", wire_fails=record["wire_fails"],
        bytes_per_host=record["hosts"], drops=record["drops"], reran_after_drop=record.get("reran_after_drop", False),
        flagged_drop=record.get("flagged_drop", False), background_over_limit=record["background_over_limit"],
        codex_ab_chatgpt_up=record["codex_ab_chatgpt_up"], labels_written=record["labels_written"],
        label_agreement=record["label_agreement"], labels_ok=record["labels_ok"],
        mcp_tool_calls=record["mcp_tool_calls"], agent_tool_calls=record["agent_tool_calls"],
        builtin_tool_calls=record["builtin_tool_calls"], mcp_log_matches=record["mcp_log_matches"],
        permission_denials=record["permission_denials"], outputs_written=record["outputs_written"],
        processes_left_in_namespace=record["processes_left_in_namespace"], key_found_in=record["key_found_in"],
        balance_before=record.get("balance_before"), answer=record["answer"])
    manifest["complete"] = manifest_complete(manifest)
    write_json(os.path.join(run_dir, "manifest.json"), manifest)
    return manifest


def summary_row(rec: dict, manifest: dict, note: str) -> dict:
    return dict(run_id=rec["run_id"], task=rec["task"], scenario=rec["scenario"], agent=rec["agent"],
                repeat=rec["repeat"], exit=rec["exit"], seconds=rec["seconds"], completed=rec["completed"],
                model_calls=rec["model_calls"], model_statuses=rec["model_statuses"],
                model_request_bytes=rec["model_request_bytes"], wire_clean=rec["wire_clean"],
                labels_ok=rec["labels_ok"], label_agreement=rec["label_agreement"],
                builtin_tool_calls=rec["builtin_tool_calls"], mcp_tool_calls=len(rec["mcp_tool_calls"]),
                mcp_log_matches=rec["mcp_log_matches"], background_over_limit=rec["background_over_limit"],
                codex_ab_chatgpt_up=rec["codex_ab_chatgpt_up"], manifest_complete=manifest["complete"],
                reran_after_drop=rec.get("reran_after_drop", False), flagged_drop=rec.get("flagged_drop", False),
                drops=len(rec["drops"]), key_found_in=rec["key_found_in"], balance_before=rec.get("balance_before"),
                template=rec["template_home"], note=note, answer=rec["answer"][-60:])


def row_from_manifest(manifest: dict) -> dict:
    """The report row of a run whose manifest was written but whose row was not (a session stopped in between)."""
    m = manifest
    return dict(run_id=m["run_id"], task=m["task"], scenario=m["scenario"], agent=m["agent"], repeat=m["repeat"],
                exit=m["exit"], seconds=m["seconds"], completed=m["completed"], model_calls=m["model_calls"],
                model_statuses=m["model_statuses"], model_request_bytes=m["model_request_bytes"],
                wire_clean=m["wire_verdict"] == "clean", labels_ok=m["labels_ok"],
                label_agreement=m["label_agreement"], builtin_tool_calls=m["builtin_tool_calls"],
                mcp_tool_calls=len(m["mcp_tool_calls"]), mcp_log_matches=m["mcp_log_matches"],
                background_over_limit=m["background_over_limit"], codex_ab_chatgpt_up=m["codex_ab_chatgpt_up"],
                manifest_complete=m["complete"], reran_after_drop=m["reran_after_drop"],
                flagged_drop=m["flagged_drop"], drops=len(m["drops"]), key_found_in=m["key_found_in"],
                balance_before=m["balance_before"], template=m["home_template"], note="row rebuilt from the manifest",
                answer=(m["answer"] or "")[-60:])


def error_row(run_id: str, task: dict, which: str, repeat: int, exc: BaseException) -> dict:
    return dict(run_id=run_id, task=task["id"], scenario=task["scenario"], agent=which, repeat=repeat, error=True,
                note=f"run stopped on {type(exc).__name__}: {exc}",
                traceback=traceback.format_exc()[-2000:])


def describe_run(rec: dict, manifest: dict) -> str:
    return (f"exit {rec['exit']} in {rec['seconds']} s, completed {rec['completed']}; model calls {rec['model_calls']} "
            f"(statuses {rec['model_statuses']}); wire "
            f"{'clean' if rec['wire_clean'] else 'FAIL ' + str(rec['wire_fails'])}; labels ok {rec['labels_ok']} "
            f"(agreement {rec['label_agreement']}); tool calls {rec['agent_tool_calls']}; MCP log matches "
            f"{rec['mcp_log_matches']}; bytes per host {vm_gate.describe_hosts(rec['hosts'])}; manifest complete "
            f"{manifest['complete']}"
            + (f"; background over {BACKGROUND_DOWNLOAD_LIMIT:,} B {rec['background_over_limit']}"
               if rec["background_over_limit"] else "")
            + (f"; API KEY FOUND IN {rec['key_found_in']}" if rec["key_found_in"] else ""))


# ---------------------------------------------------------------- the pilot
def make_templates(gate: vm_gate.Gate) -> dict:
    """One warm template home per agent version, made and checked exactly as the gate's H1 does. The warm-up runs'
    key logs and home copies are deleted once the templates are saved."""
    made = gate.warm_homes()
    templates = {}
    for which in made:
        t = homes.load_template(vm_gate.HOMES_ROOT, which, homes.agent_version(which))
        templates[which] = dict(home=t["home"], id=template_id(t), saved=t.get("saved"),
                                codex_plugins_sha=(t.get("codex_plugins") or {}).get("sha"))
    delete_keylogs(gate.out)
    if os.path.isdir(gate.out):
        for name in os.listdir(gate.out):
            shutil.rmtree(os.path.join(gate.out, name, "home"), ignore_errors=True)
    return templates


def plan(only_task: str | None, only_agent: str | None) -> list[tuple[dict, str, int]]:
    tasks = [t for t in pilot_tasks.TASKS if only_task is None or t["id"] == only_task]
    if only_task and not tasks:
        raise ValueError(f"no task {only_task}")
    agents = [only_agent] if only_agent else AGENTS
    return [(t, a, r) for t in tasks for a in agents for r in range(1, REPEATS + 1)]


def run_name(task: dict, which: str, repeat: int) -> str:
    return f"{task['id']}__{which}__r{repeat}"


def run_done(runs_dir: str, run_id: str) -> bool:
    return os.path.exists(os.path.join(runs_dir, run_id, "manifest.json"))


def set_aside(path: str, suffix: str) -> str:
    """Moves a run folder out of the way (a flagged first attempt, a run that stopped on an error, or a run left by a
    stopped session), without its home copy and key log."""
    shutil.rmtree(os.path.join(path, "home"), ignore_errors=True)
    delete_keylogs(path)
    dest, k = f"{path}__{suffix}1", 1
    while os.path.exists(dest):
        k += 1
        dest = f"{path}__{suffix}{k}"
    os.rename(path, dest)
    return dest


def kept_rows(rows: list) -> list:
    return [r for r in rows if not r.get("flagged_drop") and not r.get("error")]


def quality_marks(rows: list, expected: int, stopped_early: str | None = None, templates_ok: bool = True) -> dict:
    kept = kept_rows(rows)
    pilot_runs = [r for r in rows if not r.get("error")]
    n = len(kept)
    marks = dict(expected_runs=expected, runs=n, error_runs=sum(1 for r in rows if r.get("error")),
                 flagged_first_attempts=sum(1 for r in rows if r.get("flagged_drop")), stopped_early=stopped_early,
                 templates_ok=templates_ok)
    complete_set = n == expected and not stopped_early and templates_ok
    if not n:
        marks.update(Q1_wire=None, Q2_labels=None, Q3_background=None, Q4_manifests=None, Q5_completed=None,
                     complete_set=complete_set, all_pass=False)
        return marks
    clean = sum(1 for r in kept if r["wire_clean"])
    done = sum(1 for r in kept if r["completed"])
    q1 = clean / n >= WIRE_CLEAN_MIN
    q2 = all(r["labels_ok"] is True for r in kept)
    q3 = all(not r["background_over_limit"] for r in pilot_runs)
    q4 = all(r["manifest_complete"] for r in kept)
    q5 = done / n >= COMPLETED_MIN
    marks.update(wire_clean=clean, wire_clean_fraction=round(clean / n, 4), completed=done,
                 completed_fraction=round(done / n, 4), Q1_wire=q1, Q2_labels=q2, Q3_background=q3,
                 Q4_manifests=q4, Q5_completed=q5, complete_set=complete_set)
    marks["all_pass"] = bool(q1 and q2 and q3 and q4 and q5 and complete_set)
    return marks


def codex_background_report(rows: list) -> dict:
    """Codex's upload to ab.chatgpt.com against run time and model calls."""
    out = [dict(run_id=r["run_id"], task=r["task"], seconds=r["seconds"], model_calls=r["model_calls"],
                model_request_bytes=r["model_request_bytes"], ab_chatgpt_up=r["codex_ab_chatgpt_up"],
                up_per_second=round(r["codex_ab_chatgpt_up"] / r["seconds"], 1) if r["seconds"] else None)
           for r in kept_rows(rows) if r["agent"] == "codex"]
    total_s = sum(r["seconds"] for r in out)
    total_up = sum(r["ab_chatgpt_up"] for r in out)
    return dict(runs=out, total_seconds=round(total_s, 1), total_up=total_up,
                up_per_second=round(total_up / total_s, 1) if total_s else None)


def finish(report: dict, out: str, final: bool) -> None:
    report["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    report["final"] = final
    report["quality_marks"] = quality_marks(report["runs"], report["expected_runs"], report.get("stopped_early"),
                                            report.get("templates_ok", False))
    report["codex_background"] = codex_background_report(report["runs"])
    write_json(os.path.join(out, "pilot.json"), report)


def run_pilot(key: str, out: str, balance_floor: float, only_task: str | None, only_agent: str | None,
              resume: bool = False) -> dict:
    pilot_tasks.validate()
    runs_dir = os.path.join(out, "runs")
    os.makedirs(runs_dir, exist_ok=True)
    session = time.strftime("%Y%m%d_%H%M%S")
    old = {}
    if resume and os.path.exists(os.path.join(out, "pilot.json")):
        with open(os.path.join(out, "pilot.json")) as f:
            old = json.load(f)
        only_task, only_agent = old.get("only_task"), old.get("only_agent")   # a resumed pilot keeps its plan
    planned = plan(only_task, only_agent)
    report = dict(stamp=os.path.basename(out), started=old.get("started") or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                  sessions=old.get("sessions", []) + [session], balance_floor=balance_floor,
                  only_task=only_task, only_agent=only_agent, expected_runs=len(planned),
                  balance_before=old.get("balance_before"), runs=old.get("runs", []), stopped_early=None,
                  templates_ok=False, gate=old.get("gate", []))
    gate = vm_gate.Gate(os.path.join(out, "warmups", session), key)

    bal, stop = check_balance(key, balance_floor)
    report["balance_before"] = report["balance_before"] or bal
    print(f"balance before: {bal}", flush=True)
    if stop:
        report["stopped_early"] = f"{stop}, before the warm-up runs"
        finish(report, out, True)
        return report
    if not gate.environment():
        report["stopped_early"] = "V0 environment failed"
        report["gate"] += gate.results
        finish(report, out, True)
        return report
    netns.cleanup_all()
    templates = make_templates(gate)
    report["gate"] += gate.results
    report["templates"] = report.get("templates", []) + [dict(session=session, **templates)]
    agents = sorted({a for _, a, _ in planned})
    report["templates_ok"] = all(a in templates for a in agents)
    finish(report, out, False)

    index = FIRST_INDEX - 1

    def next_index():
        nonlocal index
        index = index + 1 if index < LAST_INDEX else FIRST_INDEX
        return index

    for task, which, repeat in planned:
        run_id = run_name(task, which, repeat)
        run_dir = os.path.join(runs_dir, run_id)
        if run_done(runs_dir, run_id):
            if not any(r["run_id"] == run_id and not r.get("error") for r in report["runs"]):
                with open(os.path.join(run_dir, "manifest.json")) as f:
                    report["runs"].append(row_from_manifest(json.load(f)))
            continue
        if which not in templates:
            print(f"SKIP {run_id}: no warm template home for {which}", flush=True)
            continue
        if os.path.exists(run_dir):
            set_aside(run_dir, "unfinished")   # left by a stopped session: kept, not counted
        bal, stop = check_balance(key, balance_floor)
        if stop:
            report["stopped_early"] = f"{stop}, before {run_id}"
            report["balance_after"] = bal
            print(report["stopped_early"], flush=True)
            finish(report, out, True)
            return report
        print(f"\n=== {run_id} ===", flush=True)
        try:
            rec = run_once(gate, which, task, repeat, next_index(), templates[which], run_dir)
            rec["balance_before"] = bal.get("total_balance")
            note = ""
            if rec["drops"] and rec["has_calls"]:
                note = f"endpoint dropped a model call ({vm_gate.describe_drops(rec['drops'])}); rerun once"
                print(note, flush=True)
                first_dir = set_aside(run_dir, "drop")
                first = dict(rec, run_id=os.path.basename(first_dir), flagged_drop=True)
                first_manifest = write_manifest(first_dir, first)
                report["runs"].append(summary_row(first, first_manifest, "flagged first attempt (endpoint drop)"))
                finish(report, out, False)
                bal, stop = check_balance(key, balance_floor)
                if stop:
                    report["stopped_early"] = f"{stop}, before the rerun of {run_id}"
                    report["balance_after"] = bal
                    finish(report, out, True)
                    return report
                rec = run_once(gate, which, task, repeat, next_index(), templates[which], run_dir)
                rec.update(balance_before=bal.get("total_balance"), reran_after_drop=True)
                if rec["drops"]:
                    note += f"; the rerun had an endpoint drop too ({vm_gate.describe_drops(rec['drops'])})"
            manifest = write_manifest(run_dir, rec)
            print(describe_run(rec, manifest), flush=True)
            report["runs"].append(summary_row(rec, manifest, note))
        except Exception as e:
            row = error_row(run_id, task, which, repeat, e)
            print(f"ERROR {run_id}: {row['note']}", flush=True)
            delete_keylogs(run_dir)
            if os.path.exists(run_dir):
                row["run_dir"] = os.path.basename(set_aside(run_dir, "error"))
            report["runs"].append(row)
            try:
                netns.cleanup_all()
            except Exception:
                pass
        finish(report, out, False)

    report["balance_after"] = read_balance(key)
    finish(report, out, True)
    return report


# ---------------------------------------------------------------- upload bundles to Google Cloud Storage
def upload_blockers(out: str, key: str) -> list[str]:
    """Reasons not to upload: any key log left, or any file that contains the API key."""
    reasons = []
    left = [os.path.relpath(os.path.join(b, f), out) for b, _, fs in os.walk(out) for f in fs if f.endswith(".keys")]
    if left:
        reasons.append(f"key logs still present: {left}")
    hits = homes.find_secret(out, key)
    if hits:
        reasons.append(f"API key found in {hits}")
    return reasons


def upload_to_gcs(out: str, gcs_prefix: str, key: str) -> dict:
    """Copy the pilot output (captures, logs, manifests, labels, pilot.json) to a GCS bucket with gsutil, so a Colab
    cell can bring the bundles into Drive. Refused while any key log is left or any file contains the API key; key
    logs are excluded from the copy as well. gsutil uses the VM's own service-account credentials."""
    dest = gcs_prefix.rstrip("/") + "/" + os.path.basename(out)
    blockers = upload_blockers(out, key)
    if blockers:
        print(f"upload REFUSED: {'; '.join(blockers)}", flush=True)
        return dict(ok=False, dest=dest, refused=blockers)
    r = subprocess.run(["gsutil", "-m", "rsync", "-r", "-x", r".*\.keys$", out, dest], capture_output=True, text=True)
    ok = r.returncode == 0
    print((r.stdout or "")[-2000:]); print((r.stderr or "")[-2000:])
    print(f"{'uploaded to' if ok else 'upload FAILED to'} {dest}", flush=True)
    return dict(ok=ok, dest=dest, returncode=r.returncode)


def stop_on_signal(signum, frame):
    for s in (signal.SIGHUP, signal.SIGTERM):   # a second signal must not cut the clean-up short
        signal.signal(s, signal.SIG_IGN)
    raise SystemExit(f"stopped by signal {signum}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--upload", default=None, help="gs://bucket/prefix to copy the finished bundles to (optional)")
    ap.add_argument("--balance-floor", type=float, default=DEFAULT_BALANCE_FLOOR,
                    help="stop before a run if the DeepSeek balance is at or below this")
    ap.add_argument("--only-task", default=None, help="run a single task id (a smoke test)")
    ap.add_argument("--only-agent", default=None, choices=AGENTS, help="run a single agent")
    ap.add_argument("--resume", default=None, metavar="STAMP",
                    help="continue the pilot in data/harness/pilot/STAMP, skipping runs that have a manifest")
    a = ap.parse_args(argv)

    key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not key and sys.stdin.isatty():
        import getpass
        key = getpass.getpass("DeepSeek API key: ")
        os.environ["DEEPSEEK_API_KEY"] = key
    if not key:
        print("DEEPSEEK_API_KEY not set", file=sys.stderr)
        return 1
    for s in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(s, stop_on_signal)
    stale = delete_keylogs(PILOT_ROOT) if os.path.isdir(PILOT_ROOT) else 0
    if a.resume:
        out = os.path.join(PILOT_ROOT, a.resume)
        if not os.path.isdir(out):
            print(f"no pilot to resume at {out}", file=sys.stderr)
            return 1
    else:
        out = os.path.join(PILOT_ROOT, time.strftime("%Y%m%d_%H%M%S"))
        os.makedirs(out, exist_ok=True)
    print(f"benign collection pilot {os.path.basename(out)}{' (resumed)' if a.resume else ''}, output {out}; "
          f"stale key logs deleted: {stale}\n", flush=True)
    report = {}
    try:
        report = run_pilot(key, out, a.balance_floor, a.only_task, a.only_agent, resume=bool(a.resume))
    finally:
        stopped = stop_processes_under(out)
        try:
            netns.cleanup_all()
        except Exception:
            pass
        print(f"\nkey logs deleted: {delete_keylogs(out)}; processes stopped: {stopped}", flush=True)
    marks = report.get("quality_marks", {})
    print("\nPILOT QUALITY MARKS")
    for k in ("Q1_wire", "Q2_labels", "Q3_background", "Q4_manifests", "Q5_completed", "complete_set"):
        print(f"  {'PASS' if marks.get(k) else 'FAIL' if marks.get(k) is not None else 'n/a'}  {k}")
    print(f"\n{'PASS' if marks.get('all_pass') else 'FAIL'}  pilot ({marks.get('runs', 0)} kept runs of "
          f"{marks.get('expected_runs')} planned, wire clean {marks.get('wire_clean_fraction')}, completed "
          f"{marks.get('completed_fraction')}, runs stopped on an error {marks.get('error_runs')})")
    print(f"balance before {(report.get('balance_before') or {}).get('total_balance')}, "
          f"after {(report.get('balance_after') or {}).get('total_balance')}")
    if report.get("stopped_early"):
        print(f"stopped early: {report['stopped_early']}")
    if a.upload and report:
        report["upload"] = upload_to_gcs(out, a.upload, key)
        write_json(os.path.join(out, "pilot.json"), report)
    return 0 if marks.get("all_pass") else 1


if __name__ == "__main__":
    sys.exit(main())
