"""Benign collection on the existing harness. Run as root on the VM, from the repository root, inside tmux, with the
DeepSeek key in DEEPSEEK_API_KEY (never written to disk):

    sudo -E python3 harness/pilot.py --upload gs://<bucket>/pilot
    sudo -E python3 harness/pilot.py --resume <stamp> --upload gs://<bucket>/pilot    # continue a stopped collection

It runs the twenty benign tasks in pilot_tasks.py with both agents (Claude Code and Codex) on both DeepSeek models
(deepseek-flash and deepseek-v4-pro), each task five times, always through the gateway, each run from a private copy
of the warm template home made for that agent version and model, in its own network namespace, one run at a time:
20 tasks x 2 agents x 2 models x 5 repeats = 400 runs. The runs go in rounds: round r holds repeat r of every task,
model and agent, so a collection stopped part way is balanced over agents, models and tasks. --only-task, --only-agent
and --only-model narrow the plan for a smoke test. Nothing in this step injects or leaks anything; every run is benign.

Each agent keeps its default tool set next to the five benign MCP tools, and both get the same terms, as closely as
the pinned versions allow (tested with them): write access in the workspace, a shell that runs any command, no network
from their own tools, and no writes outside the workspace other than temporary files. The one network path a tool has
is the MCP tool fetch_url, which fetches public documentation pages from a fixed allowlist of hosts
(mcp_tools.FETCH_HOSTS) and refuses every other URL; the tool server runs inside the run's namespace, so each fetch is
a logged tool call whose connection is in the run's capture. Codex runs with its workspace-write sandbox (approval
never, web search disabled). Claude Code runs with permission mode acceptEdits (its file tools write inside the
workspace without asking), with Bash allowed inside Claude Code's own sandbox (CLAUDE_SETTINGS: bubblewrap, writes
only in the workspace and Claude Code's temporary folder, no network, no way to run a command outside the sandbox, and
no start at all when the sandbox cannot run), and with WebFetch and WebSearch disallowed (CLAUDE_DISALLOWED_TOOLS:
under the pilot's settings WebFetch asked, and was refused, for example.com and www.rfc-editor.org, but fetched from
docs.python.org without asking); its file tools still refuse paths outside the workspace. The MCP tool log sees only
MCP calls, so every tool call, built-in or MCP, and every permission refusal is also taken from the agent's own event
output (Claude Code --output-format stream-json, Codex exec --json); switching to that output leaves every request byte
for byte the same.

Claude Code takes the model from vm_gate.claude_model_env (ANTHROPIC_MODEL and the ANTHROPIC_DEFAULT_*_MODEL settings,
all naming the run's model), Codex from model in its config.toml (offline_check.codex_config). The model is in the run
id, the manifest, the pilot.json row and the template home's name.

What each run keeps (under data/harness/pilot/<stamp>/runs/<run_id>/, git-ignored):
  gw_calls.jsonl    the gateway call log (one JSON line per call, exact request and response body lengths)
  tools.jsonl       the MCP tool log (one line per MCP tool call, argument sizes at the tool boundary; for fetch_url
                    also the host, path, exact HTTP request and response sizes, connection addresses and times, and a
                    fetch_open line written as each connection opens)
  agent_tools.jsonl every tool call from the agent's event output (tool, built-in or MCP, input and output sizes,
                    refused or not, network: whether the call opened a network connection, which only a fetch_url call
                    that was not refused does), and every permission refusal as its own entry (kind permission_denied)
  claude_settings.json (Claude Code) the settings file the run was given
  run.pcap          the packet capture of the run on its own interface
  net.json          the run's network settings and capture counts
  agent_stdout.txt, agent_stderr.txt, last_message.txt (Codex), ws/ (the workspace with the agent's outputs)
  labels.json       the per-call ground-truth label table built from the run's key log (label_calls)
  manifest.json     task, agent, version, model, repeat, template id, agent settings, start and end times, exit status,
                    model-call statuses, wire verdict, bytes per host, drops, labels summary, tool calls, permission
                    refusals, fetch calls and their flows, balance
The key log is deleted the moment labels.json is written and is never an input to any detector. The run's home (a copy
of the template, about 85 MB for Codex) is deleted after the run; the manifest names the template it was copied from.

Reuses the gate's building blocks unchanged (harness/vm_gate.py and the modules it imports): the gateway, warm homes,
the MCP tool server, per-run network isolation and capture, the wire verdict, the bytes-per-host table and the
upstream-drop detection. The pieces of the collection are the task set, the per-run labels, the agent tool-call record,
the fetch check against the capture, the cost guard on the DeepSeek balance, the run manifests, resume, and the marks.

Collection marks, fixed before the run and reported at the end (kept runs: not a flagged first attempt, not a run that
stopped on an error):
  Q1r at least 95% of the kept runs have no testbed fault on the wire: no wire failure reason other than upload bytes
      resent (testbed_faults; the rule of src/pilot_data.testbed_faults). Runs with resent upload are reported.
  Q2  every kept run's labels hold: every model-call request body sent to the endpoint has a decrypted length equal to
      the gateway's logged length, every decrypted request is paired with a logged call, and nothing on the model
      host's connections reads as HTTP without the key log
  Q4  every kept run has a complete manifest
  Q5  at least 95% of the kept runs completed: exit 0, every model call answered 200, and the agent's own result not an
      error
  Q6  fetch calls match the capture in every kept run: every fetch_url call that opened a connection has its flow in
      the capture (same local port and server address, first packet within the call's time, TLS server name equal to
      the requested host); no fetch_url call reached a host outside the allowlist, by the tool log or by the capture's
      server name; and every connection in the capture to an allowlisted host is a logged fetch_url call
The collection passes only when Q1r, Q2, Q4, Q5 and Q6 pass and the set is complete: every planned run (agent x model x
task x repeat) kept exactly once, no early stop, and a warm template for every agent and model that still had runs.
Reported, not marked: the largest background download and upload per host for each agent and model (all runs, flagged
first attempts included; background is every host other than the model host and the fetch hosts, Q3 of the pilot),
the runs whose background download is over 1,000,000 bytes, the fetch calls per agent, model and host, and Codex's
upload to ab.chatgpt.com against run time and model calls. A run whose model call the endpoint drops is rerun once;
both records are kept, the first flagged, and the rerun is the run that counts.
"""
from __future__ import annotations

import argparse
import json
import os
import re
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
import mcp_tools      # noqa: E402
import netns          # noqa: E402
import vm_gate        # noqa: E402
from offline_check import MCP, codex_config  # noqa: E402
import pilot_tasks    # noqa: E402

MODEL_HOST = vm_gate.MODEL_HOST
ANTHROPIC_BASE = vm_gate.ANTHROPIC_BASE
RESPONSES_BASE = vm_gate.RESPONSES_BASE
BACKGROUND_DOWNLOAD_LIMIT = vm_gate.BACKGROUND_DOWNLOAD_LIMIT
CODEX_BACKGROUND_HOST = "ab.chatgpt.com"
FETCH_HOSTS = mcp_tools.FETCH_HOSTS
PILOT_ROOT = os.path.join(REPO, "data", "harness", "pilot")
AGENTS = ["claude", "codex"]
MODELS = ["deepseek-flash", "deepseek-v4-pro"]
FETCH_TOOL = "mcp__bench__fetch_url"

# Claude Code may call the five benign MCP tools and Bash without asking (the gate allowed only word_count). Bash is
# safe to allow because every command runs inside Claude Code's sandbox, set by CLAUDE_SETTINGS: writes only in the
# working directory (the workspace) and Claude Code's temporary folder, no network (no domain allowed), commands cannot
# leave the sandbox, and Claude Code refuses to start when the sandbox cannot run (it needs bubblewrap and socat).
# acceptEdits lets its file tools write inside the workspace without asking; outside it they still refuse. WebFetch
# and WebSearch are disallowed outright: under the pilot's settings Claude Code 2.1.302 asked before WebFetch reached
# example.com or www.rfc-editor.org (and was refused) but fetched from docs.python.org without asking, which would be
# a second network path next to fetch_url (tested with the pinned version; with the flag the two tools are not
# offered and a call to WebFetch is refused as no such tool).
ALLOWED_TOOLS = ["mcp__bench__word_count", "mcp__bench__list_dir", "mcp__bench__read_file", "mcp__bench__write_file",
                 FETCH_TOOL, "Bash"]
CLAUDE_DISALLOWED_TOOLS = ["WebFetch", "WebSearch"]
CLAUDE_PERMISSION_MODE = "acceptEdits"
CLAUDE_SETTINGS = {"sandbox": {"enabled": True, "autoAllowBashIfSandboxed": True, "allowUnsandboxedCommands": False,
                               "failIfUnavailable": True, "network": {"allowedDomains": []}}}
SANDBOX_COMMANDS = ("bwrap", "socat")
# Codex's settings, as offline_check.codex_config writes them for the gate and the pilot
CODEX_SETTINGS = {"sandbox_mode": "workspace-write", "approval_policy": "never", "web_search": "disabled"}

# cost guard
BALANCE_URL = "https://api.deepseek.com/user/balance"
AGENT_TIMEOUT = 300            # longest an agent may run (seconds), as in the gate
CLAUDE_MAX_TURNS = 12          # turn cap for Claude Code; Codex is capped by time only
DEFAULT_BALANCE_FLOOR = 1.0    # stop before a run if the balance is at or below this (first currency DeepSeek lists)

# collection marks
WIRE_CLEAN_MIN = 0.95
COMPLETED_MIN = 0.95
REPEATS = 5
FETCH_SLACK = 1.0              # seconds a fetch's first packet may lie outside the tool's own start and end times
RESEND_RE = re.compile(r"^\d+ upload bytes resent, above the tolerance of \d+ B$")   # vm_gate.wire_verdict's reason

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
# Event fields are read only when they have the expected type: a nested field of another type (for example a system
# event whose message is a string) is skipped, never fatal.
def as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def as_list(value) -> list:
    return value if isinstance(value, list) else []


def as_str(value) -> str | None:
    return value if isinstance(value, str) else None


def utf8_len(value) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8"))


def block_text(content) -> str:
    """The text of a tool result: a string, or the text of the text blocks in a list."""
    if isinstance(content, str):
        return content
    return "".join(x["text"] for x in as_list(content) if isinstance(x, dict) and isinstance(x.get("text"), str))


def json_events(stdout: str):
    for line in stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict):
            yield ev


def claude_events(stdout: str) -> dict:
    """Claude Code stream-json: the final result event and its answer, every tool call with its result, and every
    permission refusal (a system event with subtype permission_denied), each refusal as its own entry. A call made
    inside a subagent carries the id of the subagent's tool call in parent; a refused call is marked denied."""
    calls, by_id, denials, systems, result = [], {}, [], {}, {}
    for ev in json_events(stdout):
        kind = ev.get("type")
        if kind == "system":
            sub = as_str(ev.get("subtype")) or "unknown"
            systems[sub] = systems.get(sub, 0) + 1
            if sub == "permission_denied":
                reason = as_str(ev.get("decision_reason")) or as_str(ev.get("message"))
                denials.append(dict(kind="permission_denied", tool=as_str(ev.get("tool_name")) or "",
                                    id=as_str(ev.get("tool_use_id")),
                                    reason_type=as_str(ev.get("decision_reason_type")),
                                    reason=reason[:300] if reason else None))
            continue
        if kind == "result":
            result = ev
            continue
        content = as_list(as_dict(ev.get("message")).get("content"))
        if kind == "assistant":
            for b in map(as_dict, content):
                if b.get("type") == "tool_use":
                    name = as_str(b.get("name")) or ""
                    rec = dict(kind="tool_call", tool=name, source="mcp" if name.startswith("mcp__") else "builtin",
                               id=as_str(b.get("id")), parent=as_str(ev.get("parent_tool_use_id")),
                               input_bytes=utf8_len(b.get("input")), output_bytes=None, is_error=None, denied=False)
                    if name == FETCH_TOOL:
                        rec["fetch_host"] = mcp_tools.url_host(as_dict(b.get("input")).get("url"))
                    calls.append(rec)
                    if rec["id"]:
                        by_id[rec["id"]] = rec
        elif kind == "user":
            for b in map(as_dict, content):
                tid = as_str(b.get("tool_use_id"))
                if b.get("type") == "tool_result" and tid in by_id:
                    by_id[tid].update(output_bytes=utf8_len(block_text(b.get("content"))),
                                      is_error=bool(b.get("is_error")))
    for d in denials:
        if d["id"] in by_id:
            by_id[d["id"]]["denied"] = True
    ok = result.get("subtype") == "success" and not result.get("is_error")
    return dict(answer=str(result.get("result") or "") if result else "", tool_calls=calls, denials=denials,
                system_events=systems,
                result={k: result.get(k) for k in ("subtype", "is_error", "num_turns", "stop_reason",
                                                   "terminal_reason", "api_error_status")} if result else {},
                result_permission_denials=len(as_list(result.get("permission_denials"))),
                error=None if ok else (f"result {result.get('subtype')}" if result else "no result event"))


CODEX_NOT_TOOLS = {"agent_message", "reasoning", "error", "todo_list"}


def json_arguments(value):
    """A tool call's arguments: an object as given, or the object a JSON string holds; anything else as it is."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def codex_events(stdout: str) -> dict:
    """Codex exec --json: every tool call (shell commands, MCP calls, and any other tool item), turn failures, and
    error events. Codex asks for nothing (approval never), so it has no refusals; a command its sandbox stops fails,
    and shows as a tool call with is_error."""
    calls, errors, reported, usage = [], [], [], {}
    for ev in json_events(stdout):
        kind = ev.get("type")
        if kind == "item.completed":
            it = as_dict(ev.get("item"))
            t = as_str(it.get("type"))
            if t == "command_execution":
                calls.append(dict(kind="tool_call", tool="command_execution", source="builtin", id=as_str(it.get("id")),
                                  parent=None, input_bytes=utf8_len(it.get("command")),
                                  output_bytes=utf8_len(it.get("aggregated_output")),
                                  is_error=it.get("status") == "failed" or it.get("exit_code") not in (0, None),
                                  denied=False))
            elif t == "mcp_tool_call":
                rec = dict(kind="tool_call", tool=f"mcp__{as_str(it.get('server'))}__{as_str(it.get('tool'))}",
                           source="mcp", id=as_str(it.get("id")), parent=None,
                           input_bytes=utf8_len(it.get("arguments")),
                           output_bytes=utf8_len(block_text(as_dict(it.get("result")).get("content"))),
                           is_error=bool(it.get("error")) or it.get("status") == "failed", denied=False)
                if rec["tool"] == FETCH_TOOL:
                    rec["fetch_host"] = mcp_tools.url_host(as_dict(json_arguments(it.get("arguments"))).get("url"))
                calls.append(rec)
            elif t and t not in CODEX_NOT_TOOLS:
                calls.append(dict(kind="tool_call", tool=t, source="builtin", id=as_str(it.get("id")), parent=None,
                                  input_bytes=None, output_bytes=None, is_error=it.get("status") == "failed",
                                  denied=False))
        elif kind == "turn.failed":
            err = ev.get("error")
            msg = as_str(as_dict(err).get("message")) if isinstance(err, dict) else as_str(err)
            errors.append((msg or "turn failed")[:300])
        elif kind == "error":
            reported.append((as_str(ev.get("message")) or "error event")[:300])
        elif kind == "turn.completed":
            usage = as_dict(ev.get("usage"))
    return dict(tool_calls=calls, denials=[], usage=usage, reported_errors=reported,
                error="; ".join(errors) if errors else None)


# ---------------------------------------------------------------- fetch calls against the capture
def capture_conns(pcap: str, client_ip: str) -> list[dict]:
    """Every TCP connection the run opened, from its capture: stream, time of its first SYN, local and server address
    (ip:port) and TLS server name ('' when there is no ClientHello)."""
    conns = {}
    for row in vm_gate.tshark_rows(pcap, "tcp.flags.syn == 1 && tcp.flags.ack == 0 && !icmp",
                                   ["tcp.stream", "frame.time_epoch", "ip.src", "tcp.srcport", "ip.dst",
                                    "tcp.dstport"]):
        stream, t, src, sport, dst, dport = vm_gate.cols(row, 6)
        if vm_gate.first(src) != client_ip or stream in conns:
            continue
        conns[stream] = dict(stream=stream, t=vm_gate.epoch(t), local=f"{client_ip}:{vm_gate.first(sport)}",
                             remote=f"{vm_gate.first(dst)}:{vm_gate.first(dport)}", sni="")
    for row in vm_gate.tshark_rows(pcap, "tls.handshake.type == 1", ["tcp.stream",
                                                                    "tls.handshake.extensions_server_name"]):
        stream, sni = vm_gate.cols(row, 2)
        if stream in conns and not conns[stream]["sni"]:
            conns[stream]["sni"] = sni
    return sorted(conns.values(), key=lambda c: c["t"])


def fetch_records(tools: list, opens: list) -> list:
    """The fetch_url calls of a run: every fetch_url tool_call entry of tools.jsonl, in log order, then one entry for
    each fetch_open event that no tool_call entry accounts for (same local and server address): a fetch cut off by the
    end of its run, for example an agent timeout, whose connection is still logged."""
    calls = [t for t in tools if t.get("tool") == "fetch_url"]
    done = {((t.get("fetch") or {}).get("local"), (t.get("fetch") or {}).get("remote")) for t in calls
            if isinstance(t.get("fetch"), dict)}
    for o in opens:
        if (o.get("local"), o.get("remote")) not in done:
            calls.append(dict(tool="fetch_url", fetch=dict(
                host=o.get("host") or "", path=o.get("path"), refused=None, interrupted=True,
                error="cut off: the connection opened but the call has no tool_call entry", status=None,
                request_bytes=0, response_bytes=0, local=o.get("local"), remote=o.get("remote"), tls=None,
                t_start=o.get("t_start"), t_done=o.get("t_connect"))))
    return calls


def link_fetches(records: list, conns: list, fl: dict | None = None, hosts=FETCH_HOSTS,
                 slack: float = FETCH_SLACK) -> dict:
    """Ties every fetch_url call in the MCP tool log to its connection in the capture (mark Q6).

    records  the fetch_url calls of the run (fetch_records)
    conns    capture_conns of the run; fl the gate's flows (for the matched connection's captured bytes)
    A call that opened a connection (its fetch object has a local address) matches the capture connection with the same
    local and server address whose first SYN lies within the call's start and end times (slack seconds either side)
    and whose TLS server name is the requested host. Lists: unmatched (calls with a connection and no such flow, or a
    flow with another server name), outside (a call whose host, or whose flow's server name, is not on the allowlist,
    or a refused call that sent anything), unlogged (capture connections to an allowlisted host that no call accounts
    for). ok when all three are empty."""
    fl = fl or {}
    used, calls, unmatched, outside = set(), [], [], []
    for r in records:
        f = r.get("fetch") if isinstance(r.get("fetch"), dict) else {}
        host = f.get("host") or ""
        row = dict(host=host, path=f.get("path"), refused=f.get("refused") if f else "no fetch object in the log",
                   error=f.get("error"), status=f.get("status"), request_bytes=f.get("request_bytes", 0),
                   response_bytes=f.get("response_bytes", 0), local=f.get("local"), remote=f.get("remote"),
                   t_start=f.get("t_start"), t_done=f.get("t_done"), interrupted=bool(f.get("interrupted")),
                   stream=None, sni=None, cap_up=None, cap_down=None, matched=None)
        if f.get("local"):
            t0 = f.get("t_start") or 0
            t1 = f.get("t_done") or t0
            hit = next((c for c in conns if c["stream"] not in used and c["local"] == f["local"]
                        and c["remote"] == f.get("remote") and t0 - slack <= c["t"] <= t1 + slack), None)
            if hit:
                used.add(hit["stream"])
                m = fl.get(hit["stream"], {})
                row.update(stream=hit["stream"], sni=hit["sni"], cap_up=m.get("up_tcp"), cap_down=m.get("down_raw"))
            row["matched"] = bool(hit) and (hit["sni"] == host or (not hit["sni"] and not f.get("tls")))
            if not row["matched"]:
                unmatched.append(row)
            if host not in hosts or (hit and hit["sni"] and hit["sni"] not in hosts):
                outside.append(row)
        elif row["refused"] and (f.get("request_bytes") or f.get("response_bytes")):
            outside.append(row)
        calls.append(row)
    unlogged = [c for c in conns if c["sni"] in hosts and c["stream"] not in used]
    network = [c for c in calls if c["local"]]
    return dict(calls=calls, fetch_calls=len(calls), refused=sum(1 for c in calls if c["refused"]),
                network=len(network), matched=sum(1 for c in network if c["matched"]),
                errors=sum(1 for c in calls if c["error"]), interrupted=sum(1 for c in calls if c["interrupted"]),
                unmatched=unmatched, outside=outside, unlogged=unlogged,
                ok=not unmatched and not outside and not unlogged)


def mark_network(tool_calls: list, records: list) -> int:
    """Sets network on every tool call from the event output: True for a fetch_url call whose tool log entry (the next
    unused fetch_url entry for the same host) opened a connection, False for every other call. Every other tool has no
    network path (both shells are sandboxed without network, Claude Code's WebFetch and WebSearch are disallowed,
    Codex's web search is disabled). fetch_logged says whether a fetch_url call had a tool log entry. Returns how many
    calls went to the network."""
    pool = {}
    for r in records:
        f = r.get("fetch") if isinstance(r.get("fetch"), dict) else {}
        pool.setdefault(f.get("host") or "", []).append(f)
    for c in tool_calls:
        c["network"] = False
        if c.get("tool") != FETCH_TOOL:
            continue
        queue = pool.get(c.get("fetch_host") or "", [])
        f = queue.pop(0) if queue else None
        c["fetch_logged"] = f is not None
        c["network"] = bool(f and f.get("local"))
    return sum(1 for c in tool_calls if c["network"])


def testbed_faults(wire_fails) -> list:
    """The wire failure reasons that are faults of the testbed: every reason except upload resends (rule Q1r, the same
    rule as src/pilot_data.testbed_faults)."""
    return [w for w in (wire_fails or []) if not RESEND_RE.match(str(w))]


def background_hosts(hosts: dict) -> dict:
    """{host: [up, down]} for every host other than the model host and the fetch hosts."""
    return {h: [v.get("up", 0), v.get("down", 0)] for h, v in (hosts or {}).items()
            if h != MODEL_HOST and h not in FETCH_HOSTS}


# ---------------------------------------------------------------- agent settings
def claude_command(prompt: str, mcp_config: str, settings_file: str) -> list[str]:
    return ["claude", "-p", prompt, "--mcp-config", mcp_config, "--strict-mcp-config",
            "--allowedTools", ",".join(ALLOWED_TOOLS), "--disallowedTools", ",".join(CLAUDE_DISALLOWED_TOOLS),
            "--permission-mode", CLAUDE_PERMISSION_MODE, "--settings", settings_file, "--output-format",
            "stream-json", "--verbose", "--max-turns", str(CLAUDE_MAX_TURNS)]


def codex_command(ws: str, last_message: str, prompt: str) -> list[str]:
    return ["codex", "exec", "--skip-git-repo-check", "--ephemeral", "--json", "-C", ws, "-o", last_message, prompt]


def agent_settings(which: str, model: str = MODELS[0]) -> dict:
    """The tool, permission and model settings a run's agent had, for its manifest."""
    if which == "claude":
        return dict(permission_mode=CLAUDE_PERMISSION_MODE, allowed_tools=list(ALLOWED_TOOLS),
                    disallowed_tools=list(CLAUDE_DISALLOWED_TOOLS), settings=CLAUDE_SETTINGS,
                    model_env=vm_gate.claude_model_env(model))
    return dict(CODEX_SETTINGS, model=model)


def sandbox_command(chdir: str) -> list[str]:
    """A bubblewrap sandbox as Claude Code's sandbox needs it: its own user namespace and no network, entered in chdir
    (a folder next to the run workspaces)."""
    return ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-user", "--unshare-net",
            "--chdir", chdir, "true"]


def sandbox_check(which=shutil.which, run=subprocess.run, chdir: str = REPO) -> dict:
    """Claude Code's sandbox needs bubblewrap and socat. Checks both are installed and that bubblewrap can start a
    sandbox in its own user namespace, without network, inside chdir; the collection stops before its first run when
    this fails (Claude Code would refuse to start in every run). A home folder the sandbox cannot pass through fails
    here ("Can't chdir"; tested: the pilot's check, without a user namespace and without chdir, passed on such a home
    while Claude Code's sandboxed Bash failed), and so does any refusal to create a user namespace. vm_setup.sh sets
    both things Claude Code's sandbox needs: o+x on the home and no AppArmor restriction on user namespaces."""
    missing = [c for c in SANDBOX_COMMANDS if not which(c)]
    if missing:
        return dict(ok=False, detail=f"missing {', '.join(missing)}; sudo bash harness/vm_setup.sh installs them")
    try:
        r = run(sandbox_command(chdir), capture_output=True, text=True, timeout=60)
    except Exception as e:
        return dict(ok=False, detail=f"bubblewrap could not run: {type(e).__name__}: {e}")
    if r.returncode != 0:
        return dict(ok=False, detail=f"bubblewrap could not start a sandbox in {chdir}: "
                                     f"{(r.stderr or '').strip()[-300:]}; sudo bash harness/vm_setup.sh sets what it "
                                     "needs")
    return dict(ok=True, detail=f"bubblewrap and socat installed; bubblewrap starts a sandbox with its own user "
                                f"namespace and without network in {chdir}")


# ---------------------------------------------------------------- one benign run
def seed_workspace(ws: str, task: dict) -> None:
    for rel, content in task.get("inputs", {}).items():
        full = os.path.join(ws, rel)
        os.makedirs(os.path.dirname(full) or ws, exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)


def template_id(meta: dict) -> str:
    sha = (meta.get("codex_plugins") or {}).get("sha")
    model = f"-{meta['model']}" if meta.get("model") else ""
    return f"{meta['agent']}-{meta['version']}{model}@{meta.get('saved')}" + (f"+plugins:{sha[:12]}" if sha else "")


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


def run_once(gate: vm_gate.Gate, which: str, model: str, task: dict, repeat: int, index: int, template: dict,
             run_dir: str) -> dict:
    """One benign run of one task with one agent on one model, through the gateway, from a copy of the warm template
    home made for that agent and model, in its own namespace. Mirrors vm_gate.Gate.agent for the plumbing, with this
    task's prompt and workspace, the agent settings above, and the agent's event output. Writes labels.json from the
    key log and deletes the key log, then reads the event output, ties the fetch calls to the capture and deletes the
    run's home. An error after the agent has finished (while reading its event output) leaves the capture, the call log
    and labels.json in place, with the key log already deleted."""
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
                               **vm_gate.claude_model_env(model))
                    settings_file = os.path.join(run_dir, "claude_settings.json")
                    write_json(settings_file, CLAUDE_SETTINGS)
                    cmd = claude_command(task["prompt"], cfg, settings_file)
                else:
                    gw, log, _ = gate.start_gateway(net, run_dir, "gw", RESPONSES_BASE, 8082)
                    codex_home = os.path.join(home, ".codex")
                    os.makedirs(codex_home, exist_ok=True)
                    with open(os.path.join(codex_home, "config.toml"), "w") as f:
                        f.write(codex_config("http://127.0.0.1:8082", mcp, model))
                    env.update(CODEX_HOME=codex_home, DEEPSEEK_API_KEY=gate.key)
                    cmd = codex_command(ws, last_message, task["prompt"])
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
            conns = capture_conns(cap.path, net.ns_ip)
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
    tools = vm_gate.read_jsonl(tool_log, "tool_call")
    fetches = fetch_records(tools, vm_gate.read_jsonl(tool_log, "fetch_open"))
    fetch = link_fetches(fetches, conns, fl)
    network_calls = mark_network(ev["tool_calls"], fetches)
    with open(os.path.join(run_dir, "agent_tools.jsonl"), "w") as f:
        for c in ev["tool_calls"] + ev["denials"]:
            f.write(json.dumps(c) + "\n")
    model_calls = [c for c in calls if is_model_path(c.get("path"))]
    statuses = [c.get("status") for c in model_calls]
    endpoint_errors = [c["error"] for c in calls if c.get("error") and c.get("error_side") != "agent"]
    completed = (code == 0 and bool(statuses) and all(s == 200 for s in statuses) and not endpoint_errors
                 and ev["error"] is None)
    background = [(h, d) for h, d in vm_gate.background_downloads(hosts) if h not in FETCH_HOSTS]
    wire_ok, wire_fails = vm_gate.wire_verdict(wire)
    outputs_written = [o for o in task.get("outputs", []) if os.path.exists(os.path.join(ws, o))]
    mcp_events = [c for c in ev["tool_calls"] if c["source"] == "mcp"]
    shutil.rmtree(home, ignore_errors=True)
    key_found_in = homes.find_secret(run_dir, gate.key)
    return dict(
        run_id=os.path.basename(run_dir), task=task["id"], scenario=task["scenario"], agent=which,
        version=homes.agent_version(which), model=model, repeat=repeat, index=index,
        template_home=template["id"], template_saved=template.get("saved"),
        codex_plugins_sha=template.get("codex_plugins_sha"), start=start_iso, end=end_iso, seconds=round(took, 1),
        exit=code, answer=answer.strip()[-200:], model_calls=len(model_calls), model_statuses=statuses,
        model_request_bytes=sum(c.get("req_body_bytes", 0) for c in model_calls), endpoint_errors=endpoint_errors,
        agent_error=ev["error"], completed=completed, agent_settings=agent_settings(which, model),
        permission_denied=[(d["tool"], d["reason"]) for d in ev["denials"]], permission_denials=len(ev["denials"]),
        result_permission_denials=ev.get("result_permission_denials"), system_events=ev.get("system_events", {}),
        reported_errors=ev.get("reported_errors", []), mcp_tool_calls=[(t["tool"], t["args_bytes"]) for t in tools],
        agent_tool_calls=[(c["tool"], c["source"], c["input_bytes"], c["output_bytes"], c["denied"])
                          for c in ev["tool_calls"]],
        builtin_tool_calls=len(ev["tool_calls"]) - len(mcp_events), mcp_event_calls=len(mcp_events),
        mcp_log_matches=len(mcp_events) == len(tools), outputs_written=outputs_written,
        network_tool_calls=network_calls, fetch_calls=fetch["calls"], fetch_network=fetch["network"],
        fetch_refused=fetch["refused"], fetch_matched=fetch["matched"], fetch_unmatched=fetch["unmatched"],
        fetch_outside=fetch["outside"], fetch_unlogged=fetch["unlogged"], fetch_ok=fetch["ok"],
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
    """The run manifest: task, agent, version, model, repeat, home template id, agent settings, start and end times,
    exit status, model-call statuses, wire verdict, bytes per host, drops, labels summary, tool calls, permission
    refusals, and the fetch calls with their flows."""
    manifest = dict(
        run_id=record["run_id"], task=record["task"], scenario=record["scenario"], agent=record["agent"],
        version=record["version"], model=record["model"], repeat=record["repeat"],
        home_template=record["template_home"], home_template_saved=record["template_saved"],
        codex_plugins_sha=record["codex_plugins_sha"], agent_settings=record["agent_settings"],
        start=record["start"], end=record["end"], seconds=record["seconds"], exit=record["exit"],
        model_calls=record["model_calls"],
        model_statuses=record["model_statuses"], model_request_bytes=record["model_request_bytes"],
        endpoint_errors=record["endpoint_errors"], agent_error=record["agent_error"], completed=record["completed"],
        wire_verdict="clean" if record["wire_clean"] else "fail", wire_fails=record["wire_fails"],
        testbed_faults=testbed_faults(record["wire_fails"]),
        bytes_per_host=record["hosts"], drops=record["drops"], reran_after_drop=record.get("reran_after_drop", False),
        flagged_drop=record.get("flagged_drop", False), background_over_limit=record["background_over_limit"],
        codex_ab_chatgpt_up=record["codex_ab_chatgpt_up"], labels_written=record["labels_written"],
        label_agreement=record["label_agreement"], labels_ok=record["labels_ok"],
        mcp_tool_calls=record["mcp_tool_calls"], agent_tool_calls=record["agent_tool_calls"],
        builtin_tool_calls=record["builtin_tool_calls"], mcp_log_matches=record["mcp_log_matches"],
        network_tool_calls=record["network_tool_calls"], fetch_calls=record["fetch_calls"],
        fetch_network=record["fetch_network"], fetch_refused=record["fetch_refused"],
        fetch_matched=record["fetch_matched"], fetch_unmatched=record["fetch_unmatched"],
        fetch_outside=record["fetch_outside"], fetch_unlogged=record["fetch_unlogged"], fetch_ok=record["fetch_ok"],
        permission_denials=record["permission_denials"], permission_denied=record["permission_denied"],
        result_permission_denials=record["result_permission_denials"], system_events=record["system_events"],
        reported_errors=record["reported_errors"], outputs_written=record["outputs_written"],
        processes_left_in_namespace=record["processes_left_in_namespace"], key_found_in=record["key_found_in"],
        balance_before=record.get("balance_before"), answer=record["answer"])
    manifest["complete"] = manifest_complete(manifest)
    write_json(os.path.join(run_dir, "manifest.json"), manifest)
    return manifest


def fetch_summary(calls: list) -> list:
    """Per fetch call, the fields a pilot.json row keeps: host, refused or not, status, logged sizes, captured bytes,
    matched."""
    return [dict(host=c["host"], refused=bool(c["refused"]), status=c["status"], request_bytes=c["request_bytes"],
                 response_bytes=c["response_bytes"], cap_up=c["cap_up"], cap_down=c["cap_down"],
                 matched=c["matched"]) for c in calls]


def summary_row(rec: dict, manifest: dict, note: str) -> dict:
    return dict(run_id=rec["run_id"], task=rec["task"], scenario=rec["scenario"], agent=rec["agent"],
                model=rec["model"], repeat=rec["repeat"], exit=rec["exit"], seconds=rec["seconds"],
                completed=rec["completed"], model_calls=rec["model_calls"], model_statuses=rec["model_statuses"],
                model_request_bytes=rec["model_request_bytes"], wire_clean=rec["wire_clean"],
                wire_fails=rec["wire_fails"], labels_ok=rec["labels_ok"], label_agreement=rec["label_agreement"],
                builtin_tool_calls=rec["builtin_tool_calls"], mcp_tool_calls=len(rec["mcp_tool_calls"]),
                network_tool_calls=rec["network_tool_calls"], fetch=fetch_summary(rec["fetch_calls"]),
                fetch_ok=rec["fetch_ok"], permission_denials=rec["permission_denials"],
                mcp_log_matches=rec["mcp_log_matches"], background=background_hosts(rec["hosts"]),
                background_over_limit=rec["background_over_limit"], codex_ab_chatgpt_up=rec["codex_ab_chatgpt_up"],
                manifest_complete=manifest["complete"], reran_after_drop=rec.get("reran_after_drop", False),
                flagged_drop=rec.get("flagged_drop", False), drops=len(rec["drops"]), key_found_in=rec["key_found_in"],
                balance_before=rec.get("balance_before"), template=rec["template_home"], note=note,
                answer=rec["answer"][-60:])


def row_from_manifest(manifest: dict) -> dict:
    """The report row of a run whose manifest was written but whose row was not (a session stopped in between)."""
    m = manifest
    return dict(run_id=m["run_id"], task=m["task"], scenario=m["scenario"], agent=m["agent"], model=m["model"],
                repeat=m["repeat"], exit=m["exit"], seconds=m["seconds"], completed=m["completed"],
                model_calls=m["model_calls"], model_statuses=m["model_statuses"],
                model_request_bytes=m["model_request_bytes"], wire_clean=m["wire_verdict"] == "clean",
                wire_fails=m["wire_fails"], labels_ok=m["labels_ok"], label_agreement=m["label_agreement"],
                builtin_tool_calls=m["builtin_tool_calls"], mcp_tool_calls=len(m["mcp_tool_calls"]),
                network_tool_calls=m["network_tool_calls"], fetch=fetch_summary(m["fetch_calls"]),
                fetch_ok=m["fetch_ok"], permission_denials=m["permission_denials"],
                mcp_log_matches=m["mcp_log_matches"], background=background_hosts(m["bytes_per_host"]),
                background_over_limit=m["background_over_limit"], codex_ab_chatgpt_up=m["codex_ab_chatgpt_up"],
                manifest_complete=m["complete"], reran_after_drop=m["reran_after_drop"],
                flagged_drop=m["flagged_drop"], drops=len(m["drops"]), key_found_in=m["key_found_in"],
                balance_before=m["balance_before"], template=m["home_template"], note="row rebuilt from the manifest",
                answer=(m["answer"] or "")[-60:])


def error_row(run_id: str, task: dict, which: str, model: str, repeat: int, exc: BaseException) -> dict:
    """The row of a run that stopped on an error. Its run_id is changed to the name of the set-aside folder (or, when
    the run left no folder, to an id no folder has), as for a flagged first attempt, so that every row's run_id is
    unique and names its own folder; planned_run_id keeps the planned name, which the rerun on resume takes."""
    return dict(run_id=f"{run_id}__error", planned_run_id=run_id, task=task["id"], scenario=task["scenario"],
                agent=which, model=model, repeat=repeat, error=True,
                note=f"run stopped on {type(exc).__name__}: {exc}", traceback=traceback.format_exc()[-2000:])


def set_aside_error(run_dir: str) -> dict:
    """Sets aside the folder of a run that stopped on an error and says what it kept: every file except the home copy
    and the key log (set_aside removes both), so a run that stopped after the agent finished keeps its capture, call
    log and labels."""
    dest = set_aside(run_dir, "error")
    files = sorted(os.path.relpath(os.path.join(b, f), dest) for b, _, fs in os.walk(dest) for f in fs)
    return dict(run_dir=os.path.basename(dest), kept_files=[f for f in files if not f.startswith("ws" + os.sep)],
                workspace_files=sum(1 for f in files if f.startswith("ws" + os.sep)),
                capture_kept=os.path.exists(os.path.join(dest, "run.pcap")),
                call_log_kept=os.path.exists(os.path.join(dest, "gw_calls.jsonl")),
                labels_kept=os.path.exists(os.path.join(dest, "labels.json")),
                key_log_left=any(f.endswith(".keys") for f in files),
                home_left=os.path.isdir(os.path.join(dest, "home")))


def describe_run(rec: dict, manifest: dict) -> str:
    fetches = [(c["host"], "refused" if c["refused"] else c["status"], c["matched"]) for c in rec["fetch_calls"]]
    return (f"{rec['model']}: exit {rec['exit']} in {rec['seconds']} s, completed {rec['completed']}; model calls "
            f"{rec['model_calls']} (statuses {rec['model_statuses']}); wire "
            f"{'clean' if rec['wire_clean'] else 'FAIL ' + str(rec['wire_fails'])}; labels ok {rec['labels_ok']} "
            f"(agreement {rec['label_agreement']}); tool calls {rec['agent_tool_calls']}; permission refusals "
            f"{rec['permission_denied']}; MCP log matches {rec['mcp_log_matches']}; fetch calls (host, status, "
            f"flow matched) {fetches}; fetch check {'ok' if rec['fetch_ok'] else 'FAIL'}; bytes per host "
            f"{vm_gate.describe_hosts(rec['hosts'])}; manifest complete {manifest['complete']}"
            + (f"; background over {BACKGROUND_DOWNLOAD_LIMIT:,} B {rec['background_over_limit']}"
               if rec["background_over_limit"] else "")
            + (f"; API KEY FOUND IN {rec['key_found_in']}" if rec["key_found_in"] else ""))


# ---------------------------------------------------------------- the collection
def make_templates(gate: vm_gate.Gate, pairs: list) -> dict:
    """One warm template home per agent version and model in pairs [(agent, model)], each made and checked as the
    gate's H1 does, with a warm-up run on that model. The warm-up runs' key logs and home copies are deleted once the
    templates are saved. Returns {(agent, model): template}."""
    templates, lines, data = {}, [], {}
    for i, (which, model) in enumerate(pairs):
        t, line, data[f"{which} {model}"] = gate.warm_home(which, 31 + i, 41 + i, model=model)
        lines.append(line)
        if t:
            templates[(which, model)] = dict(home=t["home"], id=template_id(t), saved=t.get("saved"), model=model,
                                             codex_plugins_sha=(t.get("codex_plugins") or {}).get("sha"))
    gate.record("H1 warm homes", len(templates) == len(pairs), " | ".join(lines) or "no template needed", data)
    delete_keylogs(gate.out)
    if os.path.isdir(gate.out):
        for name in os.listdir(gate.out):
            shutil.rmtree(os.path.join(gate.out, name, "home"), ignore_errors=True)
    return templates


def plan(only_task: str | None = None, only_agent: str | None = None,
         only_model: str | None = None) -> list[tuple[dict, str, str, int]]:
    """The planned runs (task, agent, model, repeat) in run order: round r holds repeat r of every task, model and
    agent, in task order, so a collection stopped part way is balanced."""
    tasks = [t for t in pilot_tasks.TASKS if only_task is None or t["id"] == only_task]
    if only_task and not tasks:
        raise ValueError(f"no task {only_task}")
    if only_agent and only_agent not in AGENTS:
        raise ValueError(f"no agent {only_agent}")
    if only_model and only_model not in MODELS:
        raise ValueError(f"no model {only_model}")
    agents = [only_agent] if only_agent else AGENTS
    models = [only_model] if only_model else MODELS
    return [(t, a, m, r) for r in range(1, REPEATS + 1) for t in tasks for m in models for a in agents]


def plan_cells(only_task=None, only_agent=None, only_model=None) -> list[tuple[str, str, str, int]]:
    return [(t["id"], a, m, r) for t, a, m, r in plan(only_task, only_agent, only_model)]


def run_name(task: dict, which: str, model: str, repeat: int) -> str:
    return f"{task['id']}__{which}__{model}__r{repeat}"


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


def cell(row: dict) -> tuple:
    return (row.get("task"), row.get("agent"), row.get("model"), row.get("repeat"))


def complete_set_facts(rows: list, planned: list) -> dict:
    """The kept runs against the planned cells (task, agent, model, repeat): cells with no kept run, cells kept more
    than once, and kept runs outside the plan."""
    kept = [cell(r) for r in kept_rows(rows)]
    counts = {}
    for c in kept:
        counts[c] = counts.get(c, 0) + 1
    want = set(planned)
    return dict(missing=sorted(c for c in want if c not in counts), duplicated=sorted(c for c, n in counts.items()
                                                                                     if n > 1 and c in want),
                outside_plan=sorted(c for c in counts if c not in want))


def quality_marks(rows: list, planned: list, stopped_early: str | None = None, templates_ok: bool = True) -> dict:
    """Q1r, Q2, Q4, Q5, Q6 and the complete set over agent x model x task x repeat; planned is plan_cells()."""
    kept = kept_rows(rows)
    n = len(kept)
    facts = complete_set_facts(rows, planned)
    marks = dict(expected_runs=len(planned), runs=n, error_runs=sum(1 for r in rows if r.get("error")),
                 flagged_first_attempts=sum(1 for r in rows if r.get("flagged_drop")), stopped_early=stopped_early,
                 templates_ok=templates_ok, missing_runs=len(facts["missing"]),
                 duplicated_runs=len(facts["duplicated"]), runs_outside_plan=len(facts["outside_plan"]),
                 missing_examples=[list(c) for c in facts["missing"][:10]])
    complete_set = not (facts["missing"] or facts["duplicated"] or facts["outside_plan"]) and not stopped_early \
        and templates_ok
    if not n:
        marks.update(Q1r_wire=None, Q2_labels=None, Q4_manifests=None, Q5_completed=None, Q6_fetch=None,
                     complete_set=complete_set, all_pass=False)
        return marks
    no_fault = sum(1 for r in kept if not testbed_faults(r.get("wire_fails")))
    clean = sum(1 for r in kept if r.get("wire_clean"))
    done = sum(1 for r in kept if r.get("completed"))
    q1r = no_fault / n >= WIRE_CLEAN_MIN
    q2 = all(r.get("labels_ok") is True for r in kept)
    q4 = all(r.get("manifest_complete") for r in kept)
    q5 = done / n >= COMPLETED_MIN
    q6 = all(r.get("fetch_ok") is True for r in kept)
    marks.update(no_testbed_fault=no_fault, no_testbed_fault_fraction=round(no_fault / n, 4), wire_clean=clean,
                 wire_clean_fraction=round(clean / n, 4),
                 resend_runs=sum(1 for r in kept if len(testbed_faults(r.get("wire_fails"))) <
                                 len(r.get("wire_fails") or [])),
                 completed=done, completed_fraction=round(done / n, 4),
                 fetch_check_failed=[r["run_id"] for r in kept if r.get("fetch_ok") is not True][:20],
                 Q1r_wire=q1r, Q2_labels=q2, Q4_manifests=q4, Q5_completed=q5, Q6_fetch=q6, complete_set=complete_set)
    marks["all_pass"] = bool(q1r and q2 and q4 and q5 and q6 and complete_set)
    return marks


def background_report(rows: list) -> list:
    """Q3 of the pilot as a reported number: per agent, model and background host, the largest download and the
    largest upload over all runs (flagged first attempts included), and the runs whose download from that host is over
    BACKGROUND_DOWNLOAD_LIMIT. The DNS rows (dns <resolver>) hold every lookup of the run, so also the gateway's
    lookups of the model host and fetch_url's lookups of the fetch hosts, as in the pilot; the analysis ties lookups to
    connections by name and time (notebook 03 does so for the model host)."""
    out = {}
    for r in rows:
        if r.get("error"):
            continue
        for host, (up, down) in (r.get("background") or {}).items():
            k = (r["agent"], r.get("model"), host)
            e = out.setdefault(k, dict(agent=k[0], model=k[1], host=host, runs=0, max_down=0, max_down_run=None,
                                       max_up=0, max_up_run=None, over_limit=[]))
            e["runs"] += 1
            if down > e["max_down"]:
                e["max_down"], e["max_down_run"] = down, r["run_id"]
            if up > e["max_up"]:
                e["max_up"], e["max_up_run"] = up, r["run_id"]
            if down > BACKGROUND_DOWNLOAD_LIMIT:
                e["over_limit"].append(r["run_id"])
    return sorted(out.values(), key=lambda e: (e["agent"], e["model"] or "", -e["max_down"]))


def fetch_report(rows: list) -> dict:
    """fetch_url use over the kept runs: per agent and model, the fetch calls, how many went to the network, were
    refused or matched their flow; per host, the largest logged response and captured download; per network task, the
    share of kept runs with at least one fetch that went to the network."""
    kept = kept_rows(rows)
    per = {}
    hosts = {}
    for r in kept:
        e = per.setdefault((r["agent"], r.get("model")), dict(agent=r["agent"], model=r.get("model"), runs=0,
                                                              calls=0, network=0, refused=0, matched=0))
        e["runs"] += 1
        for f in r.get("fetch") or []:
            e["calls"] += 1
            e["refused"] += bool(f["refused"])
            e["network"] += f["matched"] is not None
            e["matched"] += f["matched"] is True
            if f["matched"] is not None:
                h = hosts.setdefault(f["host"], dict(host=f["host"], calls=0, max_response_bytes=0, max_cap_down=0))
                h["calls"] += 1
                h["max_response_bytes"] = max(h["max_response_bytes"], f["response_bytes"] or 0)
                h["max_cap_down"] = max(h["max_cap_down"], f["cap_down"] or 0)
    tasks = {}
    for r in kept:
        if r["task"] in pilot_tasks.NETWORK_TASKS:
            t = tasks.setdefault(r["task"], dict(task=r["task"], runs=0, with_fetch=0))
            t["runs"] += 1
            t["with_fetch"] += any(f["matched"] is not None for f in r.get("fetch") or [])
    return dict(per_agent_model=list(per.values()), per_host=list(hosts.values()),
                per_network_task=list(tasks.values()))


def codex_background_report(rows: list) -> dict:
    """Codex's upload to ab.chatgpt.com against run time and model calls, per run and per model."""
    out = [dict(run_id=r["run_id"], task=r["task"], model=r.get("model"), seconds=r["seconds"],
                model_calls=r["model_calls"], model_request_bytes=r["model_request_bytes"],
                ab_chatgpt_up=r["codex_ab_chatgpt_up"],
                up_per_second=round(r["codex_ab_chatgpt_up"] / r["seconds"], 1) if r["seconds"] else None)
           for r in kept_rows(rows) if r["agent"] == "codex"]
    per_model = {}
    for r in out:
        m = per_model.setdefault(r["model"], dict(seconds=0.0, up=0))
        m["seconds"] += r["seconds"] or 0
        m["up"] += r["ab_chatgpt_up"] or 0
    total_s = sum(r["seconds"] or 0 for r in out)
    total_up = sum(r["ab_chatgpt_up"] or 0 for r in out)
    return dict(runs=out, total_seconds=round(total_s, 1), total_up=total_up,
                up_per_second=round(total_up / total_s, 1) if total_s else None,
                per_model={k: dict(seconds=round(v["seconds"], 1), up=v["up"],
                                   up_per_second=round(v["up"] / v["seconds"], 1) if v["seconds"] else None)
                           for k, v in per_model.items()})


def finish(report: dict, out: str, final: bool) -> None:
    report["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    report["final"] = final
    planned = plan_cells(report.get("only_task"), report.get("only_agent"), report.get("only_model"))
    report["quality_marks"] = quality_marks(report["runs"], planned, report.get("stopped_early"),
                                            report.get("templates_ok", False))
    report["background_report"] = background_report(report["runs"])
    report["fetch_report"] = fetch_report(report["runs"])
    report["codex_background"] = codex_background_report(report["runs"])
    write_json(os.path.join(out, "pilot.json"), report)


def run_pilot(key: str, out: str, balance_floor: float, only_task: str | None, only_agent: str | None,
              only_model: str | None = None, resume: bool = False) -> dict:
    pilot_tasks.validate()
    runs_dir = os.path.join(out, "runs")
    os.makedirs(runs_dir, exist_ok=True)
    session = time.strftime("%Y%m%d_%H%M%S")
    old = {}
    if resume and os.path.exists(os.path.join(out, "pilot.json")):
        with open(os.path.join(out, "pilot.json")) as f:
            old = json.load(f)
        # a resumed collection keeps its plan
        only_task, only_agent, only_model = old.get("only_task"), old.get("only_agent"), old.get("only_model")
    planned = plan(only_task, only_agent, only_model)
    report = dict(stamp=os.path.basename(out), started=old.get("started") or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                  sessions=old.get("sessions", []) + [session], balance_floor=balance_floor,
                  only_task=only_task, only_agent=only_agent, only_model=only_model, repeats=REPEATS,
                  models=[m for m in MODELS if only_model in (None, m)], expected_runs=len(planned),
                  balance_before=old.get("balance_before"), runs=old.get("runs", []), stopped_early=None,
                  templates_ok=False, gate=old.get("gate", []), templates=old.get("templates", []))
    gate = vm_gate.Gate(os.path.join(out, "warmups", session), key)
    left = [(t, a, m, r) for t, a, m, r in planned if not run_done(runs_dir, run_name(t, a, m, r))]
    pairs = sorted({(a, m) for _, a, m, _ in left}, key=lambda p: (AGENTS.index(p[0]), MODELS.index(p[1])))
    report["session_plan"] = dict(session=session, runs_left=len(left), templates_needed=[list(p) for p in pairs])
    finish(report, out, False)          # the plan is on disk before the warm-ups, so a stop during them keeps it

    if pairs:
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
        if any(a == "claude" for a, _ in pairs):
            report["sandbox_check"] = sandbox_check(chdir=runs_dir)
            print(f"Claude Code sandbox: {report['sandbox_check']['detail']}", flush=True)
            if not report["sandbox_check"]["ok"]:
                report["stopped_early"] = f"Claude Code sandbox cannot start: {report['sandbox_check']['detail']}"
                report["gate"] += gate.results
                finish(report, out, True)
                return report
        netns.cleanup_all()
    templates = make_templates(gate, pairs) if pairs else {}
    report["gate"] += gate.results
    report["templates"] += [dict(session=session, **{f"{a} {m}": t for (a, m), t in templates.items()})]
    report["templates_ok"] = all(p in templates for p in pairs)
    finish(report, out, False)

    index = FIRST_INDEX - 1

    def next_index():
        nonlocal index
        index = index + 1 if index < LAST_INDEX else FIRST_INDEX
        return index

    for task, which, model, repeat in planned:
        run_id = run_name(task, which, model, repeat)
        run_dir = os.path.join(runs_dir, run_id)
        if run_done(runs_dir, run_id):
            if not any(r["run_id"] == run_id and not r.get("error") for r in report["runs"]):
                with open(os.path.join(run_dir, "manifest.json")) as f:
                    report["runs"].append(row_from_manifest(json.load(f)))
            continue
        template = templates.get((which, model))
        if template is None:
            print(f"SKIP {run_id}: no warm template home for {which} on {model}", flush=True)
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
            rec = run_once(gate, which, model, task, repeat, next_index(), template, run_dir)
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
                rec = run_once(gate, which, model, task, repeat, next_index(), template, run_dir)
                rec.update(balance_before=bal.get("total_balance"), reran_after_drop=True)
                if rec["drops"]:
                    note += f"; the rerun had an endpoint drop too ({vm_gate.describe_drops(rec['drops'])})"
            manifest = write_manifest(run_dir, rec)
            print(describe_run(rec, manifest), flush=True)
            report["runs"].append(summary_row(rec, manifest, note))
        except Exception as e:
            row = error_row(run_id, task, which, model, repeat, e)
            print(f"ERROR {run_id}: {row['note']}", flush=True)
            delete_keylogs(run_dir)
            if os.path.exists(run_dir):
                row.update(set_aside_error(run_dir))
                row["run_id"] = row["run_dir"]
            else:
                taken = {r.get("run_id") for r in report["runs"]}
                k = 1
                while f"{run_id}__error_nofolder{k}" in taken:
                    k += 1
                row["run_id"] = f"{run_id}__error_nofolder{k}"
            report["runs"].append(row)
            try:
                netns.cleanup_all()
            except Exception:
                pass
        finish(report, out, False)

    report["balance_after"] = read_balance(key) if pairs else report.get("balance_after", old.get("balance_after"))
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
    ap.add_argument("--only-model", default=None, choices=MODELS, help="run a single model")
    ap.add_argument("--resume", default=None, metavar="STAMP",
                    help="continue the collection in data/harness/pilot/STAMP, skipping runs that have a manifest "
                         "(it keeps its own plan; --only-* are then ignored)")
    a = ap.parse_args(argv)
    if a.only_task and a.only_task not in [t["id"] for t in pilot_tasks.TASKS]:
        ap.error(f"no task {a.only_task}; the tasks are: {', '.join(t['id'] for t in pilot_tasks.TASKS)}")

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
    print(f"benign collection {os.path.basename(out)}{' (resumed)' if a.resume else ''}, output {out}; "
          f"stale key logs deleted: {stale}\n", flush=True)
    report = {}
    try:
        report = run_pilot(key, out, a.balance_floor, a.only_task, a.only_agent, a.only_model,
                           resume=bool(a.resume))
    finally:
        stopped = stop_processes_under(out)
        try:
            netns.cleanup_all()
        except Exception:
            pass
        print(f"\nkey logs deleted: {delete_keylogs(out)}; processes stopped: {stopped}", flush=True)
    marks = report.get("quality_marks", {})
    print("\nCOLLECTION MARKS")
    for k in ("Q1r_wire", "Q2_labels", "Q4_manifests", "Q5_completed", "Q6_fetch", "complete_set"):
        print(f"  {'PASS' if marks.get(k) else 'FAIL' if marks.get(k) is not None else 'n/a'}  {k}")
    print(f"\n{'PASS' if marks.get('all_pass') else 'FAIL'}  collection ({marks.get('runs', 0)} kept runs of "
          f"{marks.get('expected_runs')} planned, {marks.get('missing_runs')} missing; no testbed fault on the wire "
          f"{marks.get('no_testbed_fault_fraction')} (clean as the gate rules it {marks.get('wire_clean_fraction')}, "
          f"runs with resent upload {marks.get('resend_runs')}); completed {marks.get('completed_fraction')}; runs "
          f"stopped on an error {marks.get('error_runs')}; fetch check failed in {marks.get('fetch_check_failed')})")
    print("\nbackground per agent, model and host (reported): largest download, largest upload, runs over "
          f"{BACKGROUND_DOWNLOAD_LIMIT:,} B")
    for e in report.get("background_report", []):
        print(f"  {e['agent']:6s} {e['model'] or '':16s} {e['host'][:40]:40s} down {e['max_down']:>11,} B  "
              f"up {e['max_up']:>11,} B  over {len(e['over_limit'])}")
    print("\nfetch_url per agent and model (kept runs): calls, to the network, refused, flow matched")
    for e in (report.get("fetch_report") or {}).get("per_agent_model", []):
        print(f"  {e['agent']:6s} {e['model'] or '':16s} calls {e['calls']}, network {e['network']}, refused "
              f"{e['refused']}, matched {e['matched']} over {e['runs']} runs")
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
