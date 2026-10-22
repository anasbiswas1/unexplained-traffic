"""VM gate for the benign collection testbed. Run as root on the VM, from the repository root, with the DeepSeek key
in DEEPSEEK_API_KEY (it is never written to disk):

    sudo -E python3 harness/vm_gate.py

Every check below runs on the VM:
  V0 environment     root, Python, the commands the testbed needs, agent versions, the key present
  V1 offline checks  harness/offline_check.py --agents (gateway, MCP tool log, both agents against a local fake
                     endpoint)
  V2 isolation       two namespaces at once: each capture holds only its own run's traffic; a run cannot reach another
                     run, the VM itself or the cloud metadata address
  V3 Anthropic API   inside a namespace, through the gateway: a streamed request with a tool definition is answered
                     (whether the model called the tool is reported); a long streamed answer reaches the client piece
                     by piece; three calls share one TLS connection on the wire
  V4 key log         the run's TLS key log decrypts its capture with tshark; decrypted request lengths equal the
                     gateway's logged lengths; without the key log nothing decrypts
  V5 Responses API   a streamed request with a function tool on DeepSeek's Responses API, the wire format Codex uses,
                     is answered as an event stream (whether the model called the tool is reported)
  V6 Claude Code     a one-tool task through the gateway, with the MCP tool log and a capture
  V7 Codex           the same task with Codex
  V8 fidelity        each agent runs the same task straight to DeepSeek; TLS connections to the model host, offered
                     ALPN protocols and upload bytes are compared with the gateway run
Gates: gate 1 (Codex on DeepSeek) = V5 and V7; gate 2 (gateway keeps the traffic shape) = V1, V3 and V8;
testbed = V0, V2, V4 and V6.

Upload bytes are measured three ways per TCP connection: raw TCP payload of every captured segment (resent segments
included), TCP payload counted once from the sequence numbers (resent bytes removed), and TLS record bytes (record
header plus record length, each record once). V4 and V8 report the last two and the bytes resent.

Upstream drops: when a call through the gateway ends in an error on the endpoint's side (error_side "upstream" in the
gateway log) and the first FIN or RST on its connection in the capture comes from the endpoint, the endpoint dropped
the connection; this is recorded as an upstream drop, not a gateway fault. A check through the gateway (V3, V5, V6,
V7) that meets an upstream drop is run once more and fails only if the rerun meets one too. A call the agent itself
closed (error_side "agent") is reported but is not a gateway fault either.

Key logs are deleted when the gate ends. Captures and logs stay under data/harness/vm_gate/<time>/ (git-ignored).
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

MODEL_HOST = "api.deepseek.com"
ANTHROPIC_BASE = "https://api.deepseek.com/anthropic"
RESPONSES_BASE = "https://api.deepseek.com"
MODEL = "deepseek-flash"
WORD_COUNT_SCHEMA = {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}
AGENT_TIMEOUT = 300
NEEDED = ["ip", "iptables", "tcpdump", "tshark", "node", "npm", "claude", "codex", "openssl"]


# ---------------------------------------------------------------- clients run inside a namespace (internal mode)
def client_anthropic(port: int) -> dict:
    """Three calls on one kept-alive connection to the gateway: tool request, long streamed answer, short call."""
    key = os.environ["DEEPSEEK_API_KEY"]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=300)
    headers = {"content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"}
    out = {}

    def call(name, body, stream):
        t0 = time.time()
        conn.request("POST", "/v1/messages", json.dumps(body), headers)
        resp = conn.getresponse()
        reads, text = [], b""
        while True:
            piece = resp.read1(65536) if stream else resp.read()
            if not piece:
                break
            reads.append((time.time(), len(piece)))
            text += piece
            if not stream:
                break
        out[name] = dict(status=resp.status, t0=t0, reads=reads, bytes=len(text),
                         content_type=resp.getheader("content-type"),
                         head=text[:300].decode("utf-8", "replace") if resp.status != 200 else None)
        return text.decode("utf-8", "replace")

    text = call("tool", dict(model=MODEL, max_tokens=256, stream=True,
                             tools=[dict(name="word_count", description="Count the words in a text.",
                                         input_schema=WORD_COUNT_SCHEMA)],
                             messages=[dict(role="user", content="Use the word_count tool to count the words in: "
                                                                 "alpha beta gamma delta")]), True)
    out["tool"]["tool_use"] = bool(re.search(r'"type"\s*:\s*"tool_use"', text)
                                   and re.search(r'"name"\s*:\s*"word_count"', text))
    call("stream", dict(model=MODEL, max_tokens=3000, stream=True, messages=[dict(
        role="user", content="Write the whole numbers from 1 to 400 in order, separated by single spaces, "
                             "and nothing else.")]), True)
    call("short", dict(model=MODEL, max_tokens=16, messages=[dict(role="user", content="Reply with: ok")]), False)
    conn.close()
    return out


def client_responses(port: int) -> dict:
    key = os.environ["DEEPSEEK_API_KEY"]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=300)
    body = dict(model=MODEL, stream=True, input="Use the word_count tool to count the words in: alpha beta gamma delta",
                tools=[dict(type="function", name="word_count", description="Count the words in a text.",
                            parameters=WORD_COUNT_SCHEMA)])
    conn.request("POST", "/responses", json.dumps(body),
                 {"content-type": "application/json", "authorization": f"Bearer {key}"})
    resp = conn.getresponse()
    text = b""
    while True:
        piece = resp.read1(65536)
        if not piece:
            break
        text += piece
    conn.close()
    t = text.decode("utf-8", "replace")
    return dict(status=resp.status, content_type=resp.getheader("content-type"), bytes=len(text),
                function_call=bool(re.search(r'"type"\s*:\s*"function_call"', t)
                                   and re.search(r'"name"\s*:\s*"word_count"', t)),
                events=sorted(set(re.findall(r"event:\s*(\S+)", t))),
                head=t[:300] if resp.status != 200 else None)


def client_fetch(url: str) -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=30) as r:
            return dict(ok=True, status=r.status)
    except urllib.error.HTTPError as e:
        return dict(ok=True, status=e.code)
    except Exception as e:
        return dict(ok=False, error=f"{type(e).__name__}: {e}")


def client_reach(ip: str, port: int) -> dict:
    s = socket.socket()
    s.settimeout(4)
    try:
        s.connect((ip, port))
        return dict(result="connected")
    except ConnectionRefusedError:
        return dict(result="refused")
    except (socket.timeout, TimeoutError):
        return dict(result="timeout")
    except OSError as e:
        return dict(result=f"error {e.errno}")
    finally:
        s.close()


def client_alpn(host: str) -> dict:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, 443), timeout=15) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        return dict(selected=s.selected_alpn_protocol(), tls=s.version())


# ---------------------------------------------------------------- helpers on the VM side
def sh(args, timeout=60, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kw)


def in_ns(net, client: str, *args, timeout=400) -> dict:
    r = sh(net.cmd([sys.executable, os.path.abspath(__file__), "--client", client, *map(str, args)]), timeout=timeout)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return dict(error=f"client {client} failed: {r.stderr.strip()[-400:]}")


def tshark_rows(pcap, display_filter, fields, keylog=None):
    args = ["tshark", "-r", pcap, "-n"]
    if keylog:
        args += ["-o", f"tls.keylog_file:{keylog}"]
    args += ["-Y", display_filter, "-T", "fields", "-E", "separator=\t"]
    for f in fields:
        args += ["-e", f]
    r = sh(args, timeout=300)
    return [ln.split("\t") for ln in r.stdout.splitlines() if ln.strip()]


NOT_RESENT = ("!tcp.analysis.retransmission && !tcp.analysis.fast_retransmission "
              "&& !tcp.analysis.spurious_retransmission")


def cols(row, n):
    return (list(row) + [""] * n)[:n]


def truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true")


def epoch(value: str) -> float:
    """frame.time_epoch as seconds; tshark prints a number, some versions an ISO 8601 time."""
    try:
        return float(value)
    except ValueError:
        import datetime
        v = value.strip().replace("Z", "+00:00")
        if "." in v:
            head, frac = v.split(".", 1)
            n = len(frac) - len(frac.lstrip("0123456789"))
            v = f"{head}.{frac[:min(n, 6)]}{frac[n:]}"
        t = datetime.datetime.fromisoformat(v)
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
        return t.timestamp()


def upload_measures(segments, records, client_ip) -> dict:
    """Bytes per TCP stream, from tshark rows.

    segments  rows (tcp.stream, ip.src, tcp.seq, tcp.len), one per captured segment with payload
    records   rows (tcp.stream, ip.src, tls.record.length values joined by commas), frames that are not resends
    Per stream:
      up_raw    client payload of every captured segment, resent segments included
      up_tcp    client payload counted once: highest sequence end minus lowest sequence start
      resent    up_raw minus up_tcp
      up_tls    client TLS record bytes: 5-byte record header plus record length, each record once
      down_raw  endpoint payload of every captured segment
    The capture is taken on the client's side of each connection, so every byte the client sent appears there before
    any resend of it; up_tls and up_tcp therefore count the same bytes and should be equal.
    """
    empty = dict(up_raw=0, up_tcp=0, resent=0, up_tls=0, down_raw=0)
    out, span = {}, {}
    for row in segments:
        stream, src, seq, length = cols(row, 4)
        if not seq.isdigit() or not length.isdigit():
            continue
        f = out.setdefault(stream, dict(empty))
        n, start = int(length), int(seq)
        if src == client_ip:
            f["up_raw"] += n
            lo, hi = span.get(stream, (start, start + n))
            span[stream] = (min(lo, start), max(hi, start + n))
        else:
            f["down_raw"] += n
    for stream, (lo, hi) in span.items():
        out[stream]["up_tcp"] = hi - lo
        out[stream]["resent"] = out[stream]["up_raw"] - (hi - lo)
    for row in records:
        stream, src, lengths = cols(row, 3)
        if src == client_ip and lengths:
            f = out.setdefault(stream, dict(empty))
            f["up_tls"] += sum(5 + int(x) for x in lengths.split(",") if x.strip().isdigit())
    return out


def flows(pcap: str, client_ip: str) -> dict:
    """Per TCP stream: server name, offered ALPN list, selected ALPN when visible, and the byte counts of
    upload_measures."""
    out = {}
    for row in tshark_rows(pcap, "tls.handshake.type == 1", ["tcp.stream", "tls.handshake.extensions_server_name",
                                                              "tls.handshake.extensions_alpn_str"]):
        stream, sni, alpn = cols(row, 3)
        out.setdefault(stream, {}).update(sni=sni, offered=alpn)
    for row in tshark_rows(pcap, "tls.handshake.type == 2", ["tcp.stream", "tls.handshake.extensions_alpn_str"]):
        stream, alpn = cols(row, 2)
        if alpn:
            out.setdefault(stream, {})["selected"] = alpn
    segments = tshark_rows(pcap, "tcp.len > 0", ["tcp.stream", "ip.src", "tcp.seq", "tcp.len"])
    records = tshark_rows(pcap, f"tls.record && {NOT_RESENT}", ["tcp.stream", "ip.src", "tls.record.length"])
    for stream, m in upload_measures(segments, records, client_ip).items():
        out.setdefault(stream, {}).update(m)
    return out


def close_rows_to_events(rows, client_ip) -> dict:
    """FIN and RST packets per client port, in capture order: {port: [(time, sent by the endpoint, 'FIN'/'RST')]}.
    rows: (frame.time_epoch, ip.src, tcp.srcport, tcp.dstport, tcp.flags.fin, tcp.flags.reset)."""
    events = {}
    for row in rows:
        t, src, sport, dport, fin, rst = cols(row, 6)
        from_endpoint = src != client_ip
        port = dport if from_endpoint else sport
        events.setdefault(port, []).append((epoch(t), from_endpoint, "RST" if truthy(rst) else "FIN"))
    return events


def close_events(pcap: str, client_ip: str) -> dict:
    rows = tshark_rows(pcap, "tcp.flags.fin == 1 || tcp.flags.reset == 1",
                       ["frame.time_epoch", "ip.src", "tcp.srcport", "tcp.dstport", "tcp.flags.fin",
                        "tcp.flags.reset"])
    return close_rows_to_events(rows, client_ip)


def upstream_drops(calls: list[dict], events: dict) -> list[dict]:
    """Calls through the gateway that ended in an error on the endpoint's side, on a connection the endpoint closed
    first."""
    drops = []
    for c in calls:
        if not c.get("error") or not c.get("up_local") or c.get("error_side", "upstream") != "upstream":
            continue
        port = c["up_local"].rsplit(":", 1)[1]
        after = [e for e in events.get(port, []) if e[0] >= c["t"] - 0.001]
        if not after or not after[0][1]:
            continue
        t, _, kind = after[0]
        if c.get("status") is None:
            phase = "before the response head"
        elif not c.get("resp_body_bytes"):
            phase = f"after the {c['status']} response head, before any body"
        else:
            phase = f"inside the body, after {c['resp_body_bytes']} bytes"
        drops.append(dict(conn=c["conn"], seq=c["seq"], path=c["path"].split("?")[0], status=c.get("status"),
                          phase=phase, closed_by=f"endpoint {kind}",
                          seconds_after_head=round(t - c["t_resp_head"], 3) if c.get("t_resp_head") else None,
                          gateway_error=c["error"]))
    return drops


def describe_drops(drops: list[dict]) -> str:
    return "; ".join(f"upstream drop on {d['path']} {d['phase']} ({d['closed_by']}"
                     + (f", {d['seconds_after_head']} s after the head" if d["seconds_after_head"] is not None
                        else "") + ")" for d in drops)


def model_flows(fl: dict) -> list[dict]:
    return [f for f in fl.values() if f.get("sni") == MODEL_HOST]


def answered(text: str) -> bool:
    """The one-tool task asks for the word count only; the answer must contain the number 4 and no other number."""
    return re.findall(r"\d+", text or "") == ["4"]


def read_jsonl(path, event=None):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        rows = [json.loads(x) for x in f if x.strip()]
    return [r for r in rows if event is None or r.get("event") == event]


class Gate:
    def __init__(self, out_dir, key):
        self.out = out_dir
        self.key = key
        self.results = []
        self.keylogs = []

    def record(self, check, passed, detail, data=None):
        self.results.append(dict(check=check, where="VM", passed=passed, detail=detail, data=data))
        mark = "PASS" if passed else ("SKIP" if passed is None else "FAIL")
        print(f"{mark}  {check}: {detail}", flush=True)

    def start_gateway(self, net, run_dir, name, upstream, port):
        keylog = os.path.join(run_dir, f"{name}.keys")
        log = os.path.join(run_dir, f"{name}_calls.jsonl")
        self.keylogs.append(keylog)
        proc = subprocess.Popen(net.cmd([sys.executable, os.path.join(HERE, "call_gateway.py"), "--listen",
                                         f"127.0.0.1:{port}", "--upstream", upstream, "--log", log,
                                         "--keylog", keylog]), stderr=subprocess.PIPE, text=True)
        line = proc.stderr.readline()
        if "listening" not in line:
            raise RuntimeError(f"gateway did not start: {line}")
        return proc, log, keylog

    @staticmethod
    def stop(proc):
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # V0
    def environment(self):
        versions, missing = {}, []
        for cmd in NEEDED:
            if not shutil.which(cmd):
                missing.append(cmd)
                continue
            flag = {"tshark": ["--version"], "tcpdump": ["--version"], "ip": ["-V"],
                    "openssl": ["version"]}.get(cmd, ["--version"])
            r = sh([cmd] + flag)
            versions[cmd] = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr).strip() else "?"
        ok = os.geteuid() == 0 and sys.version_info >= (3, 9) and not missing and bool(self.key)
        self.record("V0 environment", ok,
                    f"root {os.geteuid() == 0}; Python {platform.python_version()}; {platform.platform()}; "
                    f"missing commands {missing or 'none'}; DeepSeek key present {bool(self.key)}",
                    dict(versions=versions))
        return ok

    # V1
    def offline(self):
        d = os.path.join(self.out, "offline")
        r = sh([sys.executable, os.path.join(HERE, "offline_check.py"), "--agents", "--out", d], timeout=900)
        rep = json.load(open(os.path.join(d, "offline_check.json"))) if os.path.exists(
            os.path.join(d, "offline_check.json")) else []
        failed = [x["check"] for x in rep if x["passed"] is False]
        skipped = [x["check"] for x in rep if x["passed"] is None]
        ok = r.returncode == 0 and rep and not failed and not skipped
        self.record("V1 offline checks", ok, f"{len(rep)} checks; failed {failed or 'none'}; skipped "
                                             f"{skipped or 'none'}", dict(results=rep))

    # V2
    def isolation(self):
        import netns
        d = os.path.join(self.out, "isolation")
        with netns.RunNet(11) as a, netns.RunNet(12) as b:
            ca, cb = a.capture(os.path.join(d, "a.pcap")), b.capture(os.path.join(d, "b.pcap"))
            try:
                me = os.path.abspath(__file__)
                pa = subprocess.Popen(a.cmd([sys.executable, me, "--client", "fetch", f"https://{MODEL_HOST}/"]),
                                      stdout=subprocess.PIPE, text=True)
                pb = subprocess.Popen(b.cmd([sys.executable, me, "--client", "fetch", "https://www.example.com/"]),
                                      stdout=subprocess.PIPE, text=True)
                fa = json.loads((pa.communicate(timeout=60)[0].strip().splitlines() or ["{}"])[-1])
                fb = json.loads((pb.communicate(timeout=60)[0].strip().splitlines() or ["{}"])[-1])
                time.sleep(1)
            finally:
                ca.stop()
                cb.stop()
            # reachability is tested after the captures stop, so its probe packets are not part of the capture check
            reach_run = in_ns(a, "reach", b.ns_ip, 9)
            reach_vm = in_ns(a, "reach", a.host_ip, 22)
            reach_meta = in_ns(a, "reach", "169.254.169.254", 80)
            ra = tshark_rows(ca.path, "ip", ["ip.src", "ip.dst"])
            rb = tshark_rows(cb.path, "ip", ["ip.src", "ip.dst"])
            sni_a = {r[0] for r in tshark_rows(ca.path, "tls.handshake.type == 1",
                                               ["tls.handshake.extensions_server_name"])}
            sni_b = {r[0] for r in tshark_rows(cb.path, "tls.handshake.type == 1",
                                               ["tls.handshake.extensions_server_name"])}
            ips_a = {ip for row in ra for ip in row}
            ips_b = {ip for row in rb for ip in row}
            clean = (b.ns_ip not in ips_a and a.ns_ip not in ips_b and a.ns_ip in ips_a and b.ns_ip in ips_b)
            ok = (fa.get("ok") and fb.get("ok") and sni_a == {MODEL_HOST} and sni_b == {"www.example.com"} and clean
                  and reach_run.get("result") == "timeout" and reach_vm.get("result") == "timeout"
                  and reach_meta.get("result") == "timeout")
            self.record("V2 isolation", ok,
                        f"run A fetched {MODEL_HOST} ({fa}), run B fetched www.example.com ({fb}) at the same time; "
                        f"capture A: {len(ra)} packets, server names {sorted(sni_a)}; capture B: {len(rb)} packets, "
                        f"server names {sorted(sni_b)}; no packet of one run in the other's capture {clean}; "
                        f"A to B {reach_run}, A to the VM {reach_vm}, A to the metadata address {reach_meta}")

    # V3 and V4
    def with_rerun(self, attempt, index, rerun_index, name):
        """Runs one attempt; when the endpoint dropped a call, records the drop and runs the attempt once more."""
        first = attempt(index, name)
        if not first["drops"]:
            return first, ""
        note = f"first attempt: {describe_drops(first['drops'])}; rerun once"
        second = attempt(rerun_index, name + "_rerun")
        second["first_drops"] = first["drops"]
        if second["drops"]:
            note += f"; rerun: {describe_drops(second['drops'])}, so the endpoint dropped a call again"
        else:
            note += "; the rerun had no upstream drop"
        return second, note

    def anthropic_attempt(self, index, name):
        import netns
        d = os.path.join(self.out, name)
        with netns.RunNet(index) as net:
            cap = net.capture(os.path.join(d, "run.pcap"))
            gw = None
            try:
                gw, log, keylog = self.start_gateway(net, d, "gw", ANTHROPIC_BASE, 8081)
                res = in_ns(net, "anthropic", 8081)
                time.sleep(0.5)
            finally:
                if gw:
                    self.stop(gw)
                time.sleep(1)
                cap.stop()
            calls = read_jsonl(log, "call")
            return dict(res=res, calls=calls, flows=flows(cap.path, net.ns_ip), pcap=cap.path, keylog=keylog,
                        drops=upstream_drops(calls, close_events(cap.path, net.ns_ip)))

    def anthropic_api(self):
        a, note = self.with_rerun(self.anthropic_attempt, 13, 23, "anthropic_api")
        lead = note + "; " if note else ""
        res, calls, fl = a["res"], a["calls"], a["flows"]
        data = dict(client=res, calls=calls, flows=fl, first_attempt_drops=a.get("first_drops"),
                    drops=a["drops"])
        if a["drops"]:
            self.record("V3 Anthropic API", False, note, data)
            self.record("V4 key log", False, "not run: the endpoint dropped a call on both attempts")
            return
        mf = model_flows(fl)
        if "error" in res or len(calls) != 3:
            self.record("V3 Anthropic API", False, f"{lead}client result {str(res)[:400]}; {len(calls)} logged calls",
                        data)
            self.record("V4 key log", False, "not run: V3 did not complete")
            return
        tool_ok = res["tool"]["status"] == 200
        s = res["stream"]
        g = calls[1]
        first_arrival = s["reads"][0][0] if s["reads"] else None
        span = (g["t_end"] - g["t_first_byte"]) if g["t_first_byte"] else 0
        lag = (first_arrival - g["t_first_byte"]) if first_arrival and g["t_first_byte"] else None
        streamed = (s["status"] == 200 and len(s["reads"]) >= 5 and lag is not None and lag < 0.25
                    and span >= 1.0 and first_arrival < g["t_end"] - 0.5)
        one_conn = len({c["up_conn"] for c in calls}) == 1 and [c["up_new"] for c in calls] == [True, False, False]
        ok = tool_ok and streamed and one_conn and len(mf) == 1 and all(c["status"] == 200 for c in calls)
        self.record("V3 Anthropic API", ok,
                    f"{lead}tool request {res['tool']['status']}, tool call returned {res['tool']['tool_use']}; long "
                    f"answer streamed over {span:.2f} s in {len(s['reads'])} reads, first piece reached the client "
                    f"{(lag or 0) * 1e3:.0f} ms after the gateway read it; statuses "
                    f"{[c['status'] for c in calls]}; one upstream connection for 3 calls {one_conn}; TLS "
                    f"connections to {MODEL_HOST} in the capture {len(mf)}"
                    + (f"; error body {res['tool']['head'] or s['head']}" if not tool_ok or s['status'] != 200
                       else ""), data)
        # V4: decrypt with the run's key log, then without it
        req = tshark_rows(a["pcap"], "http.request", ["http.request.method", "http.request.uri",
                                                      "http.content_length"], keylog=a["keylog"])
        rsp = tshark_rows(a["pcap"], "http.response", ["http.response.code"], keylog=a["keylog"])
        plain = tshark_rows(a["pcap"], "http", ["frame.number"])
        dec_lengths = [int(r[2]) for r in req if len(r) > 2 and r[2].isdigit()]
        logged = [c["req_body_bytes"] for c in calls]
        f = mf[0] if mf else {}
        framed = sum(c["req_head_bytes"] + c["req_wire_body_bytes"] for c in calls)
        ok4 = dec_lengths == logged and [r[0] for r in rsp] == ["200"] * 3 and not plain
        self.record("V4 key log", ok4,
                    f"with the key log tshark decrypted {len(req)} requests with lengths {dec_lengths} (gateway "
                    f"logged {logged}) and {len(rsp)} responses {[r[0] for r in rsp]}; without it "
                    f"{len(plain)} HTTP frames; upload on the wire {f.get('up_tls', 0)} bytes of TLS records and "
                    f"{f.get('up_tcp', 0)} TCP bytes without resends ({f.get('resent', 0)} bytes resent) for "
                    f"{framed} bytes of HTTP, so TLS overhead {f.get('up_tls', 0) - framed} bytes over 3 calls")

    # V5
    def responses_attempt(self, index, name):
        import netns
        d = os.path.join(self.out, name)
        with netns.RunNet(index) as net:
            cap = net.capture(os.path.join(d, "run.pcap"))
            gw = None
            try:
                gw, log, _ = self.start_gateway(net, d, "gw", RESPONSES_BASE, 8082)
                res = in_ns(net, "responses", 8082)
                alpn = in_ns(net, "alpn", MODEL_HOST)
            finally:
                if gw:
                    self.stop(gw)
                time.sleep(1)
                cap.stop()
            calls = read_jsonl(log, "call")
            return dict(res=res, alpn=alpn, calls=calls, pcap=cap.path,
                        drops=upstream_drops(calls, close_events(cap.path, net.ns_ip)))

    def responses_api(self):
        a, note = self.with_rerun(self.responses_attempt, 14, 24, "responses_api")
        self.alpn = a["alpn"]
        res, calls = a["res"], a["calls"]
        data = dict(client=res, calls=calls, first_attempt_drops=a.get("first_drops"), drops=a["drops"])
        if a["drops"]:
            self.record("V5 Responses API", False, note, data)
            return
        ok = res.get("status") == 200 and len(calls) == 1 \
            and (calls[0]["resp_content_type"] or "").startswith("text/event-stream")
        self.record("V5 Responses API", ok,
                    (note + "; " if note else "")
                    + f"POST /responses {res.get('status')}, content type {res.get('content_type')}, function call "
                    f"to word_count {res.get('function_call')}, events {res.get('events')}"
                    + (f"; error body {res.get('head') or res.get('error')}" if not ok else ""), data)

    # V6 to V8
    def agent_run(self, which, mode, index):
        """Gateway runs get the upstream-drop rerun; direct runs have no gateway log to read drops from."""
        if mode == "gateway":
            return self.with_rerun(lambda i, name: self.agent(which, mode, i, name), index, index + 10,
                                   f"{which}_{mode}")
        return self.agent(which, mode, index, f"{which}_{mode}"), ""

    def agent(self, which, mode, index, name):
        import netns
        from offline_check import AGENT_PROMPT, MCP, codex_config
        d = os.path.join(self.out, name)
        home, ws = os.path.join(d, "home"), os.path.join(d, "ws")
        os.makedirs(home, exist_ok=True)
        os.makedirs(ws, exist_ok=True)
        tool_log = os.path.join(d, "tools.jsonl")
        mcp = {"command": sys.executable, "args": [MCP], "env": {"UT_TOOL_LOG": tool_log, "UT_WORKSPACE": ws}}
        env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "OPENAI_", "CODEX_", "CLAUDE_"))
               and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
        env.update(HOME=home, UT_TOOL_LOG=tool_log, UT_WORKSPACE=ws)
        with netns.RunNet(index) as net:
            cap = net.capture(os.path.join(d, "run.pcap"))
            gw = log = None
            if which == "claude":
                if mode == "gateway":
                    gw, log, _ = self.start_gateway(net, d, "gw", ANTHROPIC_BASE, 8081)
                base = "http://127.0.0.1:8081" if mode == "gateway" else ANTHROPIC_BASE
                cfg = os.path.join(d, "mcp.json")
                with open(cfg, "w") as f:
                    json.dump({"mcpServers": {"bench": dict(mcp, type="stdio")}}, f)
                env.update(ANTHROPIC_BASE_URL=base, ANTHROPIC_AUTH_TOKEN=self.key,
                           ANTHROPIC_MODEL="deepseek-flash[1m]", ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-flash[1m]",
                           ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-flash[1m]",
                           ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-flash")
                cmd = ["claude", "-p", AGENT_PROMPT, "--mcp-config", cfg, "--strict-mcp-config", "--allowedTools",
                       "mcp__bench__word_count", "--output-format", "json", "--max-turns", "6"]
            else:
                if mode == "gateway":
                    gw, log, _ = self.start_gateway(net, d, "gw", RESPONSES_BASE, 8082)
                base = "http://127.0.0.1:8082" if mode == "gateway" else RESPONSES_BASE + "/"
                codex_home = os.path.join(home, ".codex")
                os.makedirs(codex_home, exist_ok=True)
                with open(os.path.join(codex_home, "config.toml"), "w") as f:
                    f.write(codex_config(base, mcp))
                env.update(CODEX_HOME=codex_home, DEEPSEEK_API_KEY=self.key)
                cmd = ["codex", "exec", "--skip-git-repo-check", "--ephemeral", "-C", ws, "-o",
                       os.path.join(d, "last_message.txt"), AGENT_PROMPT]
            t0 = time.time()
            try:
                p = subprocess.run(net.cmd(cmd), env=env, cwd=ws, stdin=subprocess.DEVNULL, capture_output=True,
                                   text=True, timeout=AGENT_TIMEOUT)
                code, out, err = p.returncode, p.stdout, p.stderr
            except subprocess.TimeoutExpired as e:
                code, out, err = "timeout", str(e.stdout or ""), str(e.stderr or "")
            finally:
                time.sleep(1)
                if gw:
                    self.stop(gw)
                cap.stop()
            took = time.time() - t0
            with open(os.path.join(d, "agent_stdout.txt"), "w") as f:
                f.write(out)
            with open(os.path.join(d, "agent_stderr.txt"), "w") as f:
                f.write(err)
            fl = flows(cap.path, net.ns_ip)
            events = close_events(cap.path, net.ns_ip)
        answer = ""
        if which == "claude":
            try:
                answer = str(json.loads(out).get("result", ""))
            except ValueError:
                pass
        elif os.path.exists(os.path.join(d, "last_message.txt")):
            with open(os.path.join(d, "last_message.txt")) as f:
                answer = f.read()
        calls = read_jsonl(log, "call") if log else []
        tools = read_jsonl(tool_log, "tool_call")
        mf = model_flows(fl)
        return dict(which=which, mode=mode, exit=code, seconds=round(took, 1), answer=answer.strip()[-200:],
                    calls=calls, tools=tools, model_flows=mf, pcap=cap.path, drops=upstream_drops(calls, events),
                    other_hosts=sorted({f.get("sni") for f in fl.values()
                                        if f.get("sni") and f.get("sni") != MODEL_HOST}),
                    stderr_tail=err.strip()[-400:])

    def agent_check(self, name, r, note=""):
        if r["drops"]:
            self.record(name, False, note, r)
            return
        model_calls = [c for c in r["calls"] if c["path"].split("?")[0].endswith(("/v1/messages", "/responses"))]
        streamed = [c for c in model_calls if (c["resp_content_type"] or "").startswith("text/event-stream")]
        agent_conns = {c["conn"] for c in r["calls"]}
        up_conns = {c["up_conn"] for c in r["calls"] if c["up_conn"]}
        agent_closes = [c for c in r["calls"] if c["error"] and c.get("error_side") == "agent"]
        errors = [c["error"] for c in r["calls"] if c["error"] and c.get("error_side") != "agent"]
        ok = (r["exit"] == 0 and answered(r["answer"]) and len(model_calls) >= 2 and streamed
              and all(c["status"] == 200 for c in model_calls) and r["tools"] and r["tools"][0]["tool"] == "word_count"
              and len(agent_conns) == len(up_conns) and not errors and r["model_flows"])
        self.record(name, ok,
                    (note + "; " if note else "")
                    + f"exit {r['exit']} in {r['seconds']} s, answer {r['answer'][-40:]!r}; {len(model_calls)} model "
                    f"calls (statuses {[c['status'] for c in model_calls]}, {len(streamed)} streamed, request bytes "
                    f"{[c['req_body_bytes'] for c in model_calls]}); tool calls "
                    f"{[(t['tool'], t['args_bytes']) for t in r['tools']]}; "
                    f"agent connections {len(agent_conns)}, upstream connections {len(up_conns)}; calls the agent "
                    f"closed itself {len(agent_closes)}; gateway or endpoint errors {errors}; TLS connections "
                    f"to {MODEL_HOST} {len(r['model_flows'])}; other hosts {r['other_hosts']}"
                    + (f"; stderr {r['stderr_tail'][-300:]}" if not ok else ""), r)

    def fidelity(self, direct, gateway, label):
        def summary(r):
            mf = r["model_flows"]
            total = lambda k: sum(f.get(k, 0) for f in mf)
            return dict(connections=len(mf), offered=sorted({f.get("offered", "") for f in mf}),
                        selected=sorted({f.get("selected", "") for f in mf if f.get("selected")}),
                        up_tls=total("up_tls"), up_tcp=total("up_tcp"), up_raw=total("up_raw"),
                        resent=total("resent"), tool_calls=len(r["tools"]), exit=r["exit"],
                        answer=r["answer"][-20:])

        def pct(g, d):
            return f"{(g - d) / d * 100:+.1f}%" if d else "n/a"
        sd, sg = summary(direct), summary(gateway)
        probe = getattr(self, "alpn", None) or {}
        server_h2 = probe.get("selected") == "h2"
        direct_h2 = any("h2" in o.split(",") for o in sd["offered"]) and server_h2
        same_protocol = not direct_h2   # the gateway speaks HTTP/1.1 upstream
        same_conns = sd["connections"] == sg["connections"]
        ok = (direct["exit"] == 0 and gateway["exit"] == 0 and "selected" in probe and same_protocol and same_conns
              and sd["connections"] > 0)
        self.record(f"V8 fidelity {label}", ok,
                    (f"ALPN probe of {MODEL_HOST} failed {probe}; " if "selected" not in probe else "")
                    + ("the gateway run is the rerun after an upstream drop; " if gateway.get("first_drops") else "")
                    + f"TLS connections to {MODEL_HOST}: straight to DeepSeek {sd['connections']}, through the "
                    f"gateway {sg['connections']}; offered ALPN: straight {sd['offered']}, gateway {sg['offered']}; "
                    f"upload as TLS records: straight {sd['up_tls']} B, gateway {sg['up_tls']} B "
                    f"({pct(sg['up_tls'], sd['up_tls'])}); upload as TCP bytes without resends: straight "
                    f"{sd['up_tcp']} B, gateway {sg['up_tcp']} B ({pct(sg['up_tcp'], sd['up_tcp'])}); resent: "
                    f"straight {sd['resent']} B, gateway {sg['resent']} B; tool calls: straight {sd['tool_calls']}, "
                    f"gateway {sg['tool_calls']}; {MODEL_HOST} picks h2 when offered: {server_h2}; same HTTP "
                    f"version on the wire {same_protocol}; same number of connections {same_conns}",
                    dict(direct=sd, gateway=sg))

    def guard(self, name, fn, *args):
        try:
            return fn(*args)
        except Exception as e:
            self.record(name, False, f"stopped with {type(e).__name__}: {e}")
            return None

    def delete_keylogs(self):
        removed = 0
        for root, _, files in os.walk(self.out):
            for f in files:
                if f.endswith(".keys"):
                    os.remove(os.path.join(root, f))
                    removed += 1
        return removed


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", default=None, help=argparse.SUPPRESS)
    ap.add_argument("args", nargs="*", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.client:
        fn = dict(anthropic=lambda: client_anthropic(int(a.args[0])),
                  responses=lambda: client_responses(int(a.args[0])),
                  fetch=lambda: client_fetch(a.args[0]), reach=lambda: client_reach(a.args[0], int(a.args[1])),
                  alpn=lambda: client_alpn(a.args[0]))[a.client]
        try:
            print(json.dumps(fn()))
        except Exception as e:
            print(json.dumps(dict(error=f"{type(e).__name__}: {e}")))
        return 0

    key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not key and sys.stdin.isatty():
        import getpass
        key = getpass.getpass("DeepSeek API key: ")
        os.environ["DEEPSEEK_API_KEY"] = key
    stamp = time.strftime("%Y%m%d_%H%M%S")
    out = os.path.join(REPO, "data", "harness", "vm_gate", stamp)
    os.makedirs(out, exist_ok=True)
    g = Gate(out, key)
    print(f"VM gate {stamp}, output {out}\n", flush=True)
    try:
        if not g.environment():
            print("\nV0 failed; the other checks need it")
            return 1
        import netns
        netns.cleanup_all()
        g.guard("V1 offline checks", g.offline)
        g.guard("V2 isolation", g.isolation)
        g.guard("V3 Anthropic API", g.anthropic_api)
        g.guard("V5 Responses API", g.responses_api)
        runs = {}
        for i, (which, mode) in enumerate([("claude", "gateway"), ("codex", "gateway"), ("claude", "direct"),
                                           ("codex", "direct")]):
            runs[(which, mode)] = g.guard(f"{which} {mode} run", g.agent_run, which, mode, 15 + i) or (None, "")
        for name, run_key in (("V6 Claude Code", ("claude", "gateway")), ("V7 Codex", ("codex", "gateway"))):
            run, note = runs[run_key]
            if run:
                g.agent_check(name, run, note)
            else:
                g.record(name, False, "the run did not complete")
        for label, which in (("Claude Code", "claude"), ("Codex", "codex")):
            direct, gateway = runs[(which, "direct")][0], runs[(which, "gateway")][0]
            if direct and gateway and not gateway["drops"]:
                g.fidelity(direct, gateway, label)
            else:
                g.record(f"V8 fidelity {label}", False, "a run did not complete or the endpoint dropped a call on "
                                                         "both gateway attempts")
    finally:
        removed = g.delete_keylogs()
        try:
            import netns
            netns.cleanup_all()
        except Exception:
            pass
        print(f"\nkey logs deleted: {removed}")
    passed = {r["check"].split()[0]: r["passed"] for r in g.results}
    fid = [r["passed"] for r in g.results if r["check"].startswith("V8")]
    gates = {
        "GATE 1 Codex on DeepSeek (V5, V7)": all(passed.get(k) for k in ("V5", "V7")),
        "GATE 2 gateway keeps the traffic shape (V1, V3, V8)": all(passed.get(k) for k in ("V1", "V3")) and fid
        and all(fid),
        "TESTBED isolation, capture, key log, Claude Code (V0, V2, V4, V6)": all(
            passed.get(k) for k in ("V0", "V2", "V4", "V6")),
    }
    print()
    for name, ok in gates.items():
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    with open(os.path.join(out, "vm_gate.json"), "w") as f:
        json.dump(dict(stamp=stamp, gates=gates, results=g.results), f, indent=1, default=str)
    print(f"\nreport {os.path.join(out, 'vm_gate.json')}")
    return 0 if all(gates.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
