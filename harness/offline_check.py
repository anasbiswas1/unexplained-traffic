"""Offline checks of the call gateway and the MCP tool log. No network, no root, standard library only.

A local fake endpoint stands in for the model endpoint. The gateway under test runs as its own process, exactly as on
the VM. Checks:
  O1 request sizes      exact request body length logged and forwarded byte for byte, 0 B to 1 MB, fixed-length and
                        chunked uploads
  O2 response sizes     exact response body length logged and relayed byte for byte, fixed-length and chunked
  O3 streaming          streamed events reach the client when the endpoint sends them, not when the response ends
  O4 connection reuse   one upstream connection per client connection, reused across calls; concurrent clients get
                        one each
  O5 reconnect          an endpoint that answers with Connection: close is followed by one new upstream connection,
                        logged as such
  O6 idle close         an endpoint that drops the idle connection between calls is followed by one new upstream
                        connection, and the client's next call succeeds on its kept connection
  O7 client close       a client that closes ends its upstream connection
  O8 no-body responses  HEAD and 204 keep the connection in step
  O9 expect-continue    a client that waits for 100 Continue sends its body and is sized exactly
  O10 TLS key log       an HTTPS upstream works and its session keys reach the key log (needs the openssl command)
  O11 MCP tool log      tool calls are answered and their argument sizes logged exactly
  O12 endpoint drop     an endpoint that drops a stream inside the body: the log keeps the bytes relayed before the
                        drop and names the upstream side
  O13 agent close       an agent that closes after the last event, before the end of the stream: the log keeps the
                        bytes relayed and names the agent side
With --agents, real agent clients run against the fake endpoint through the gateway, with the MCP tool server:
  A1 Claude Code (needs the claude command), A2 Codex (needs the codex command).

Usage: python3 harness/offline_check.py [--agents] [--out DIR]
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
GATEWAY = os.path.join(HERE, "call_gateway.py")
MCP = os.path.join(HERE, "mcp_tools.py")
SIZES = [0, 1, 2, 100, 1000, 65535, 65536, 65537, 100_000, 999_999, 1_000_000]
CHUNKED_SIZES = [0, 1, 70_000, 1_000_000]
AGENT_PROMPT = ("Use the word_count tool to count the words in this text: 'alpha beta gamma delta'. "
                "Then reply with only the number.")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------- fake endpoint
class FakeEndpoint:
    """Minimal HTTP/1.1 endpoint with keep-alive, chunked and fixed-length bodies, SSE streams, and fake Anthropic
    Messages and Responses APIs that call one tool and then answer with its result."""

    def __init__(self, tls_ctx=None, host="127.0.0.1", port=None):
        self.tls_ctx = tls_ctx
        self.host = host
        self.port = port or free_port()
        self.conns = []          # one dict per accepted connection
        self.requests = []       # one dict per request
        self.sse_sent = {}       # stream id -> list of send times
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()
        self.ready.wait(10)

    def _run(self):
        asyncio.set_event_loop(self.loop)
        server = self.loop.run_until_complete(asyncio.start_server(self.handle, self.host, self.port,
                                                                   ssl=self.tls_ctx, limit=1 << 20))
        self.ready.set()
        self.loop.run_forever()
        server.close()

    async def read_body(self, reader, headers):
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = bytearray()
            while True:
                size = int((await reader.readuntil(b"\r\n")).split(b";")[0], 16)
                if size == 0:
                    while (await reader.readuntil(b"\r\n")) != b"\r\n":
                        pass
                    return bytes(body)
                body += await reader.readexactly(size)
                await reader.readexactly(2)
        n = int(headers.get("content-length", "0") or 0)
        return await reader.readexactly(n) if n else b""

    async def handle(self, reader, writer):
        conn = dict(id=len(self.conns) + 1, peer=writer.get_extra_info("peername")[1], requests=0, eof=False)
        self.conns.append(conn)
        try:
            while True:
                try:
                    raw = await reader.readuntil(b"\r\n\r\n")
                except asyncio.IncompleteReadError:
                    conn["eof"] = True
                    return
                lines = raw.decode("latin-1").split("\r\n")
                method, target, _ = lines[0].split(" ", 2)
                headers = {}
                for ln in lines[1:]:
                    if ln:
                        k, _, v = ln.partition(":")
                        headers[k.strip().lower()] = v.strip()
                if headers.get("expect", "").lower() == "100-continue":
                    writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                body = await self.read_body(reader, headers)
                conn["requests"] += 1
                self.requests.append(dict(conn=conn["id"], method=method, target=target, headers=headers,
                                          length=len(body), sha256=hashlib.sha256(body).hexdigest(), t=time.time()))
                close = await self.route(method, target, headers, body, writer)
                if close == "idle":
                    await asyncio.sleep(0.2)   # the endpoint drops the kept connection while it is idle
                    writer.close()
                    return
                if close:
                    writer.close()
                    return
        except (ConnectionError, asyncio.IncompleteReadError):
            conn["eof"] = True
        finally:
            writer.close()

    @staticmethod
    def head(status, reason, headers):
        out = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
        return out.encode("latin-1")

    async def send_fixed(self, writer, status, body, ctype="application/json", extra=(), method="POST"):
        writer.write(self.head(status, "OK" if status < 400 else "Error",
                               [("Content-Type", ctype), ("Content-Length", str(len(body))), *extra])
                     + (b"" if method == "HEAD" else body))
        await writer.drain()

    async def send_chunked(self, writer, pieces, ctype, gap=0.0, stream_id=None, end_gap=0.0, cut_after=None):
        writer.write(self.head(200, "OK", [("Content-Type", ctype), ("Transfer-Encoding", "chunked")]))
        await writer.drain()
        times = self.sse_sent.setdefault(stream_id, []) if stream_id else None
        for i, piece in enumerate(pieces):
            if gap and i:
                await asyncio.sleep(gap)
            if cut_after is not None and i == cut_after:
                writer.close()    # the endpoint drops the connection inside the body
                raise ConnectionError("endpoint dropped the stream")
            if times is not None:
                times.append(time.time())
            writer.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            await writer.drain()
        if end_gap:
            await asyncio.sleep(end_gap)
        writer.write(b"0\r\n\r\n")
        await writer.drain()

    async def route(self, method, target, headers, body, writer):
        u = urlsplit(target)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        path = u.path
        if path.endswith("/size"):
            await self.send_fixed(writer, 200, json.dumps({"len": len(body),
                                                           "sha256": hashlib.sha256(body).hexdigest()}).encode())
        elif path.endswith("/bigresp"):
            data = random.Random(int(q.get("n", 0))).randbytes(int(q.get("n", 0)))
            if q.get("chunked") == "1":
                step = 7919
                await self.send_chunked(writer, [data[i:i + step] for i in range(0, len(data), step)] or [],
                                        "application/octet-stream")
            else:
                await self.send_fixed(writer, 200, data, "application/octet-stream")
        elif path.endswith("/sse"):
            n, gap = int(q.get("events", 5)), float(q.get("gap", 0.25))
            pieces = [f"event: tick\ndata: {{\"i\": {i}}}\n\n".encode() for i in range(n)]
            cut = int(q["cut"]) if "cut" in q else None
            await self.send_chunked(writer, pieces, "text/event-stream", gap, q.get("id", "sse"),
                                    float(q.get("endgap", 0)), cut)
            if cut is not None:
                return True
        elif path.endswith("/close"):
            body = b'{"closing": true}'
            writer.write(self.head(200, "OK", [("Content-Type", "application/json"),
                                               ("Content-Length", str(len(body))), ("Connection", "close")]) + body)
            await writer.drain()
            return True
        elif path.endswith("/idleclose"):
            await self.send_fixed(writer, 200, b'{"idle_close": true}')
            return "idle"
        elif path.endswith("/nocontent"):
            writer.write(self.head(204, "No Content", []))
            await writer.drain()
        elif path.endswith("/head") and method == "HEAD":
            writer.write(self.head(200, "OK", [("Content-Type", "text/plain"), ("Content-Length", "12345")]))
            await writer.drain()
        elif path.endswith("/v1/messages/count_tokens"):
            await self.send_fixed(writer, 200, b'{"input_tokens": 10}')
        elif path.endswith("/v1/messages"):
            await self.anthropic(json.loads(body or b"{}"), writer)
        elif path.endswith("/responses"):
            await self.responses(json.loads(body or b"{}"), writer)
        elif path.endswith("/models"):
            await self.send_fixed(writer, 200, json.dumps({"object": "list", "data": [
                {"id": "deepseek-flash", "object": "model", "created": 0, "owned_by": "deepseek"},
                {"id": "deepseek-v4-pro", "object": "model", "created": 0, "owned_by": "deepseek"}]}).encode())
        else:
            await self.send_fixed(writer, 404, json.dumps({"error": f"no route {method} {path}"}).encode(),
                                  method=method)
        return False

    # fake model logic shared by both APIs: call the word_count tool once, then answer with its result
    @staticmethod
    def find_tool(tools, parent=None):
        for t in tools or []:
            if not isinstance(t, dict):
                continue
            name = str(t.get("name", ""))
            if name.endswith("word_count"):
                return name, (parent or t.get("namespace"))
            inner = t.get("tools")
            if isinstance(inner, list):
                found = FakeEndpoint.find_tool(inner, name or parent)
                if found:
                    return found
        return None

    @staticmethod
    def answer_from(result):
        # the agent wraps the tool output in its own text; the fake model answers with the last number in it
        if result is None:
            return "ok"
        numbers = re.findall(r"\d+", result)
        return numbers[-1] if numbers else result.strip()

    @staticmethod
    def quoted(text):
        m = re.search(r"'([^']+)'", text or "")
        return m.group(1) if m else ""

    async def anthropic(self, req, writer):
        result, prompt = None, ""
        for m in req.get("messages") or []:
            content = m.get("content")
            if isinstance(content, str):
                prompt = content if m.get("role") == "user" else prompt
                continue
            for b in content or []:
                if b.get("type") == "tool_result":
                    c = b.get("content")
                    result = c if isinstance(c, str) else "".join(x.get("text", "") for x in c or [])
                elif b.get("type") == "text" and m.get("role") == "user":
                    prompt = b.get("text", "")
        tool = self.find_tool(req.get("tools"))
        model = req.get("model", "deepseek-flash")
        forced = (req.get("tool_choice") or {}).get("type") in ("tool", "any")
        if result is None and tool and ("word_count" in prompt or forced):
            block = {"type": "tool_use", "id": "toolu_01", "name": tool[0], "input": {}}
            deltas = [{"type": "input_json_delta",
                       "partial_json": json.dumps({"text": self.quoted(prompt)})}]
            stop = "tool_use"
            message_content = [{"type": "tool_use", "id": "toolu_01", "name": tool[0],
                                "input": {"text": self.quoted(prompt)}}]
        elif "1 to 400" in prompt:
            numbers = " ".join(str(i) for i in range(1, 401))
            block = {"type": "text", "text": ""}
            deltas = [{"type": "text_delta", "text": numbers[i:i + 40]} for i in range(0, len(numbers), 40)]
            stop = "end_turn"
            message_content = [{"type": "text", "text": numbers}]
        else:
            text = self.answer_from(result)
            block = {"type": "text", "text": ""}
            deltas = [{"type": "text_delta", "text": text}]
            stop = "end_turn"
            message_content = [{"type": "text", "text": text}]
        usage = {"input_tokens": 10, "output_tokens": 5}
        if not req.get("stream"):
            await self.send_fixed(writer, 200, json.dumps({
                "id": "msg_01", "type": "message", "role": "assistant", "model": model,
                "content": message_content, "stop_reason": stop, "stop_sequence": None, "usage": usage}).encode())
            return
        events = [("message_start", {"type": "message_start", "message": {
                      "id": "msg_01", "type": "message", "role": "assistant", "model": model, "content": [],
                      "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}),
                  ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": block})]
        events += [("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": d}) for d in deltas]
        events += [("content_block_stop", {"type": "content_block_stop", "index": 0}),
                   ("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                      "usage": {"output_tokens": 5}}),
                   ("message_stop", {"type": "message_stop"})]
        pieces = [f"event: {e}\ndata: {json.dumps(d)}\n\n".encode() for e, d in events]
        await self.send_chunked(writer, pieces, "text/event-stream", 0.05 if len(deltas) > 10 else 0.02)

    async def responses(self, req, writer):
        result, prompt = None, ""
        items = req.get("input")
        items = [{"type": "message", "role": "user", "content": items}] if isinstance(items, str) else items or []
        for it in items:
            if it.get("type") == "function_call_output":
                out = it.get("output")
                result = out if isinstance(out, str) else json.dumps(out)
            elif it.get("type") == "message" and it.get("role") == "user":
                c = it.get("content")
                prompt = c if isinstance(c, str) else "".join(x.get("text", "") for x in c or [])
        tool = self.find_tool(req.get("tools"))
        rid = "resp_%06d" % len(self.requests)
        events = [{"type": "response.created", "response": {"id": rid}}]
        if result is None and tool and ("word_count" in prompt or req.get("tool_choice") == "required"):
            item = {"type": "function_call", "call_id": "call_01", "name": tool[0],
                    "arguments": json.dumps({"text": self.quoted(prompt)})}
            if tool[1] and tool[1] != tool[0]:
                item["namespace"] = tool[1]
            events.append({"type": "response.output_item.done", "item": item})
        else:
            text = self.answer_from(result)
            msg = {"type": "message", "role": "assistant", "id": "msg_01",
                   "content": [{"type": "output_text", "text": text}]}
            events += [{"type": "response.output_item.added", "item": dict(msg, content=[])},
                       {"type": "response.output_text.delta", "delta": text},
                       {"type": "response.output_item.done", "item": msg}]
        events.append({"type": "response.completed", "response": {"id": rid, "usage": {
            "input_tokens": 10, "input_tokens_details": None, "output_tokens": 5, "output_tokens_details": None,
            "total_tokens": 15}}})
        pieces = [f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events]
        await self.send_chunked(writer, pieces, "text/event-stream", 0.02)


# ---------------------------------------------------------------- gateway process
class GatewayProc:
    def __init__(self, upstream, workdir, name, keylog=None, cafile=None):
        self.port = free_port()
        self.log = os.path.join(workdir, f"{name}_calls.jsonl")
        args = [sys.executable, GATEWAY, "--listen", f"127.0.0.1:{self.port}", "--upstream", upstream,
                "--log", self.log]
        if keylog:
            args += ["--keylog", keylog]
        if cafile:
            args += ["--cafile", cafile]
        self.proc = subprocess.Popen(args, stderr=subprocess.PIPE, text=True)
        line = self.proc.stderr.readline()
        if "listening" not in line:
            raise RuntimeError(f"gateway did not start: {line}")

    def records(self, event="call"):
        with open(self.log) as f:
            return [r for r in map(json.loads, f) if r.get("event") == event]

    def stop(self):
        self.proc.terminate()
        self.proc.wait(10)


# ---------------------------------------------------------------- raw client helpers
class RawClient:
    """HTTP/1.1 client on one kept-alive socket, so tests control framing and see arrival times."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port))
        self.buf = b""

    def send(self, method, path, body=b"", headers=(), chunked=False, chunk=8191):
        h = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", *headers]
        if chunked:
            h.append("Transfer-Encoding: chunked")
            self.sock.sendall(("\r\n".join(h) + "\r\n\r\n").encode())
            for i in range(0, len(body), chunk):
                piece = body[i:i + chunk]
                self.sock.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.sock.sendall(b"0\r\n\r\n")
        else:
            if method not in ("GET", "HEAD") or body:
                h.append(f"Content-Length: {len(body)}")
            self.sock.sendall(("\r\n".join(h) + "\r\n\r\n").encode() + body)

    def _fill(self):
        data = self.sock.recv(65536)
        if not data:
            raise ConnectionError("closed")
        self.buf += data
        return time.time()

    def _until(self, sep):
        while sep not in self.buf:
            self._fill()
        i = self.buf.index(sep) + len(sep)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def _exact(self, n):
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def response(self, method="POST", on_piece=None):
        while True:
            head = self._until(b"\r\n\r\n").decode("latin-1")
            status = int(head.split(" ", 2)[1])
            if status != 100:
                break
        hdr = {k.strip().lower(): v.strip() for k, _, v in
               (ln.partition(":") for ln in head.split("\r\n")[1:] if ln)}
        body = b""
        if method == "HEAD" or status in (204, 304):
            return status, hdr, body
        if "chunked" in hdr.get("transfer-encoding", ""):
            while True:
                size = int(self._until(b"\r\n").split(b";")[0], 16)
                if size == 0:
                    self._until(b"\r\n")
                    break
                piece = self._exact(size)
                if on_piece:
                    on_piece(piece, time.time())
                body += piece
                self._exact(2)
        else:
            body = self._exact(int(hdr.get("content-length", 0)))
        return status, hdr, body

    def close(self):
        self.sock.close()


# ---------------------------------------------------------------- checks
def check(results, name, passed, detail):
    results.append(dict(check=name, where="offline", passed=bool(passed), detail=detail))
    print(f"{'PASS' if passed else 'FAIL'}  {name}: {detail}", flush=True)


def run_core(results, workdir):
    fake = FakeEndpoint()
    gw = GatewayProc(f"http://127.0.0.1:{fake.port}/base", workdir, "core")
    rng = random.Random(7)
    def check_o1():
        """O1 request sizes"""
        c = RawClient(gw.port)
        bad = []
        cases = [(n, False) for n in SIZES] + [(n, True) for n in CHUNKED_SIZES]
        for n, chunked in cases:
            body = rng.randbytes(n)
            c.send("POST", "/size", body, ["Content-Type: application/octet-stream"], chunked=chunked,
                   chunk={0: 8191, 1: 1, 70_000: 1}.get(n, 777))
            status, _, resp = c.response()
            echo = json.loads(resp)
            if status != 200 or echo["len"] != n or echo["sha256"] != hashlib.sha256(body).hexdigest():
                bad.append((n, chunked, "upstream got", echo["len"]))
        c.close()
        time.sleep(0.2)
        logged = [r for r in gw.records() if r["path"] == "/size"]
        for (n, chunked), r in zip(cases, logged):
            if r["req_body_bytes"] != n or r["req_framing"] != ("chunked" if chunked else ("length" if True else "")):
                bad.append((n, chunked, "logged", r["req_body_bytes"], r["req_framing"]))
        prefix_ok = all(q["target"] == "/base/size" for q in fake.requests if q["target"].endswith("/size"))
        host_ok = all(q["headers"].get("host") == f"127.0.0.1:{fake.port}" for q in fake.requests)
        check(results, "O1 request sizes", not bad and len(logged) == len(cases) and prefix_ok and host_ok,
              f"{len(cases)} uploads from 0 B to 1 MB ({len(SIZES)} fixed-length, {len(CHUNKED_SIZES)} chunked): "
              f"logged length and upstream bytes exact for {len(cases) - len(bad)}/{len(cases)}; "
              f"path prefix kept {prefix_ok}; Host rewritten {host_ok}" + (f"; mismatches {bad[:3]}" if bad else ""))


    def check_o2():
        """O2 response sizes"""
        c = RawClient(gw.port)
        bad, cases = [], [(n, ch) for n in (0, 1, 1000, 1_000_000) for ch in (False, True)]
        for n, ch in cases:
            c.send("POST", f"/bigresp?n={n}&chunked={int(ch)}", b"{}")
            status, _, body = c.response()
            if body != random.Random(n).randbytes(n):
                bad.append((n, ch, "client got", len(body)))
        c.close()
        time.sleep(0.2)
        logged = [r for r in gw.records() if r["path"].startswith("/bigresp")]
        for (n, ch), r in zip(cases, logged):
            if r["resp_body_bytes"] != n or r["resp_framing"] != ("chunked" if ch else "length"):
                bad.append((n, ch, "logged", r["resp_body_bytes"]))
        check(results, "O2 response sizes", not bad and len(logged) == len(cases),
              f"{len(cases)} responses (0 B to 1 MB, fixed-length and chunked) relayed byte for byte and logged "
              f"exactly: {len(cases) - len(bad)}/{len(cases)}" + (f"; mismatches {bad[:3]}" if bad else ""))


    def check_o3():
        """O3 streaming"""
        c = RawClient(gw.port)
        arrivals = []
        c.send("POST", "/sse?events=8&gap=0.25&id=s1", b"{}")
        c.response(on_piece=lambda p, t: arrivals.append(t))
        c.close()
        sent = fake.sse_sent["s1"]
        lags = [a - s for a, s in zip(arrivals, sent)]
        r = [x for x in gw.records() if x["path"].startswith("/sse")][-1]
        first_before_last_sent = arrivals[0] < sent[-1] - 1.0
        ok = len(arrivals) == len(sent) == 8 and max(lags) < 0.1 and first_before_last_sent
        check(results, "O3 streaming", ok,
              f"8 events sent 250 ms apart over {sent[-1] - sent[0]:.2f} s; each reached the client "
              f"{min(lags) * 1e3:.1f} to {max(lags) * 1e3:.1f} ms after the endpoint sent it; first event arrived "
              f"{sent[-1] - arrivals[0]:.2f} s before the last was sent; gateway relayed {r['resp_pieces']} pieces")


    def check_o4():
        """O4 connection reuse"""
        before = len(fake.conns)
        c = RawClient(gw.port)
        for i in range(5):
            c.send("POST", "/size", b"x" * (i * 100))
            c.response()
        c.close()
        time.sleep(0.2)
        one = len(fake.conns) - before
        before = len(fake.conns)

        def worker():
            k = RawClient(gw.port)
            for i in range(3):
                k.send("POST", "/size", b"y" * 10)
                k.response()
            k.close()
        threads = [threading.Thread(target=worker) for _ in range(3)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        time.sleep(0.2)
        three = len(fake.conns) - before
        calls = gw.records()
        by_conn = {}
        for r in calls:
            by_conn.setdefault(r["conn"], set()).add(r["up_conn"])
        one_up_each = all(len(v) == 1 for v in by_conn.values() if v != {None})
        check(results, "O4 connection reuse", one == 1 and three == 3 and one_up_each,
              f"5 sequential calls on one client connection used {one} upstream connection; 3 concurrent clients "
              f"with 3 calls each used {three}; every client connection kept a single upstream connection "
              f"{one_up_each}")


    def check_o5():
        """O5 reconnect"""
        before = len(fake.conns)
        c = RawClient(gw.port)
        c.send("POST", "/size", b"a")
        c.response()
        c.send("POST", "/close", b"{}")
        s1, h1, _ = c.response()
        survived = True
        try:
            c.send("POST", "/size", b"bb")
            s2, _, b2 = c.response()
        except ConnectionError:
            survived, s2, b2 = False, None, b"{}"
        c.close()
        time.sleep(0.2)
        recs = gw.records()[-3:]
        closes = [r for r in gw.records("up_close") if r["reason"] == "upstream asked to close"]
        ok = (s1 == 200 and h1.get("connection") == "close" and closes and survived and s2 == 200
              and json.loads(b2).get("len") == 2
              and len(fake.conns) - before == 2 and [r["up_new"] for r in recs] == [True, False, True])
        check(results, "O5 reconnect", ok,
              f"the endpoint answered with Connection: close and the gateway passed that header to the client "
              f"({h1.get('connection')}); upstream close logged {bool(closes)}; the client's next call on its kept "
              f"connection returned {s2}; upstream connections {len(fake.conns) - before}; up_new on the calls "
              f"{[r['up_new'] for r in recs]}")

    def check_o6():
        """O6 idle close"""
        before = len(fake.conns)
        c = RawClient(gw.port)
        c.send("POST", "/idleclose", b"{}")
        s1, _, _ = c.response()
        time.sleep(0.6)
        c.send("POST", "/size", b"ccc")
        s2, _, b2 = c.response()
        c.close()
        time.sleep(0.2)
        recs = gw.records()[-2:]
        idle = [r for r in gw.records("up_close") if r["reason"] == "upstream closed while idle"]
        ok = (s1 == 200 and s2 == 200 and json.loads(b2)["len"] == 3 and idle and len(fake.conns) - before == 2
              and [r["up_new"] for r in recs] == [True, True] and not [r for r in recs if r["error"]])
        check(results, "O6 idle close", ok,
              f"the endpoint dropped the kept connection 0.2 s after a call; the client's next call 0.6 s later on "
              f"the same client connection returned {s2}; idle close logged {bool(idle)}; upstream connections "
              f"{len(fake.conns) - before}; up_new on the two calls {[r['up_new'] for r in recs]}")


    def check_o7():
        """O7 client close"""
        c = RawClient(gw.port)
        c.send("POST", "/size", b"z", ["Connection: close"])
        c.response()
        time.sleep(0.3)
        c.close()
        last_up = gw.records("up_close")[-1]
        check(results, "O7 client close", last_up["reason"] == "agent asked to close" and fake.conns[-1]["eof"],
              f"client sent Connection: close; gateway closed its upstream connection ({last_up['reason']}); "
              f"endpoint saw the close {fake.conns[-1]['eof']}")


    def check_o8():
        """O8 no-body responses"""
        before = len(fake.conns)
        c = RawClient(gw.port)
        c.send("HEAD", "/head")
        s_head, h_head, b_head = c.response("HEAD")
        c.send("POST", "/nocontent", b"{}")
        s_204, _, _ = c.response()
        c.send("POST", "/size", b"after")
        s_after, _, b_after = c.response()
        c.close()
        time.sleep(0.2)
        ok = (s_head == 200 and b_head == b"" and h_head.get("content-length") == "12345" and s_204 == 204
              and s_after == 200 and json.loads(b_after)["len"] == 5 and len(fake.conns) - before == 1)
        check(results, "O8 no-body responses", ok,
              f"HEAD {s_head} with Content-Length {h_head.get('content-length')} and no body, then 204, then a sized "
              f"call on the same connection: {s_after}, one upstream connection {len(fake.conns) - before == 1}")


    def check_o9():
        """O9 expect-continue"""
        c = RawClient(gw.port)
        body = rng.randbytes(50_000)
        head = (f"POST /size HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\nExpect: 100-continue\r\n\r\n")
        c.sock.sendall(head.encode())
        interim = c._until(b"\r\n\r\n")
        c.sock.sendall(body)
        status, _, resp = c.response()
        c.close()
        time.sleep(0.2)
        r = gw.records()[-1]
        ok = interim.startswith(b"HTTP/1.1 100") and status == 200 and json.loads(resp)["len"] == 50_000 \
            and r["req_body_bytes"] == 50_000 and r["expect_continue"]
        check(results, "O9 expect-continue", ok,
              f"client got 100 Continue from the gateway, sent 50000 bytes, endpoint received "
              f"{json.loads(resp)['len']}, logged {r['req_body_bytes']}")

    def check_o12():
        """O12 endpoint drop"""
        c = RawClient(gw.port)
        received = []
        c.send("POST", "/sse?events=4&gap=0.05&cut=2&id=drop", b"{}")
        try:
            c.response(on_piece=lambda p, t: received.append(p))
            closed = False
        except ConnectionError:
            closed = True
        c.close()
        time.sleep(0.3)
        r = [x for x in gw.records() if x["path"].startswith("/sse?") and "id=drop" in x["path"]][-1]
        sent = sum(len(p) for p in received)
        ok = (closed and r["error_side"] == "upstream" and r["resp_body_bytes"] == sent == 2 * 28
              and r["resp_pieces"] == 2)
        check(results, "O12 endpoint drop", ok,
              f"the endpoint sent 2 of 4 events and dropped the connection; the client got {sent} bytes and then a "
              f"closed connection {closed}; the gateway logged {r['resp_body_bytes']} bytes in {r['resp_pieces']} "
              f"pieces, error side {r['error_side']} ({r['error']})")

    def check_o13():
        """O13 agent close"""
        c = RawClient(gw.port)
        c.send("POST", "/sse?events=3&gap=0.05&endgap=0.3&id=early", b"{}")
        got = b""
        while got.count(b"event: tick") < 3:
            got += c.sock.recv(65536)
        c.sock.close()
        time.sleep(0.8)
        r = [x for x in gw.records() if x["path"].startswith("/sse?") and "id=early" in x["path"]][-1]
        up = [x for x in gw.records("up_close") if x["up_conn"] == r["up_conn"]]
        ok = r["error_side"] == "agent" and r["resp_body_bytes"] == 3 * 28 and up \
            and up[-1]["reason"] == "agent connection failed during the call"
        check(results, "O13 agent close", ok,
              f"the client closed after the 3rd event, before the end of the stream; the gateway logged "
              f"{r['resp_body_bytes']} bytes, error side {r['error_side']} ({r['error']}); upstream connection "
              f"closed: {up[-1]['reason'] if up else None}")

    try:
        for fn in (check_o1, check_o2, check_o3, check_o4, check_o5, check_o6, check_o7, check_o8, check_o9,
                   check_o12, check_o13):
            try:
                fn()
            except Exception as e:
                check(results, fn.__doc__, False, f"stopped with {type(e).__name__}: {e}")
    finally:
        gw.stop()


def run_tls(results, workdir):
    if not shutil.which("openssl"):
        results.append(dict(check="O10 TLS key log", where="offline", passed=None,
                            detail="skipped: openssl command not found"))
        print("SKIP  O10 TLS key log: openssl command not found")
        return
    key, crt = os.path.join(workdir, "fake.key"), os.path.join(workdir, "fake.crt")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(crt, key)
    ctx.set_alpn_protocols(["http/1.1"])
    fake = FakeEndpoint(ctx)
    keylog = os.path.join(workdir, "tls.keys")
    gw = GatewayProc(f"https://localhost:{fake.port}", workdir, "tls", keylog=keylog, cafile=crt)
    try:
        c = RawClient(gw.port)
        sizes = [0, 12345, 1_000_000]
        echoed = []
        for n in sizes:
            c.send("POST", "/size", b"k" * n)
            echoed.append(json.loads(c.response()[2])["len"])
        c.close()
        time.sleep(0.2)
        logged = [r["req_body_bytes"] for r in gw.records()]
        with open(keylog) as f:
            labels = {ln.split()[0] for ln in f if ln.strip() and not ln.startswith("#")}
        ok = echoed == sizes and logged == sizes and len(fake.conns) == 1 and \
            ("CLIENT_TRAFFIC_SECRET_0" in labels or "CLIENT_RANDOM" in labels)
        check(results, "O10 TLS key log", ok,
              f"HTTPS upstream with verified certificate: sizes {sizes} logged {logged}; one TLS connection "
              f"{len(fake.conns) == 1}; key log lines {sorted(labels)}")
    finally:
        gw.stop()


def run_mcp(results, workdir):
    log = os.path.join(workdir, "tools.jsonl")
    ws = os.path.join(workdir, "ws")
    env = dict(os.environ, UT_TOOL_LOG=log, UT_WORKSPACE=ws)
    p = subprocess.Popen([sys.executable, MCP], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
    args = {"text": "alpha beta gamma delta été"}
    call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "word_count", "arguments": args}}
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "t", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, call,
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}}}]
    lines = [json.dumps(m).encode() for m in msgs]
    out, _ = p.communicate(b"\n".join(lines) + b"\n", timeout=20)
    replies = [json.loads(x) for x in out.splitlines()]
    with open(log) as f:
        recs = [json.loads(x) for x in f]
    tc = [r for r in recs if r["event"] == "tool_call"]
    want_args = len(json.dumps(args, separators=(",", ":"), ensure_ascii=False).encode())
    ok = (len(replies) == 4 and replies[2]["result"]["content"][0]["text"] == "5"
          and len(replies[1]["result"]["tools"]) == 4 and len(tc) == 2
          and tc[0]["args_bytes"] == want_args and tc[0]["msg_bytes"] == len(lines[3])
          and tc[0]["result_bytes"] == len(out.splitlines()[2]) and tc[1]["is_error"] is True)
    check(results, "O11 MCP tool log", ok,
          f"initialize, tools/list and two tools/call answered; word_count returned "
          f"{replies[2]['result']['content'][0]['text']}; args_bytes {tc[0]['args_bytes'] if tc else None} "
          f"(expected {want_args}), msg_bytes exact {bool(tc) and tc[0]['msg_bytes'] == len(lines[3])}; "
          f"path outside the workspace refused {bool(tc) and tc[-1]['is_error']}")


# ---------------------------------------------------------------- real agent clients against the fake endpoint
def run_agent(results, workdir, which):
    exe = shutil.which("claude" if which == "claude" else "codex")
    name = "A1 Claude Code via gateway" if which == "claude" else "A2 Codex via gateway"
    if not exe:
        results.append(dict(check=name, where="offline", passed=None, detail="skipped: command not found"))
        print(f"SKIP  {name}: command not found")
        return
    fake = FakeEndpoint()
    run = os.path.join(workdir, which)
    home, ws = os.path.join(run, "home"), os.path.join(run, "ws")
    os.makedirs(home, exist_ok=True)
    os.makedirs(ws, exist_ok=True)
    tool_log = os.path.join(run, "tools.jsonl")
    upstream = f"http://127.0.0.1:{fake.port}" + ("/anthropic" if which == "claude" else "")
    gw = GatewayProc(upstream, run, which)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("ANTHROPIC_", "OPENAI_", "CODEX_", "CLAUDE_"))
           and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env.update(HOME=home, UT_TOOL_LOG=tool_log, UT_WORKSPACE=ws, NO_PROXY="127.0.0.1,localhost",
               no_proxy="127.0.0.1,localhost")
    mcp = {"command": sys.executable, "args": [MCP], "env": {"UT_TOOL_LOG": tool_log, "UT_WORKSPACE": ws}}
    if which == "claude":
        cfg = os.path.join(run, "mcp.json")
        with open(cfg, "w") as f:
            json.dump({"mcpServers": {"bench": dict(mcp, type="stdio")}}, f)
        env.update(ANTHROPIC_BASE_URL=f"http://127.0.0.1:{gw.port}", ANTHROPIC_AUTH_TOKEN="offline-test-token",
                   ANTHROPIC_MODEL="deepseek-flash", ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-flash",
                   ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-flash", ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-flash",
                   CLAUDE_CODE_SUBAGENT_MODEL="deepseek-flash", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
        cmd = [exe, "-p", AGENT_PROMPT, "--mcp-config", cfg, "--strict-mcp-config",
               "--allowedTools", "mcp__bench__word_count", "--output-format", "json", "--max-turns", "4"]
    else:
        codex_home = os.path.join(home, ".codex")
        os.makedirs(codex_home, exist_ok=True)
        with open(os.path.join(codex_home, "config.toml"), "w") as f:
            f.write(codex_config(f"http://127.0.0.1:{gw.port}", mcp))
        env.update(CODEX_HOME=codex_home, DEEPSEEK_API_KEY="offline-test-token")
        cmd = [exe, "exec", "--skip-git-repo-check", "--ephemeral", "-C", ws,
               "-o", os.path.join(run, "last_message.txt"), AGENT_PROMPT]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, env=env, cwd=ws, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=240)
        code, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        code, out, err = "timeout", e.stdout or "", e.stderr or ""
    took = time.time() - t0
    time.sleep(0.3)
    gw.stop()
    calls = gw.records()
    with open(os.path.join(run, "agent_stdout.txt"), "w") as f:
        f.write(str(out))
    with open(os.path.join(run, "agent_stderr.txt"), "w") as f:
        f.write(str(err))
    tools = []
    if os.path.exists(tool_log):
        with open(tool_log) as f:
            tools = [r for r in map(json.loads, f) if r["event"] == "tool_call"]
    answer = ""
    if which == "claude":
        try:
            answer = str(json.loads(out).get("result", ""))
        except ValueError:
            answer = ""
    elif os.path.exists(os.path.join(run, "last_message.txt")):
        with open(os.path.join(run, "last_message.txt")) as f:
            answer = f.read()
    model_calls = [r for r in calls if r["path"].split("?")[0].endswith(("/v1/messages", "/responses"))]
    streamed = [r for r in model_calls if (r["resp_content_type"] or "").startswith("text/event-stream")]
    agent_conns = sorted({r["conn"] for r in calls})
    up_conns = sorted({r["up_conn"] for r in calls if r["up_conn"]})
    per_conn = {c: len([r for r in calls if r["conn"] == c]) for c in agent_conns}
    sizes_ok = all(r["req_body_bytes"] == q["length"] for r, q in zip(
        [r for r in calls if r["req_framing"] != "none"], [q for q in fake.requests if q["method"] != "GET"]))
    agent_closes = [r for r in calls if r["error"] and r.get("error_side") == "agent"]
    errors = [r for r in calls if r["error"] and r.get("error_side") != "agent"]
    ok = (code == 0 and len(model_calls) >= 2 and streamed and len(tools) >= 1 and tools[0]["tool"] == "word_count"
          and tools[0]["args_bytes"] > 0 and re.findall(r"\d+", answer) == ["4"] and len(up_conns) == len(agent_conns)
          and sizes_ok and not errors)
    paths = sorted({f"{r['method']} {r['path'].split('?')[0]}" for r in calls})
    check(results, name, ok,
          f"exit {code} in {took:.0f} s; {len(calls)} calls through the gateway ({', '.join(paths)}), "
          f"{len(streamed)} streamed; {len(agent_conns)} agent connections, {len(up_conns)} upstream connections, "
          f"calls per agent connection {list(per_conn.values())}; logged request sizes equal the bytes the endpoint "
          f"received {sizes_ok}; tool calls logged {[(t['tool'], t['args_bytes']) for t in tools]}; "
          f"answer {(answer or '').strip()[-60:]!r}; calls the agent closed itself {len(agent_closes)}; other "
          f"errors {[r['error'] for r in errors]}")


def codex_config(base_url, mcp):
    env = ", ".join(f'{k} = "{v}"' for k, v in mcp["env"].items())
    return (f'model = "deepseek-flash"\n'
            f'model_provider = "deepseek"\n'
            f'approval_policy = "never"\n'
            f'sandbox_mode = "workspace-write"\n'
            f'web_search = "disabled"\n\n'
            f'[model_providers.deepseek]\n'
            f'name = "deepseek"\n'
            f'base_url = "{base_url}"\n'
            f'env_key = "DEEPSEEK_API_KEY"\n'
            f'wire_api = "responses"\n\n'
            f'[mcp_servers.bench]\n'
            f'command = "{mcp["command"]}"\n'
            f'args = {json.dumps(mcp["args"])}\n'
            f'env = {{ {env} }}\n'
            f'default_tools_approval_mode = "approve"\n')


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", action="store_true", help="also run the installed agent clients")
    ap.add_argument("--out", default=None, help="folder for logs and the JSON report")
    args = ap.parse_args(argv)
    workdir = args.out or tempfile.mkdtemp(prefix="ut_offline_")
    os.makedirs(workdir, exist_ok=True)
    results = []
    run_core(results, workdir)
    run_tls(results, workdir)
    run_mcp(results, workdir)
    if args.agents:
        run_agent(results, workdir, "claude")
        run_agent(results, workdir, "codex")
    with open(os.path.join(workdir, "offline_check.json"), "w") as f:
        json.dump(results, f, indent=1)
    failed = [r["check"] for r in results if r["passed"] is False]
    print(f"\nOFFLINE CHECK: {'PASS' if not failed else 'FAIL'}"
          + (f" (failed: {', '.join(failed)})" if failed else "") + f"; report {workdir}/offline_check.json")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
