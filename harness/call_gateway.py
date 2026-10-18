"""Per-call size gateway between one agent and its model endpoint.

The agent is configured to call this gateway instead of the model endpoint. For every HTTP request the gateway
writes one JSON line with the exact request body length and the exact response body length, and forwards the request
unchanged apart from the Host header and the upstream path prefix. Response bytes go back to the agent as soon as they
are read from the endpoint, piece by piece, with no buffering of the body.

Connection behaviour follows the agent's own connections:
  - one upstream connection per agent connection, opened on the agent's first request and reused for its later ones;
  - the upstream connection is closed when the agent closes its connection;
  - if the endpoint closes the upstream connection (with Connection: close, or while it is idle between calls), the
    next request on that agent connection opens a new one, as the agent would itself, and the log marks it (up_new
    true on a call that is not the first of its agent connection).

TLS session keys of the upstream connections go to the key log named by --keylog, or by SSLKEYLOGFILE, for
ground-truth labelling of the capture only. Bodies and header values are never logged.

Log lines (one JSON object per line, times are Unix epoch seconds):
  event=up_open   upstream connection opened (up_conn, conn, up_local, up_remote, t)
  event=up_close  upstream connection closed (up_conn, conn, reason, t)
  event=call      one request and its response (sizes, framing, status, times, ids)

Standard library only.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
import ssl
import sys
import time
from urllib.parse import urlsplit

HEAD_LIMIT = 1 << 20          # longest accepted header block
PIECE = 1 << 16               # largest single read when relaying a body
MODEL_SCAN = 4096             # the model name is read from the first bytes of a JSON body only
MODEL_RE = re.compile(rb'"model"\s*:\s*"([^"\\]{1,120})"')
NO_BODY_STATUS = {204, 304}


class Log:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.f = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, rec: dict) -> None:
        self.f.write(json.dumps(rec, separators=(",", ":")) + "\n")
        self.f.flush()

    def close(self) -> None:
        self.f.close()


class Head:
    """A parsed header block that keeps the raw header lines so they can be forwarded as received."""

    def __init__(self, raw: bytes):
        lines = raw.split(b"\r\n")
        while lines and lines[0] == b"":
            lines.pop(0)
        if not lines:
            raise ValueError("empty header block")
        self.start = lines[0].decode("latin-1")
        self.lines = [ln for ln in lines[1:] if ln != b""]
        self.fields = []
        for ln in self.lines:
            name, sep, value = ln.partition(b":")
            if not sep or not name or name != name.strip():
                raise ValueError(f"bad header line: {ln[:80]!r}")
            self.fields.append((name.decode("latin-1").lower(), value.decode("latin-1").strip()))

    def get(self, name: str) -> str | None:
        for k, v in self.fields:
            if k == name:
                return v
        return None

    def tokens(self, name: str) -> list[str]:
        out = []
        for k, v in self.fields:
            if k == name:
                out += [t.strip().lower() for t in v.split(",") if t.strip()]
        return out

    def size(self) -> int:
        return len(self.start.encode("latin-1")) + 2 + sum(len(ln) + 2 for ln in self.lines) + 2

    def encode(self, start: str, replace: dict[str, str] | None = None, drop: set[str] | None = None) -> bytes:
        """Header block with a new start line; lines named in replace get the new value, lines in drop are removed,
        every other line is kept byte for byte."""
        replace = dict(replace or {})
        drop = drop or set()
        out = [start.encode("latin-1")]
        for ln, (k, _) in zip(self.lines, self.fields):
            if k in drop:
                continue
            if k in replace:
                out.append(ln.partition(b":")[0] + b": " + replace.pop(k).encode("latin-1"))
            else:
                out.append(ln)
        for k, v in replace.items():
            out.append(k.title().encode("latin-1") + b": " + v.encode("latin-1"))
        return b"\r\n".join(out) + b"\r\n\r\n"


def framing(head: Head, is_request: bool, method: str = "", status: int = 0) -> tuple[str, int]:
    if not is_request and (method == "HEAD" or status in NO_BODY_STATUS or 100 <= status < 200):
        return "none", 0
    if "chunked" in head.tokens("transfer-encoding"):
        return "chunked", 0
    cl = head.get("content-length")
    if cl is not None:
        n = int(cl)
        if n < 0:
            raise ValueError("negative content-length")
        return "length", n
    return ("none", 0) if is_request else ("eof", 0)


class Relay:
    """Copies one body from reader to writer as it arrives and counts its bytes."""

    def __init__(self, idle: float, on_piece=None):
        self.idle = idle
        self.on_piece = on_piece
        self.body = 0          # payload bytes after removing chunk framing
        self.wire = 0          # bytes as framed on the connection
        self.pieces = 0
        self.t_first = None

    async def _read(self, reader, n):
        data = await asyncio.wait_for(reader.read(n), self.idle)
        if data and self.t_first is None:
            self.t_first = time.time()
        return data

    async def _line(self, reader):
        data = await asyncio.wait_for(reader.readuntil(b"\r\n"), self.idle)
        if self.t_first is None:
            self.t_first = time.time()
        return data

    async def _payload(self, reader, writer, remaining):
        while remaining:
            data = await self._read(reader, min(remaining, PIECE))
            if not data:
                raise ConnectionError("connection closed inside a body")
            writer.write(data)
            await writer.drain()
            remaining -= len(data)
            self.body += len(data)
            self.wire += len(data)
            self.pieces += 1
            if self.on_piece:
                self.on_piece(data)

    async def run(self, kind: str, length: int, reader, writer) -> None:
        if kind == "none":
            return
        if kind == "length":
            await self._payload(reader, writer, length)
            return
        if kind == "eof":
            while True:
                data = await self._read(reader, PIECE)
                if not data:
                    return
                writer.write(data)
                await writer.drain()
                self.body += len(data)
                self.wire += len(data)
                self.pieces += 1
                if self.on_piece:
                    self.on_piece(data)
        # chunked: every chunk is forwarded with its framing, and the chunk terminator is flushed before the next read
        while True:
            line = await self._line(reader)
            writer.write(line)
            self.wire += len(line)
            size = int(line.split(b";", 1)[0].strip(), 16)
            if size == 0:
                while True:
                    trailer = await self._line(reader)
                    writer.write(trailer)
                    self.wire += len(trailer)
                    if trailer == b"\r\n":
                        await writer.drain()
                        return
            await self._payload(reader, writer, size)
            crlf = await asyncio.wait_for(reader.readexactly(2), self.idle)
            if crlf != b"\r\n":
                raise ValueError("bad chunk terminator")
            writer.write(crlf)
            await writer.drain()
            self.wire += 2


class Upstream:
    def __init__(self, url: str, keylog: str | None, cafile: str | None, connect_timeout: float):
        u = urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise SystemExit(f"bad upstream url: {url}")
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        default_port = 443 if u.scheme == "https" else 80
        self.host_header = self.host if self.port == default_port else f"{self.host}:{self.port}"
        self.prefix = u.path.rstrip("/")
        self.connect_timeout = connect_timeout
        self.tls = None
        if u.scheme == "https":
            ctx = ssl.create_default_context(cafile=cafile)
            ctx.set_alpn_protocols(["http/1.1"])
            keylog = keylog or os.environ.get("SSLKEYLOGFILE")
            if keylog:
                os.makedirs(os.path.dirname(os.path.abspath(keylog)), exist_ok=True)
                ctx.keylog_filename = keylog
            self.tls = ctx

    async def open(self):
        return await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, ssl=self.tls,
                                    server_hostname=self.host if self.tls else None, limit=HEAD_LIMIT),
            self.connect_timeout)

    def target(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            u = urlsplit(target)
            target = (u.path or "/") + (f"?{u.query}" if u.query else "")
        if target == "*":
            return target
        return self.prefix + target


def peer(writer, which: str) -> str | None:
    info = writer.get_extra_info(which)
    return f"{info[0]}:{info[1]}" if info else None


class Gateway:
    def __init__(self, upstream: Upstream, log: Log, idle: float):
        self.up = upstream
        self.log = log
        self.idle = idle
        self.next_conn = 0
        self.next_up = 0
        self.tasks: set[asyncio.Task] = set()

    async def handle(self, d_reader, d_writer):
        self.next_conn += 1
        conn = self.next_conn
        task = asyncio.current_task()
        self.tasks.add(task)
        up = None   # (reader, writer, up_conn_id)
        seq = 0
        try:
            while True:
                try:
                    raw = await d_reader.readuntil(b"\r\n\r\n")
                except asyncio.IncompleteReadError as e:
                    if e.partial.strip():
                        raise
                    return
                except (ConnectionError, asyncio.LimitOverrunError):
                    return
                if not raw.strip():
                    continue
                seq += 1
                up, keep = await self.call(conn, seq, Head(raw), d_reader, d_writer, up)
                if not keep:
                    return
        except Exception as e:
            self.log.write(dict(event="error", conn=conn, t=time.time(), error=f"{type(e).__name__}: {e}"))
        finally:
            if up is not None:
                self.close_up(up, conn, "agent connection closed")
            d_writer.close()
            self.tasks.discard(task)

    def close_up(self, up, conn, reason):
        up[1].close()
        self.log.write(dict(event="up_close", conn=conn, up_conn=up[2], reason=reason, t=time.time()))

    async def call(self, conn, seq, req: Head, d_reader, d_writer, up):
        t0 = time.time()
        method, target, version = req.start.split(" ", 2)
        rec = dict(event="call", conn=conn, seq=seq, t=t0, method=method, path=target, model=None, up_conn=None,
                   up_new=False, up_local=None, up_remote=None, req_framing=None, req_body_bytes=0,
                   req_wire_body_bytes=0, req_head_bytes=req.size(), req_sha256=None,
                   req_content_type=req.get("content-type"), req_content_encoding=req.get("content-encoding"),
                   expect_continue=False, status=None, resp_framing=None, resp_body_bytes=0,
                   resp_wire_body_bytes=0, resp_head_bytes=0, resp_pieces=0,
                   resp_content_type=None, resp_content_encoding=None, upgrade=False,
                   t_req_end=None, t_resp_head=None, t_first_byte=None, t_end=None, error=None)
        client_close = "close" in req.tokens("connection") or (version == "HTTP/1.0"
                                                               and "keep-alive" not in req.tokens("connection"))
        if up is not None and (up[0].at_eof() or up[1].is_closing()):
            self.close_up(up, conn, "upstream closed while idle")
            up = None
        try:
            if up is None:
                r, w = await self.up.open()
                self.next_up += 1
                up = (r, w, self.next_up)
                rec["up_new"] = True
                self.log.write(dict(event="up_open", conn=conn, up_conn=self.next_up, t=time.time(),
                                    up_local=peer(w, "sockname"), up_remote=peer(w, "peername")))
        except Exception as e:
            rec["error"] = f"upstream connect failed: {type(e).__name__}: {e}"
            rec["t_end"] = time.time()
            self.log.write(rec)
            body = json.dumps({"error": rec["error"]}).encode()
            d_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: "
                           + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await d_writer.drain()
            return None, False
        u_reader, u_writer, up_id = up
        rec.update(up_conn=up_id, up_local=peer(u_writer, "sockname"), up_remote=peer(u_writer, "peername"))
        sha = hashlib.sha256()
        scan = bytearray()

        def seen(piece):
            sha.update(piece)
            if len(scan) < MODEL_SCAN:
                scan.extend(piece[:MODEL_SCAN - len(scan)])

        keep_up = True
        try:
            kind, length = framing(req, True)
            rec["req_framing"] = kind
            drop = set()
            if "100-continue" in req.tokens("expect"):
                # the gateway answers 100 Continue itself so the agent sends its body at once
                rec["expect_continue"] = True
                drop.add("expect")
                d_writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                await d_writer.drain()
            u_writer.write(req.encode(f"{method} {self.up.target(target)} {version}",
                                      replace={"host": self.up.host_header}, drop=drop))
            sent = Relay(self.idle, seen)
            await sent.run(kind, length, d_reader, u_writer)
            await u_writer.drain()
            rec.update(req_body_bytes=sent.body, req_wire_body_bytes=sent.wire, t_req_end=time.time())
            if kind != "none":
                rec["req_sha256"] = sha.hexdigest()
                m = MODEL_RE.search(bytes(scan))
                rec["model"] = m.group(1).decode("utf-8", "replace") if m else None

            while True:
                raw = await asyncio.wait_for(u_reader.readuntil(b"\r\n\r\n"), self.idle)
                resp = Head(raw)
                status = int(resp.start.split(" ", 2)[1])
                rec["resp_head_bytes"] += resp.size()
                d_writer.write(raw)
                await d_writer.drain()
                if 100 <= status < 200 and status != 101:
                    continue
                break
            rec.update(status=status, t_resp_head=time.time(), resp_content_type=resp.get("content-type"),
                       resp_content_encoding=resp.get("content-encoding"))

            if status == 101:
                rec["upgrade"] = True
                up_bytes, down_bytes = await self.tunnel(d_reader, d_writer, u_reader, u_writer)
                rec.update(req_wire_body_bytes=rec["req_wire_body_bytes"] + up_bytes,
                           resp_body_bytes=down_bytes, resp_wire_body_bytes=down_bytes, resp_framing="tunnel",
                           t_end=time.time())
                self.log.write(rec)
                self.close_up(up, conn, "tunnel ended")
                return None, False

            r_kind, r_len = framing(resp, False, method, status)
            rec["resp_framing"] = r_kind
            got = Relay(self.idle)
            await got.run(r_kind, r_len, u_reader, d_writer)
            rec.update(resp_body_bytes=got.body, resp_wire_body_bytes=got.wire, resp_pieces=got.pieces,
                       t_first_byte=got.t_first, t_end=time.time())
            if r_kind == "eof" or "close" in resp.tokens("connection"):
                keep_up = False
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {e}"
            rec["t_end"] = time.time()
            self.log.write(rec)
            self.close_up(up, conn, "error during call")
            return None, False

        self.log.write(rec)
        if r_kind == "eof":
            self.close_up(up, conn, "response ended by upstream close")
            return None, False
        if client_close:
            self.close_up(up, conn, "agent asked to close")
            return None, False
        if not keep_up:
            self.close_up(up, conn, "upstream asked to close")
            return None, True
        return up, True

    async def tunnel(self, d_reader, d_writer, u_reader, u_writer):
        async def pipe(src, dst):
            n = 0
            while True:
                data = await src.read(PIECE)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
                n += len(data)
            dst.close()
            return n
        a, b = await asyncio.gather(pipe(d_reader, u_writer), pipe(u_reader, d_writer), return_exceptions=True)
        return (a if isinstance(a, int) else 0), (b if isinstance(b, int) else 0)


async def serve(args):
    host, _, port = args.listen.rpartition(":")
    log = Log(args.log)
    gw = Gateway(Upstream(args.upstream, args.keylog, args.cafile, args.connect_timeout), log, args.idle_timeout)
    server = await asyncio.start_server(gw.handle, host or "127.0.0.1", int(port), limit=HEAD_LIMIT)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    print(f"call_gateway listening on {args.listen} -> {args.upstream}", file=sys.stderr, flush=True)
    async with server:
        await stop.wait()
        server.close()
        for task in list(gw.tasks):
            task.cancel()
        await asyncio.gather(*gw.tasks, return_exceptions=True)
    log.close()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--listen", default="127.0.0.1:8081", help="host:port the agent calls")
    p.add_argument("--upstream", required=True, help="model endpoint base URL, e.g. https://api.deepseek.com/anthropic")
    p.add_argument("--log", required=True, help="JSON-lines call log")
    p.add_argument("--keylog", default=None, help="TLS key log for ground-truth labelling (default: SSLKEYLOGFILE)")
    p.add_argument("--cafile", default=None, help="CA bundle trusted instead of the system store (tests only)")
    p.add_argument("--connect-timeout", type=float, default=30.0)
    p.add_argument("--idle-timeout", type=float, default=900.0, help="longest silence inside one call")
    asyncio.run(serve(p.parse_args(argv)))


if __name__ == "__main__":
    main()
