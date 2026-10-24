"""Benign collection pilot (notebook 03): reading one pilot, and linking each run's gateway call log to its capture.

Layout written by harness/pilot.py under data/harness/pilot/<stamp>/ (git-ignored):
  pilot.json        one row per record: the planned runs plus any flagged first attempt (run_id ending __drop<k>,
                    flagged_drop true). Kept runs are the rows that are neither flagged nor stopped on an error.
  runs/<run_id>/    manifest.json, gw_calls.jsonl, labels.json, net.json, run.pcap, agent_tools.jsonl, tools.jsonl,
                    the agent's output and its workspace
  warmups/          the warm-up runs that made the template homes

Capture reading (read_capture_seq). Flows, client and server sides and destination names as in
ant_capture.read_capture. Bytes are TCP or UDP payload. For TCP every payload packet also records how many of its bytes
are new in the sequence space of its direction, so a resent segment adds nothing: up_bytes and down_bytes count each
sequence byte once; up_raw and down_raw count every captured segment, as the harness's bytes-per-host table does. A
UDP flow to port 53 keeps the names its queries ask for. A flow's host is its destination name, else its server
address; a flow to port 53 has host "dns <resolver address>".

Linking (link_run). The gateway logs the local and remote address of every upstream connection it opens (event
up_open, up_local and up_remote). The capture flow with that local port and that server address is that connection; a
logged connection that carries no logged call explains nothing. A TCP flow to the model host (by name, or without a
name to an address the gateway connected to) that is not a logged connection is an unlogged model-host connection. A logged call owns the upload sent on its
connection from its own start time to the start of the next call on the same connection; the first call also owns
everything before it (the TLS handshake) and the last everything after it (the closing alert), so the calls of a
connection own all of its upload. A DNS flow that asks only for the model host is the name lookup of the next
connection to the model host when that connection is a linked one and starts at most lookup_s seconds after the
lookup. Every other flow is traffic the call log does not explain.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import math
import os
import re
import struct

import dpkt
import numpy as np
import pandas as pd

from ant_capture import (LINKTYPES, TH_ACK, TH_SYN, _open, _orient, ip_text, is_private, network_layer,
                         parse_client_hello, parse_http_host)

REQUIRED_FILES = ("manifest.json", "gw_calls.jsonl", "labels.json", "net.json", "run.pcap", "agent_tools.jsonl")
MODEL_PATH_ENDS = ("/v1/messages", "/responses")      # harness/pilot.py is_model_path
RESEND_RE = re.compile(r"^\d+ upload bytes resent, above the tolerance of \d+ B$")   # harness/vm_gate.py wire_verdict
KEYLOG_RE = re.compile(rb"(CLIENT_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|"
                       rb"CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0|EXPORTER_SECRET) [0-9a-fA-F]{64} "
                       rb"[0-9a-fA-F]{32,}")
KEYLOG_NAMES = ("keylog", "sslkey")
SNIFF_BYTES = 16384
SCAN_MAX_BYTES = 64 << 20
MASK = 0xFFFFFFFF
FLOW_COLS = ["flow", "proto", "client_ip", "client_port", "server_ip", "server_port", "first_ts", "last_ts",
             "up_bytes", "down_bytes", "up_raw", "down_raw", "up_pkts", "down_pkts", "syn_seen", "sni", "http_host",
             "dns_name", "name", "server_private", "queries", "host"]
CALL_COLS = ["conn", "seq", "up_conn", "port", "remote", "t", "t_end", "method", "path", "model_call", "status", "error",
             "error_side", "up_new", "on_wire", "head", "body", "body_decoded", "resp_body", "logged", "n_rec",
             "last_on_conn", "flow", "wire"]


# ---------------------------------------------------------------- small readers

def read_json(path: str):
    with open(path) as f:
        return json.load(f)


def read_jsonl(path: str) -> list[dict]:
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def is_model_path(path) -> bool:
    return (path or "").split("?")[0].endswith(MODEL_PATH_ENDS)


def port_of(addr) -> int | None:
    if not addr or ":" not in str(addr):
        return None
    tail = str(addr).rsplit(":", 1)[1]
    return int(tail) if tail.isdigit() else None


def testbed_faults(wire_fails) -> list[str]:
    """The wire failure reasons that are faults of the testbed: every reason except upload resends (rule Q1r)."""
    return [w for w in (wire_fails or []) if not RESEND_RE.match(str(w))]


def scan_for_keylogs(root: str) -> tuple[list[str], list[str]]:
    """(hits, too_large): files under root whose name marks a TLS key log or that hold a key-log line, and files other
    than captures that are larger than SCAN_MAX_BYTES and so were not scanned (captures are never scanned)."""
    hits, too_large = [], []
    for base, _, files in os.walk(root):
        for name in files:
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root)
            if any(k in name.lower() for k in KEYLOG_NAMES):
                hits.append(rel)
                continue
            if name.endswith((".pcap", ".pcapng", ".parquet")):
                continue
            try:
                if os.path.getsize(path) > SCAN_MAX_BYTES:
                    too_large.append(rel)
                    continue
                with open(path, "rb") as f:
                    if KEYLOG_RE.search(f.read()):
                        hits.append(rel)
            except OSError as e:
                hits.append(f"{rel} (unreadable: {e})")
    return sorted(hits), sorted(too_large)


# ---------------------------------------------------------------- capture with sequence-aware byte counts

class _Seq:
    """Sequence bytes seen in one direction of a TCP flow, as sorted disjoint intervals relative to a base."""
    __slots__ = ("base", "lo", "hi")

    def __init__(self):
        self.base, self.lo, self.hi = None, [], []

    def add(self, seq: int, n: int) -> int:
        """Records the segment [seq, seq + n) and returns how many of its bytes were not seen before."""
        if self.base is None:
            self.base = seq
        a = (seq - self.base) & MASK
        if a >= 0x80000000:          # a segment just before the first one seen (reordering)
            a -= 0x100000000
        b = a + n
        i = bisect.bisect_left(self.hi, a)
        j, new, lo, hi = i, n, a, b
        while j < len(self.lo) and self.lo[j] <= b:
            new -= max(0, min(b, self.hi[j]) - max(a, self.lo[j]))
            lo, hi = min(lo, self.lo[j]), max(hi, self.hi[j])
            j += 1
        self.lo[i:j], self.hi[i:j] = [lo], [hi]
        return new


class _Flow:
    __slots__ = ("idx", "proto", "cip", "cport", "sip", "sport", "first", "last", "up_raw", "dn_raw", "up_new",
                 "dn_new", "up_p", "dn_p", "syn", "sq_up", "sq_dn", "segs", "seg_bytes", "collect", "queries",
                 "dns_start")

    def __init__(self, idx, proto, cip, cport, sip, sport, ts, dns_name):
        self.idx, self.proto, self.cip, self.cport, self.sip, self.sport = idx, proto, cip, cport, sip, sport
        self.first = self.last = ts
        self.up_raw = self.dn_raw = self.up_new = self.dn_new = self.up_p = self.dn_p = 0
        self.syn = False
        self.sq_up, self.sq_dn = _Seq(), _Seq()
        self.segs, self.seg_bytes, self.collect = {}, 0, proto == 6
        self.queries: list[str] = []
        self.dns_start = dns_name

    def client_stream(self) -> bytes:
        out = bytearray()
        for off in sorted(self.segs):
            if off > len(out):
                break
            data = self.segs[off]
            if off + len(data) > len(out):
                out += data[len(out) - off:]
        return bytes(out[:SNIFF_BYTES])


def _dns(data: bytes):
    try:
        return dpkt.dns.DNS(data)
    except (dpkt.UnpackError, IndexError, ValueError, struct.error, UnicodeDecodeError):
        return None


def read_capture_seq(path: str):
    """(packets, flows, info) for one capture. packets: one row per payload packet (ts, flow, up, plen, new)."""
    fh, rdr = _open(path)
    linktype = rdr.datalink()
    if linktype not in LINKTYPES:
        fh.close()
        raise ValueError(f"unsupported link type {linktype}")
    flows: dict[tuple, _Flow] = {}
    order: list[_Flow] = []
    dnsmap: dict[bytes, str] = {}
    rows_ts, rows_flow, rows_up, rows_len, rows_new = [], [], [], [], []
    n = dict(frames=0, ip=0, tcp=0, udp=0, other=0, bad=0)
    try:
        for ts, buf in rdr:
            n["frames"] += 1
            ts = float(ts)
            try:
                ip = network_layer(buf, linktype)
            except (dpkt.UnpackError, IndexError, ValueError, struct.error):
                n["bad"] += 1
                continue
            if ip is None:
                n["other"] += 1
                continue
            n["ip"] += 1
            if isinstance(ip, dpkt.ip.IP):
                if ip.offset:
                    n["other"] += 1
                    continue
                proto, l4, ip_payload = ip.p, ip.data, ip.len - ip.hl * 4
            else:
                proto, l4 = ip.p, ip.data
                try:
                    ext = sum(len(h) for h in getattr(ip, "all_extension_headers", []) or [])
                except TypeError:
                    ext = 0
                ip_payload = ip.plen - ext
            src, dst = ip.src, ip.dst
            if proto == 6 and isinstance(l4, dpkt.tcp.TCP):
                n["tcp"] += 1
                sport, dport, flags, seq = l4.sport, l4.dport, l4.flags, l4.seq
                plen = max(0, ip_payload - l4.off * 4)
                data = bytes(l4.data)
            elif proto == 17 and isinstance(l4, dpkt.udp.UDP):
                n["udp"] += 1
                sport, dport, flags, seq = l4.sport, l4.dport, 0, 0
                plen = max(0, (l4.ulen - 8) if l4.ulen else len(l4.data))
                data = bytes(l4.data)
            else:
                n["other"] += 1
                continue
            a, b = (src, sport), (dst, dport)
            key = (proto,) + (a + b if a <= b else b + a)
            fl = flows.get(key)
            if fl is None:
                if _orient(proto, src, sport, dst, dport, flags):
                    cip, cport, sip, sport_s = src, sport, dst, dport
                else:
                    cip, cport, sip, sport_s = dst, dport, src, sport
                fl = _Flow(len(order), proto, cip, cport, sip, sport_s, ts, dnsmap.get(sip))
                flows[key] = fl
                order.append(fl)
            fl.last = ts
            up = src == fl.cip and sport == fl.cport
            if proto == 6 and flags & TH_SYN:
                sq = fl.sq_up if up else fl.sq_dn
                if sq.base is None:
                    sq.base = (seq + 1) & MASK
                if up and not flags & TH_ACK:
                    fl.syn = True
            if proto == 17 and plen > 0 and data:
                if up and fl.sport == 53:
                    d = _dns(data)
                    if d is not None and d.qr == dpkt.dns.DNS_Q:
                        for q in d.qd:
                            name = q.name.lower().rstrip(".")
                            if name and name not in fl.queries:
                                fl.queries.append(name)
                elif not up and fl.sport == 53:
                    d = _dns(data)
                    if d is not None and d.qr == dpkt.dns.DNS_R and d.qd:
                        qname = d.qd[0].name.lower().rstrip(".")
                        for rr in d.an:
                            if rr.type == dpkt.dns.DNS_A and len(getattr(rr, "ip", b"")) == 4:
                                dnsmap[rr.ip] = qname
                            elif rr.type == dpkt.dns.DNS_AAAA and len(getattr(rr, "ip6", b"")) == 16:
                                dnsmap[rr.ip6] = qname
            if plen <= 0:
                continue
            if proto == 6:
                new = (fl.sq_up if up else fl.sq_dn).add(seq, plen)
                if up and fl.collect and data:
                    off = (seq - fl.sq_up.base) & MASK
                    if off < SNIFF_BYTES and off not in fl.segs:
                        fl.segs[off] = data
                        fl.seg_bytes += len(data)
                    if fl.seg_bytes >= SNIFF_BYTES or len(fl.segs) >= 48:
                        fl.collect = False
            else:
                new = plen
            if up:
                fl.up_raw += plen
                fl.up_new += new
                fl.up_p += 1
            else:
                fl.dn_raw += plen
                fl.dn_new += new
                fl.dn_p += 1
            rows_ts.append(ts)
            rows_flow.append(fl.idx)
            rows_up.append(1 if up else 0)
            rows_len.append(plen)
            rows_new.append(new)
    finally:
        fh.close()
    out = []
    for fl in order:
        sni = host = None
        if fl.proto == 6 and fl.segs:
            stream = fl.client_stream()
            if stream[:1] == b"\x16":
                sni, _ = parse_client_hello(stream)
            else:
                host = parse_http_host(stream)
        dns_name = fl.dns_start or dnsmap.get(fl.sip) or ""
        name = sni or host or dns_name or ""
        server = ip_text(fl.sip)
        if fl.sport == 53:
            label = f"dns {server}"
        elif name:
            label = name
        elif fl.proto == 6:
            label = server
        else:
            label = f"udp {server}:{fl.sport}"
        out.append(dict(flow=fl.idx, proto=fl.proto, client_ip=ip_text(fl.cip), client_port=fl.cport,
                        server_ip=server, server_port=fl.sport, first_ts=fl.first, last_ts=fl.last,
                        up_bytes=fl.up_new, down_bytes=fl.dn_new, up_raw=fl.up_raw, down_raw=fl.dn_raw,
                        up_pkts=fl.up_p, down_pkts=fl.dn_p, syn_seen=fl.syn, sni=sni or "", http_host=host or "",
                        dns_name=dns_name, name=name, server_private=is_private(fl.sip),
                        queries=",".join(fl.queries), host=label))
    F = pd.DataFrame(out, columns=FLOW_COLS)
    P = pd.DataFrame({"ts": np.asarray(rows_ts, dtype=float), "flow": np.asarray(rows_flow, dtype=np.int32),
                      "up": np.asarray(rows_up, dtype=np.int8), "plen": np.asarray(rows_len, dtype=np.int64),
                      "new": np.asarray(rows_new, dtype=np.int64)})
    info = dict(linktype=int(linktype), frames=n["frames"], ip_frames=n["ip"], tcp_frames=n["tcp"],
                udp_frames=n["udp"], other_frames=n["other"], bad_frames=n["bad"], flows=len(F),
                payload_packets=len(P), up_bytes=int(F.up_bytes.sum()), up_raw=int(F.up_raw.sum()),
                down_bytes=int(F.down_bytes.sum()), down_raw=int(F.down_raw.sum()))
    return P, F, info


# ---------------------------------------------------------------- linking the call log to the capture

def call_rows(events: list[dict]) -> pd.DataFrame:
    rows = []
    for e in events:
        if e.get("event") != "call":
            continue
        body = int(e.get("req_wire_body_bytes") or 0)
        head = int(e.get("req_head_bytes") or 0)
        # harness/pilot.py on_wire: an upstream connection existed and the request head was written; the head of a
        # request the gateway could not frame is logged but never sent
        on_wire = bool(e.get("up_local")) and e.get("req_framing") is not None
        rows.append(dict(conn=e.get("conn"), seq=e.get("seq"), up_conn=e.get("up_conn"), port=port_of(e.get("up_local")),
                         remote=e.get("up_remote"), t=e.get("t"), t_end=e.get("t_end"), method=e.get("method"),
                         path=(e.get("path") or "").split("?")[0], model_call=is_model_path(e.get("path")),
                         status=e.get("status"), error=e.get("error"), error_side=e.get("error_side"),
                         up_new=bool(e.get("up_new")), on_wire=on_wire, head=head, body=body,
                         body_decoded=int(e.get("req_body_bytes") or 0), resp_body=int(e.get("resp_body_bytes") or 0),
                         logged=head + body if on_wire else body, n_rec=math.ceil(body / 16384)))
    C = pd.DataFrame(rows, columns=CALL_COLS[:-3])
    return C


def link_run(events: list[dict], P: pd.DataFrame, F: pd.DataFrame, model_host: str, lookup_s: float):
    """Calls with the upload each owns on its connection, flows with their record class, and the link facts."""
    C = call_rows(events)
    opens = {e.get("up_conn"): (port_of(e.get("up_local")), e.get("t"), e.get("up_remote"))
             for e in events if e.get("event") == "up_open"}
    for up_conn in C.up_conn.dropna().unique():
        if up_conn not in opens:
            c = C[C.up_conn == up_conn].iloc[0]
            opens[up_conn] = (c.port, c.t, c.remote)
    F = F.copy()
    F["record"] = "none"
    F["up_conn"] = -1
    flow_of, missing, model_addrs = {}, [], set()
    tcp = F[F.proto == 6]
    for up_conn, (port, t0, remote) in sorted(opens.items(), key=lambda kv: kv[0]):
        cand = tcp[tcp.client_port == port] if port is not None else tcp.iloc[0:0]
        if remote and ":" in str(remote) and str(remote).rsplit(":", 1)[1].isdigit():
            rip, rport = str(remote).rsplit(":", 1)
            model_addrs.add(rip)
            cand = cand[(cand.server_ip == rip) & (cand.server_port == int(rport))]
        if cand.empty:
            missing.append(int(up_conn))
            continue
        inside = cand[(cand.first_ts - 2.0 <= t0) & (t0 <= cand.last_ts + 2.0)]
        pick = inside if not inside.empty else cand
        fid = int(pick.iloc[(pick.first_ts - t0).abs().argmin()].flow)
        flow_of[up_conn] = fid
        F.loc[F.flow == fid, "record"] = "call"
        F.loc[F.flow == fid, "up_conn"] = int(up_conn)
    C["last_on_conn"] = False
    C["flow"] = -1
    C["wire"] = 0
    up_pk = P[P.up == 1]
    for up_conn, g in C.groupby("up_conn"):
        g = g.sort_values(["t", "seq"])
        C.loc[g.index[-1], "last_on_conn"] = True
        fid = flow_of.get(up_conn)
        if fid is None:
            continue
        pk = up_pk[up_pk.flow == fid]
        owner = np.searchsorted(g.t.to_numpy(dtype=float)[1:], pk.ts.to_numpy(), side="right")
        wire = np.bincount(owner, weights=pk.new.to_numpy(dtype=float), minlength=len(g))
        C.loc[g.index, "flow"] = fid
        C.loc[g.index, "wire"] = wire.astype(np.int64)
    # a logged connection that carries no logged call (a gateway stopped in the middle of one) explains nothing
    no_call = [u for u in flow_of if u not in set(C.up_conn.dropna())]
    for u in no_call:
        F.loc[F.flow == flow_of[u], ["record", "up_conn"]] = ["none", -1]
    # by name, or nameless to an address the gateway connected to (a server address can be shared by other names)
    F["to_model"] = (F.proto == 6) & ((F.host == model_host) | (F.server_ip.isin(model_addrs) & (F.name == ""))
                                      | (F.record == "call"))
    linked = F[F.record == "call"]
    model = model_host.lower()
    to_model = F[F.to_model].sort_values("first_ts")
    starts, is_linked = to_model.first_ts.to_numpy(), (to_model.record == "call").to_numpy()
    for i, f in F[(F.proto == 17) & (F.server_port == 53)].iterrows():
        names = [q for q in f.queries.split(",") if q]
        if not names or any(q != model for q in names):
            continue
        k = np.searchsorted(starts, f.first_ts, side="left")
        if k < len(starts) and is_linked[k] and starts[k] <= f.first_ts + lookup_s:
            F.loc[i, "record"] = "lookup"
    facts = dict(up_conns=len(opens), missing_links=missing, wrong_server_name=int((linked.sni != model_host).sum()),
                 conns_without_call=len(no_call), short_calls=int(((C.flow >= 0) & (C.wire < C.logged)).sum()),
                 unlinked_model_flows=int(((F.record == "none") & F.to_model).sum()),
                 calls_without_upstream=int(C.port.isna().sum()))
    return C, F, facts


# ---------------------------------------------------------------- one pilot

def labels_facts(labels: dict, C: pd.DataFrame) -> dict:
    """Whether the run's labels hold (labels.json ok, agreement 1.0 over model calls) and name the same request
    sizes as the call log."""
    if not labels:
        return dict(labels_file_ok=False, labels_match_log=False)
    pairs = [p for p in labels.get("pairs", []) if p.get("model")]
    logged = {(c.conn, c.seq): c.body_decoded for c in C.itertuples()}
    match = all(logged.get((p.get("conn"), p.get("seq"))) == p.get("logged") for p in pairs)
    ok = labels.get("ok") is True and labels.get("agreement") == 1.0 and labels.get("model_pairs") == labels.get(
        "model_agree")
    return dict(labels_file_ok=bool(ok), labels_match_log=bool(match), label_model_pairs=len(pairs))


def load_pilot(root: str, model_host: str, lookup_s: float):
    """Every record of one pilot: (runs, calls, flows, packets). Records whose folder lacks a required file are kept
    in runs with the missing files named and are not parsed."""
    pilot = read_json(os.path.join(root, "pilot.json"))
    runs, calls, flows, packets = [], [], [], []
    for row in pilot["runs"]:
        rid = row["run_id"]
        d = os.path.join(root, "runs", rid)
        missing = [f for f in REQUIRED_FILES if not os.path.exists(os.path.join(d, f))]
        r = dict(run_id=rid, agent=row.get("agent"), task=row.get("task"), scenario=row.get("scenario"),
                 repeat=row.get("repeat"), flagged_drop=bool(row.get("flagged_drop")), error=bool(row.get("error")),
                 seconds=row.get("seconds"), completed=row.get("completed"), model_calls=row.get("model_calls"),
                 labels_ok=row.get("labels_ok"), wire_clean=row.get("wire_clean"),
                 mcp_tool_calls=row.get("mcp_tool_calls"), builtin_tool_calls=row.get("builtin_tool_calls"),
                 files_missing=";".join(missing))
        r["kept"] = not r["flagged_drop"] and not r["error"]
        if missing:
            runs.append(r)
            continue
        m = read_json(os.path.join(d, "manifest.json"))
        net = read_json(os.path.join(d, "net.json"))
        labels = read_json(os.path.join(d, "labels.json"))
        events = read_jsonl(os.path.join(d, "gw_calls.jsonl"))
        P, F, info = read_capture_seq(os.path.join(d, "run.pcap"))
        C, F, facts = link_run(events, P, F, model_host, lookup_s)
        fails = m.get("wire_fails") or []
        caps = net.get("captures") or [{}]
        r.update(version=m.get("version"), manifest_complete=bool(m.get("complete")),
                 manifest_agrees=bool(m.get("agent") == r["agent"] and m.get("task") == r["task"]
                                      and m.get("repeat") == r["repeat"] and m.get("model_calls") == r["model_calls"]),
                 logged_model_calls=int(C.model_call.sum()), wire_verdict=m.get("wire_verdict"),
                 wire_fails=" | ".join(map(str, fails)), testbed_faults=" | ".join(testbed_faults(fails)),
                 resend_fail=any(RESEND_RE.match(str(w)) for w in fails),
                 capture_complete=all(bool(c.get("complete")) for c in caps),
                 capture_dropped=sum(int(c.get("dropped_kernel") or 0) for c in caps),
                 calls=len(C), up_conns=facts["up_conns"], missing_links=len(facts["missing_links"]),
                 wrong_server_name=facts["wrong_server_name"], conns_without_call=facts["conns_without_call"],
                 short_calls=facts["short_calls"],
                 unlinked_model_flows=facts["unlinked_model_flows"],
                 calls_without_upstream=facts["calls_without_upstream"], flows=len(F),
                 up_bytes=info["up_bytes"], up_raw=info["up_raw"], down_bytes=info["down_bytes"],
                 down_raw=info["down_raw"], **labels_facts(labels, C))
        runs.append(r)
        calls.append(C.assign(run_id=rid))
        flows.append(F.assign(run_id=rid))
        packets.append(P.assign(run_id=rid))
    R = pd.DataFrame(runs)
    cat = lambda xs, cols: pd.concat(xs, ignore_index=True) if xs else pd.DataFrame(columns=cols + ["run_id"])
    return R, cat(calls, CALL_COLS), cat(flows, FLOW_COLS + ["record", "up_conn", "to_model"]), cat(packets, ["ts", "flow", "up",
                                                                                                    "plen", "new"])


def record_split(R: pd.DataFrame, F: pd.DataFrame) -> pd.DataFrame:
    """Per run: upload and flows the call log explains (logged connections and their name lookups) and the rest."""
    g = F.assign(rec=F.record != "none")
    up = g.pivot_table(index="run_id", columns="rec", values="up_bytes", aggfunc="sum", fill_value=0)
    nf = g.pivot_table(index="run_id", columns="rec", values="flow", aggfunc="count", fill_value=0)
    out = pd.DataFrame(index=R.run_id)
    out["up_total"] = up.sum(1).reindex(out.index).fillna(0)
    out["up_record"] = up.get(True, pd.Series(dtype=float)).reindex(out.index).fillna(0)
    out["up_other"] = out.up_total - out.up_record
    out["flows_total"] = nf.sum(1).reindex(out.index).fillna(0)
    out["flows_record"] = nf.get(True, pd.Series(dtype=float)).reindex(out.index).fillna(0)
    out["flows_other"] = out.flows_total - out.flows_record
    return out.reset_index()


def load_pilot_cached(root: str, model_host: str, lookup_s: float, cache_dir: str):
    """load_pilot, kept on disk in cache_dir with the sizes of the files it read and a digest of the reader's code;
    parsed again when any of them, the model host or the lookup window changes."""
    import ant_capture
    pilot = read_json(os.path.join(root, "pilot.json"))
    code = [hashlib.sha256(open(p, "rb").read()).hexdigest() for p in (__file__, ant_capture.__file__)]
    sig = [model_host, lookup_s, code]
    for row in pilot["runs"]:
        d = os.path.join(root, "runs", row["run_id"])
        sig.append([row["run_id"]] + [os.path.getsize(os.path.join(d, f)) if os.path.exists(os.path.join(d, f)) else None
                                      for f in REQUIRED_FILES])
    sig.append(os.path.getsize(os.path.join(root, "pilot.json")))
    digest = hashlib.sha256(json.dumps(sig).encode()).hexdigest()
    names = ("runs", "calls", "flows", "packets")
    paths = {n: os.path.join(cache_dir, f"{n}.parquet") for n in names}
    sig_path = os.path.join(cache_dir, "signature.json")
    if all(os.path.exists(p) for p in paths.values()) and os.path.exists(sig_path):
        if read_json(sig_path).get("digest") == digest:
            return tuple(pd.read_parquet(paths[n]) for n in names) + (True,)
    out = load_pilot(root, model_host, lookup_s)
    os.makedirs(cache_dir, exist_ok=True)
    for n, df in zip(names, out):
        df.to_parquet(paths[n], index=False)
    with open(sig_path, "w") as f:
        json.dump(dict(digest=digest, records=len(pilot["runs"])), f)
    return out + (False,)


def agent_names(R: pd.DataFrame) -> dict:
    """Paper names of the agents, with the version their manifests name."""
    base = {"claude": "Claude Code", "codex": "Codex"}
    out = {}
    for agent, g in R.groupby("agent"):
        versions = sorted(set(g.version.dropna()))
        out[agent] = f"{base.get(agent, agent)} {'/'.join(versions)}".strip()
    return out


def host_table(F: pd.DataFrame, R: pd.DataFrame) -> pd.DataFrame:
    """Per agent and destination host of traffic the call log does not explain (kept runs): runs that reach it,
    connections, and upload and download per run over the runs that reach it (bytes counted once)."""
    other = F[(F.record == "none") & F.run_id.isin(R.run_id[R.kept])]
    per = other.groupby(["run_id", "host"]).agg(conns=("flow", "count"), up=("up_bytes", "sum"),
                                                 down=("down_bytes", "sum")).reset_index()
    per["agent"] = per.run_id.map(R.set_index("run_id").agent)
    n = R[R.kept].groupby("agent").size()
    t = per.groupby(["agent", "host"]).agg(runs=("run_id", "nunique"), conns=("conns", "sum"),
                                           up_median=("up", "median"), up_min=("up", "min"), up_max=("up", "max"),
                                           down_median=("down", "median"), down_max=("down", "max")).reset_index()
    t["run_share"] = t.runs / t.agent.map(n)
    return t.sort_values(["agent", "up_median"], ascending=[True, False]).reset_index(drop=True)


def background_downloads(F: pd.DataFrame, R: pd.DataFrame) -> pd.DataFrame:
    """Per record (flagged first attempts included) and host of traffic the call log does not explain: download and
    upload, counted per captured segment (raw, as the harness's Q3 rule counts) and once per sequence byte."""
    other = F[F.record == "none"]
    g = other.groupby(["run_id", "host"]).agg(conns=("flow", "count"), down_raw=("down_raw", "sum"),
                                               down=("down_bytes", "sum"), up_raw=("up_raw", "sum"),
                                               up=("up_bytes", "sum")).reset_index()
    return g.merge(R[["run_id", "agent", "kept", "flagged_drop"]], on="run_id", how="left")
