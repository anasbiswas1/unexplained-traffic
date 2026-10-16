"""Capture reading for ANT (notebook 01).

Reads one packet capture (pcap or pcapng) and returns two tables and a summary:

  packets  one row per packet that carries transport payload: ts, flow, up (1 = client to server), plen
  flows    one row per bidirectional transport flow: endpoints, protocol, first and last time, payload bytes and
           packets each way, and the destination name (TLS server name, else HTTP Host, else the name that a DNS
           answer in the same capture gave for the server address)

Only metadata is kept. Payload bytes are read only to recover destination names: the first 16 KB a client sends on a
TCP flow (TLS ClientHello server name and ALPN, or an HTTP Host header) and DNS answers. Payload lengths come from the
IP and transport length fields, so Ethernet padding and short snap lengths do not change byte counts.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
from array import array

import dpkt
import numpy as np
import pandas as pd

LINKTYPES = {0: "null", 1: "ethernet", 12: "raw", 14: "raw", 101: "raw", 108: "loop", 113: "sll", 228: "ipv4",
             229: "ipv6", 276: "sll2"}
SERVER_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3128, 3306, 5432, 6379, 8080,
                8443, 9418, 27017}
CLIENT_SNIFF_BYTES = 16384
CLIENT_SNIFF_SEGMENTS = 48
TH_SYN, TH_ACK = 0x02, 0x10

_PRIVATE_CACHE: dict[bytes, bool] = {}


def ip_text(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET if len(raw) == 4 else socket.AF_INET6, raw)


def is_private(raw: bytes) -> bool:
    v = _PRIVATE_CACHE.get(raw)
    if v is None:
        a = ipaddress.ip_address(raw)
        v = bool(a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)
        _PRIVATE_CACHE[raw] = v
    return v


def _ip_from_bytes(b: bytes):
    if not b:
        return None
    ver = b[0] >> 4
    if ver == 4:
        return dpkt.ip.IP(b)
    if ver == 6:
        return dpkt.ip6.IP6(b)
    return None


def network_layer(buf: bytes, linktype: int):
    """The IPv4 or IPv6 object inside one frame, or None."""
    kind = LINKTYPES.get(linktype)
    if kind == "ethernet":
        eth = dpkt.ethernet.Ethernet(buf)
        d = eth.data
        return d if isinstance(d, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if kind == "sll":
        return _ip_from_bytes(buf[16:]) if len(buf) > 16 else None
    if kind == "sll2":
        return _ip_from_bytes(buf[20:]) if len(buf) > 20 else None
    if kind in ("null", "loop"):
        return _ip_from_bytes(buf[4:]) if len(buf) > 4 else None
    if kind in ("raw", "ipv4", "ipv6"):
        return _ip_from_bytes(buf)
    raise ValueError(f"unsupported link type {linktype}")


def _u16(b: bytes, i: int) -> int:
    return (b[i] << 8) | b[i + 1]


def parse_client_hello(stream: bytes):
    """(server_name, alpn) from the start of a client TLS stream, or (None, None)."""
    hs = b""
    i = 0
    while i + 5 <= len(stream):
        if stream[i] != 22:
            break
        rlen = _u16(stream, i + 3)
        hs += stream[i + 5:i + 5 + rlen]
        i += 5 + rlen
        if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
            break
    if len(hs) < 4 or hs[0] != 1:
        return None, None
    body = hs[4:4 + int.from_bytes(hs[1:4], "big")]
    sni = alpn = None
    try:
        p = 34
        p += 1 + body[p]
        p += 2 + _u16(body, p)
        p += 1 + body[p]
        if p + 2 > len(body):
            return None, None
        end = min(len(body), p + 2 + _u16(body, p))
        p += 2
        while p + 4 <= end:
            et, el = _u16(body, p), _u16(body, p + 2)
            ed = body[p + 4:p + 4 + el]
            p += 4 + el
            if et == 0 and len(ed) >= 2:
                q = 2
                while q + 3 <= len(ed):
                    nt, nl = ed[q], _u16(ed, q + 1)
                    name = ed[q + 3:q + 3 + nl]
                    q += 3 + nl
                    if nt == 0 and name:
                        sni = name.decode("ascii", "ignore").strip().lower().rstrip(".")
                        break
            elif et == 16 and len(ed) >= 2:
                q, protos = 2, []
                while q < len(ed):
                    ln = ed[q]
                    protos.append(ed[q + 1:q + 1 + ln].decode("ascii", "ignore"))
                    q += 1 + ln
                alpn = ",".join(x for x in protos if x) or None
    except IndexError:
        pass
    return sni, alpn


_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ", b"CONNECT ")


def parse_http_host(stream: bytes):
    if not stream.startswith(_HTTP_METHODS):
        return None
    head = stream.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if line[:5].lower() == b"host:":
            host = line[5:].strip().decode("ascii", "ignore").lower()
            if host.startswith("["):
                return host[1:host.find("]")] if "]" in host else host
            return host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return None


class _Flow:
    __slots__ = ("idx", "proto", "cip", "cport", "sip", "sport", "first", "last", "up_b", "dn_b", "up_p", "dn_p",
                 "syn", "base", "segs", "seg_bytes", "collect", "dns_start")

    def __init__(self, idx, proto, cip, cport, sip, sport, ts, syn, isn, dns_name):
        self.idx, self.proto = idx, proto
        self.cip, self.cport, self.sip, self.sport = cip, cport, sip, sport
        self.first = self.last = ts
        self.up_b = self.dn_b = self.up_p = self.dn_p = 0
        self.syn = syn
        self.base = ((isn + 1) & 0xFFFFFFFF) if syn else None
        self.segs = {}
        self.seg_bytes = 0
        self.collect = proto == 6
        self.dns_start = dns_name

    def client_stream(self) -> bytes:
        out = bytearray()
        for off in sorted(self.segs):
            if off > len(out):
                break
            data = self.segs[off]
            if off + len(data) > len(out):
                out += data[len(out) - off:]
        return bytes(out[:CLIENT_SNIFF_BYTES])


def _orient(proto, src, sport, dst, dport, flags):
    """True if src is the client."""
    if proto == 6 and flags & TH_SYN:
        return not (flags & TH_ACK)
    if dport in SERVER_PORTS and sport not in SERVER_PORTS:
        return True
    if sport in SERVER_PORTS and dport not in SERVER_PORTS:
        return False
    sp, dp = is_private(src), is_private(dst)
    if sp != dp:
        return sp
    return sport >= dport


def _open(path):
    f = open(path, "rb")
    magic = f.read(4)
    f.seek(0)
    if magic == b"\x0a\x0d\x0d\x0a":
        return f, dpkt.pcapng.Reader(f)
    return f, dpkt.pcap.Reader(f)


def read_capture(path: str):
    """(packets DataFrame, flows DataFrame, info dict) for one capture file."""
    fh, rdr = _open(path)
    linktype = rdr.datalink()
    if linktype not in LINKTYPES:
        fh.close()
        raise ValueError(f"unsupported link type {linktype}")
    flows: dict[tuple, _Flow] = {}
    order: list[_Flow] = []
    dnsmap: dict[bytes, str] = {}
    p_ts, p_flow, p_up, p_len = array("d"), array("i"), array("b"), array("q")
    n = dict(frames=0, ip=0, tcp=0, udp=0, other=0, bad=0, dns_answers=0)
    t_first = t_last = None
    try:
        for ts, buf in rdr:
            n["frames"] += 1
            ts = float(ts)
            if t_first is None:
                t_first = ts
            t_last = ts
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
                sport, dport, flags = l4.sport, l4.dport, l4.flags
                plen = max(0, ip_payload - l4.off * 4)
                data = l4.data if isinstance(l4.data, (bytes, bytearray)) else bytes(l4.data)
                seq = l4.seq
            elif proto == 17 and isinstance(l4, dpkt.udp.UDP):
                n["udp"] += 1
                sport, dport, flags, seq = l4.sport, l4.dport, 0, 0
                plen = max(0, (l4.ulen - 8) if l4.ulen else len(l4.data))
                data = l4.data if isinstance(l4.data, (bytes, bytearray)) else bytes(l4.data)
                if sport == 53 and data:
                    try:
                        d = dpkt.dns.DNS(data)
                        if d.qr == dpkt.dns.DNS_R and d.qd:
                            qname = d.qd[0].name.lower().rstrip(".")
                            for rr in d.an:
                                if rr.type == dpkt.dns.DNS_A and len(getattr(rr, "ip", b"")) == 4:
                                    dnsmap[rr.ip] = qname
                                    n["dns_answers"] += 1
                                elif rr.type == dpkt.dns.DNS_AAAA and len(getattr(rr, "ip6", b"")) == 16:
                                    dnsmap[rr.ip6] = qname
                                    n["dns_answers"] += 1
                    except (dpkt.UnpackError, IndexError, ValueError, struct.error, UnicodeDecodeError):
                        pass
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
                syn = proto == 6 and bool(flags & TH_SYN) and not (flags & TH_ACK) and cip == src
                fl = _Flow(len(order), proto, cip, cport, sip, sport_s, ts, syn, seq, dnsmap.get(sip))
                flows[key] = fl
                order.append(fl)
            elif proto == 6 and fl.base is None and (flags & TH_SYN) and not (flags & TH_ACK) and src == fl.cip:
                fl.syn, fl.base = True, (seq + 1) & 0xFFFFFFFF
            fl.last = ts
            up = src == fl.cip and sport == fl.cport
            if plen > 0:
                if up:
                    fl.up_b += plen
                    fl.up_p += 1
                else:
                    fl.dn_b += plen
                    fl.dn_p += 1
                p_ts.append(ts)
                p_flow.append(fl.idx)
                p_up.append(1 if up else 0)
                p_len.append(plen)
                if up and fl.collect and data:
                    if fl.base is None:
                        fl.base = seq
                    off = (seq - fl.base) & 0xFFFFFFFF
                    if off < CLIENT_SNIFF_BYTES:
                        fl.segs[off] = bytes(data)
                        fl.seg_bytes += len(data)
                    if fl.seg_bytes >= CLIENT_SNIFF_BYTES or len(fl.segs) >= CLIENT_SNIFF_SEGMENTS:
                        fl.collect = False
    finally:
        fh.close()

    rows = []
    for fl in order:
        sni = alpn = host = None
        if fl.proto == 6 and fl.segs:
            stream = fl.client_stream()
            if stream[:1] == b"\x16":
                sni, alpn = parse_client_hello(stream)
            else:
                host = parse_http_host(stream)
        dns_name = fl.dns_start or dnsmap.get(fl.sip)
        name, src_ = (sni, "sni") if sni else (host, "http") if host else (dns_name, "dns") if dns_name else ("", "")
        rows.append(dict(flow=fl.idx, proto=fl.proto, client_ip=ip_text(fl.cip), client_port=fl.cport,
                         server_ip=ip_text(fl.sip), server_port=fl.sport, first_ts=fl.first, last_ts=fl.last,
                         up_bytes=fl.up_b, down_bytes=fl.dn_b, up_pkts=fl.up_p, down_pkts=fl.dn_p, syn_seen=fl.syn,
                         sni=sni or "", alpn=alpn or "", http_host=host or "", dns_name=dns_name or "", name=name,
                         name_src=src_, server_private=is_private(fl.sip)))
    flow_cols = ["flow", "proto", "client_ip", "client_port", "server_ip", "server_port", "first_ts", "last_ts",
                 "up_bytes", "down_bytes", "up_pkts", "down_pkts", "syn_seen", "sni", "alpn", "http_host", "dns_name",
                 "name", "name_src", "server_private"]
    flows_df = pd.DataFrame(rows, columns=flow_cols)
    packets = pd.DataFrame({"ts": np.frombuffer(p_ts, dtype=np.float64).copy(),
                            "flow": np.frombuffer(p_flow, dtype=np.intc).astype(np.int32),
                            "up": np.frombuffer(p_up, dtype=np.int8).copy(),
                            "plen": np.frombuffer(p_len, dtype=np.int64).astype(np.int32)})
    tcp443 = (flows_df.proto == 6) & (flows_df.server_port == 443)
    named = flows_df.name != ""
    info = dict(linktype=int(linktype), linktype_name=LINKTYPES[linktype], frames=n["frames"], ip_frames=n["ip"],
                tcp_frames=n["tcp"], udp_frames=n["udp"], other_frames=n["other"], bad_frames=n["bad"],
                dns_answers=n["dns_answers"], first_ts=t_first, last_ts=t_last, flows=len(flows_df),
                payload_packets=len(packets), up_bytes=int(flows_df.up_bytes.sum()),
                down_bytes=int(flows_df.down_bytes.sum()), named_up_bytes=int(flows_df.up_bytes[named].sum()),
                tcp443_up_bytes=int(flows_df.up_bytes[tcp443].sum()),
                tcp443_named_up_bytes=int(flows_df.up_bytes[tcp443 & named].sum()),
                udp443_up_bytes=int(flows_df.up_bytes[(flows_df.proto == 17) & (flows_df.server_port == 443)].sum()))
    return packets, flows_df, info
