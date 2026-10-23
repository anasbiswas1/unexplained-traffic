"""One network namespace per run, with NAT to the internet, its own DNS settings and a packet capture on the run's own
interface, so concurrent runs never mix. Linux only, run as root.

Run k gets namespace ut<k>, a veth pair uth<k> (VM side) and utn<k> (run side) and the subnet 10.200.<k>.0/30.
Containment rules, tagged with the comment ut-run:ut<k> and removed with the run:
  - the run reaches the public internet only: private, shared and link-local ranges (which include the cloud
    metadata service) are dropped, and so is any other run's subnet;
  - the run cannot reach services on the VM itself;
  - IPv6 is off inside the run, so every capture is IPv4;
  - DNS goes to public resolvers, because the VM's own resolver is a local stub the run cannot reach.

Capture fidelity, so that the run capture holds the packets that cross the wire:
  - MTU. Both ends of the veth pair get the MTU of the VM's uplink (the interface that carries the IPv4 default route,
    or the default route's own mtu attribute when that is smaller). A veth pair left at the default 1500 on an uplink
    with a smaller MTU (1460 on Google Cloud) makes every run send full-size segments that the uplink drops, followed
    by ICMP "fragmentation needed" and resends at the start of every connection.
  - Offloads. Segmentation and receive offloads (TSO, GSO, GRO) are off on both ends. With them on, the run's TCP
    stack hands the veth blocks of up to 64 KB that are cut into wire-size segments only later, and a capture on the
    veth records the blocks, not the packets. With them off, the run's own segments, and packets merged on arrival at
    the VM (GRO on the uplink), are wire-size when they reach the run interface; merged packets keep their wire sizes
    but lose the microsecond gaps between their arrivals.
  - Capture tail. tcpdump runs in immediate mode, so every packet is written as it arrives; in its default buffered
    mode the packets waiting in its buffer when it is stopped are lost.
The MTU and offload settings are checked on both ends after creation; they and each capture's packet counts are
recorded in the run metadata (metadata()).
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import threading

TAG = "ut-run"
OFFLOADS = {"tso": "tcp-segmentation-offload", "gso": "generic-segmentation-offload",
            "gro": "generic-receive-offload"}
RESOLVERS = ["1.1.1.1", "8.8.8.8"]
BLOCKED = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"]


def sh(args, check=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r


def default_route() -> tuple[str, int | None]:
    """Interface of the IPv4 default route, and the route's own mtu attribute when it has one."""
    return parse_default_route(sh(["ip", "-4", "route", "show", "default"]).stdout)


def parse_default_route(text: str) -> tuple[str, int | None]:
    out = text.split()
    if "dev" not in out:
        raise RuntimeError("no IPv4 default route")
    route_mtu = None
    for i, word in enumerate(out[:-1]):
        if word == "mtu":
            value = out[i + 2] if out[i + 1] == "lock" and i + 2 < len(out) else out[i + 1]
            route_mtu = int(value) if value.isdigit() else None
            break
    return out[out.index("dev") + 1], route_mtu


def default_interface() -> str:
    return default_route()[0]


def parse_link_mtu(text: str) -> int:
    """MTU from the output of 'ip -o link show dev <name>'."""
    m = re.search(r"\bmtu (\d+)\b", text)
    if not m:
        raise RuntimeError(f"no mtu in: {text.strip()[:200]}")
    return int(m.group(1))


def link_mtu(dev: str, ns: str | None = None) -> int:
    args = ["ip"] + (["-n", ns] if ns else []) + ["-o", "link", "show", "dev", dev]
    return parse_link_mtu(sh(args).stdout)


def parse_offloads(text: str) -> dict:
    """States of the offloads in OFFLOADS from the output of 'ethtool -k <name>' ("off", "on", or "off [fixed]")."""
    states = {}
    for line in text.splitlines():
        name, sep, value = line.strip().partition(":")
        if sep and name in OFFLOADS.values():
            states[name] = value.strip()
    return states


def link_offloads(dev: str, ns: str | None = None) -> dict:
    args = (["ip", "netns", "exec", ns] if ns else []) + ["ethtool", "-k", dev]
    return parse_offloads(sh(args).stdout)


def offloads_off(states: dict) -> bool:
    return set(states) == set(OFFLOADS.values()) and all(v.split()[0] == "off" for v in states.values())


def uplink_mtu() -> dict:
    """The uplink, its MTU, the default route's mtu attribute, and the MTU the run interfaces get."""
    dev, route_mtu = default_route()
    dev_mtu = link_mtu(dev)
    return dict(uplink=dev, uplink_mtu=dev_mtu, route_mtu=route_mtu,
                mtu=min(dev_mtu, route_mtu) if route_mtu else dev_mtu)


def remove_tagged_rules(tag: str) -> int:
    """Delete every iptables rule whose comment equals tag (or starts with it when tag ends with ':')."""
    removed = 0
    for table in ("filter", "nat"):
        for line in sh(["iptables", "-w", "-t", table, "-S"]).stdout.splitlines():
            if not line.startswith("-A ") or "--comment" not in line:
                continue
            args = shlex.split(line)
            comment = args[args.index("--comment") + 1]
            if comment == tag or (tag.endswith(":") and comment.startswith(tag)):
                sh(["iptables", "-w", "-t", table, "-D"] + args[1:], check=False)
                removed += 1
    return removed


def cleanup_all() -> None:
    """Remove every run namespace, interface and rule left by earlier runs."""
    remove_tagged_rules(f"{TAG}:")
    for line in sh(["ip", "netns", "list"], check=False).stdout.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.startswith("ut") and name[2:].isdigit():
            sh(["ip", "netns", "del", name], check=False)
            shutil.rmtree(f"/etc/netns/{name}", ignore_errors=True)


def parse_capture_stats(text: str) -> dict:
    """tcpdump's closing counts: packets captured (written), received by filter, dropped by kernel or interface.
    complete is true when every packet the filter received was written and none was dropped."""
    counts = {}
    for key, pattern in (("captured", r"(\d+) packets? captured"), ("received", r"(\d+) packets? received by filter"),
                         ("dropped_kernel", r"(\d+) packets? dropped by kernel"),
                         ("dropped_interface", r"(\d+) packets? dropped by interface")):
        m = re.search(pattern, text)
        counts[key] = int(m.group(1)) if m else None
    counts["complete"] = (counts["captured"] is not None and counts["captured"] == counts["received"]
                          and not counts["dropped_kernel"] and not counts["dropped_interface"])
    return counts


class Capture:
    def __init__(self, proc, path):
        self.proc, self.path = proc, path
        self.lines = []
        self.ready = threading.Event()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.proc.stderr:
            self.lines.append(line.rstrip())
            if "listening on" in line:
                self.ready.set()
        self.ready.set()

    def stop(self) -> str:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self.reader.join(5)
        return "\n".join(self.lines)

    def stats(self) -> dict:
        return dict(path=self.path, **parse_capture_stats("\n".join(self.lines)))


class RunNet:
    def __init__(self, index: int):
        if not 1 <= index <= 254:
            raise ValueError("run index must be 1 to 254")
        self.index = index
        self.ns = f"ut{index}"
        self.host_if, self.ns_if = f"uth{index}", f"utn{index}"
        self.host_ip, self.ns_ip = f"10.200.{index}.1", f"10.200.{index}.2"
        self.cidr = f"10.200.{index}.0/30"
        self.tag = f"{TAG}:{self.ns}"
        self.link = {}
        self.captures = []

    def __enter__(self):
        try:
            self.create()
        except Exception:
            self.destroy()
            raise
        return self

    def __exit__(self, *exc):
        self.destroy()

    def cmd(self, args: list[str]) -> list[str]:
        return ["ip", "netns", "exec", self.ns] + list(args)

    def rule(self, table, chain, spec, position=None):
        where = ["-I", chain, str(position)] if position else ["-A", chain]
        sh(["iptables", "-w", "-t", table] + where + spec + ["-m", "comment", "--comment", self.tag])

    def create(self) -> None:
        self.destroy()
        up = uplink_mtu()
        out, mtu = up["uplink"], up["mtu"]
        sh(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
        sh(["ip", "netns", "add", self.ns])
        sh(["ip", "link", "add", self.host_if, "type", "veth", "peer", "name", self.ns_if])
        sh(["ip", "link", "set", "dev", self.host_if, "mtu", str(mtu)])
        sh(["ip", "link", "set", "dev", self.ns_if, "mtu", str(mtu)])
        sh(["ip", "link", "set", self.ns_if, "netns", self.ns])
        sh(["ip", "addr", "add", f"{self.host_ip}/30", "dev", self.host_if])
        sh(["ip", "link", "set", self.host_if, "up"])
        sh(self.cmd(["ip", "addr", "add", f"{self.ns_ip}/30", "dev", self.ns_if]))
        sh(self.cmd(["ip", "link", "set", self.ns_if, "up"]))
        off = [w for k in OFFLOADS for w in (k, "off")]
        sh(["ethtool", "-K", self.host_if] + off)
        sh(self.cmd(["ethtool", "-K", self.ns_if] + off))
        self.link = dict(up, host_if=self.host_if, host_if_mtu=link_mtu(self.host_if), ns_if=self.ns_if,
                         ns_if_mtu=link_mtu(self.ns_if, self.ns),
                         offloads={self.host_if: link_offloads(self.host_if),
                                   self.ns_if: link_offloads(self.ns_if, self.ns)})
        if not self.link["host_if_mtu"] == self.link["ns_if_mtu"] == mtu:
            raise RuntimeError(f"veth MTU differs from the uplink MTU: {self.link}")
        if not all(offloads_off(v) for v in self.link["offloads"].values()):
            raise RuntimeError(f"offloads still on: {self.link['offloads']}")
        sh(self.cmd(["ip", "link", "set", "lo", "up"]))
        sh(self.cmd(["ip", "route", "add", "default", "via", self.host_ip]))
        sh(self.cmd(["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"]), check=False)
        sh(self.cmd(["sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1"]), check=False)
        os.makedirs(f"/etc/netns/{self.ns}", exist_ok=True)
        with open(f"/etc/netns/{self.ns}/resolv.conf", "w") as f:
            f.write("".join(f"nameserver {r}\n" for r in RESOLVERS))
        # rules are inserted at the top of their chains in this order, so they are evaluated before any VM rule
        position = 1
        for net in BLOCKED:
            self.rule("filter", "FORWARD", ["-i", self.host_if, "-d", net, "-j", "DROP"], position)
            position += 1
        self.rule("filter", "FORWARD", ["-i", self.host_if, "-o", out, "-j", "ACCEPT"], position)
        self.rule("filter", "FORWARD", ["-i", out, "-o", self.host_if, "-m", "conntrack", "--ctstate",
                                        "ESTABLISHED,RELATED", "-j", "ACCEPT"], position + 1)
        self.rule("filter", "FORWARD", ["-i", self.host_if, "-j", "DROP"], position + 2)
        self.rule("filter", "FORWARD", ["-o", self.host_if, "-j", "DROP"], position + 3)
        self.rule("filter", "INPUT", ["-i", self.host_if, "-j", "DROP"], 1)
        self.rule("nat", "POSTROUTING", ["-s", self.cidr, "-o", out, "-j", "MASQUERADE"], 1)

    def metadata(self) -> dict:
        """Run network settings and the counts of the run's stopped captures, recorded with every run."""
        return dict(ns=self.ns, subnet=self.cidr, ns_ip=self.ns_ip, host_ip=self.host_ip, **self.link,
                    captures=[c.stats() for c in self.captures if c.proc.poll() is not None])

    def write_metadata(self, path: str) -> dict:
        meta = self.metadata()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w") as f:
            json.dump(meta, f, indent=1)
        return meta

    def destroy(self) -> None:
        remove_tagged_rules(self.tag)
        sh(["ip", "netns", "del", self.ns], check=False)
        sh(["ip", "link", "del", self.host_if], check=False)
        shutil.rmtree(f"/etc/netns/{self.ns}", ignore_errors=True)

    def capture(self, path: str, timeout: float = 10.0) -> Capture:
        """Start tcpdump on the run's own interface; returns once tcpdump reports that it is listening."""
        if not path.endswith(".pcap"):
            raise ValueError("capture files end in .pcap (the tcpdump AppArmor profile allows that name)")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        proc = subprocess.Popen(self.cmd(["tcpdump", "-i", self.ns_if, "-s", "0", "-U", "--immediate-mode", "-n",
                                          "-Z", "root", "-w", path]), stderr=subprocess.PIPE, text=True)
        cap = Capture(proc, path)
        self.captures.append(cap)
        if not cap.ready.wait(timeout) or proc.poll() is not None:
            cap.stop()
            raise RuntimeError(f"tcpdump did not start: {' | '.join(cap.lines)}")
        return cap
