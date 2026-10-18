"""One network namespace per run, with NAT to the internet, its own DNS settings and a packet capture on the run's own
interface, so concurrent runs never mix. Linux only, run as root.

Run k gets namespace ut<k>, a veth pair uth<k> (VM side) and utn<k> (run side) and the subnet 10.200.<k>.0/30.
Containment rules, tagged with the comment ut-run:ut<k> and removed with the run:
  - the run reaches the public internet only: private, shared and link-local ranges (which include the cloud
    metadata service) are dropped, and so is any other run's subnet;
  - the run cannot reach services on the VM itself;
  - IPv6 is off inside the run, so every capture is IPv4;
  - DNS goes to public resolvers, because the VM's own resolver is a local stub the run cannot reach.
"""
from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import threading

TAG = "ut-run"
RESOLVERS = ["1.1.1.1", "8.8.8.8"]
BLOCKED = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"]


def sh(args, check=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r


def default_interface() -> str:
    out = sh(["ip", "-4", "route", "show", "default"]).stdout.split()
    if "dev" not in out:
        raise RuntimeError("no IPv4 default route")
    return out[out.index("dev") + 1]


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


class Capture:
    def __init__(self, proc, path):
        self.proc, self.path = proc, path
        self.lines = []
        self.ready = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()

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
        return "\n".join(self.lines)


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

    def __enter__(self):
        self.create()
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
        out = default_interface()
        sh(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
        sh(["ip", "netns", "add", self.ns])
        sh(["ip", "link", "add", self.host_if, "type", "veth", "peer", "name", self.ns_if])
        sh(["ip", "link", "set", self.ns_if, "netns", self.ns])
        sh(["ip", "addr", "add", f"{self.host_ip}/30", "dev", self.host_if])
        sh(["ip", "link", "set", self.host_if, "up"])
        sh(self.cmd(["ip", "addr", "add", f"{self.ns_ip}/30", "dev", self.ns_if]))
        sh(self.cmd(["ip", "link", "set", self.ns_if, "up"]))
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
        proc = subprocess.Popen(self.cmd(["tcpdump", "-i", self.ns_if, "-s", "0", "-U", "-n", "-Z", "root",
                                          "-w", path]), stderr=subprocess.PIPE, text=True)
        cap = Capture(proc, path)
        if not cap.ready.wait(timeout) or proc.poll() is not None:
            cap.stop()
            raise RuntimeError(f"tcpdump did not start: {' | '.join(cap.lines)}")
        return cap
