"""Local network introspection: which interface, which subnet, who am I.

Everything here is best-effort and degrades gracefully. We prefer the modern
`ip` tooling on Linux, fall back to parsing /proc, and finally to a UDP-socket
trick that works on any platform to learn our own primary IP.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class Interface:
    name: str
    ip: str
    prefixlen: int
    mac: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.ip}/{self.prefixlen}", strict=False)

    @property
    def cidr(self) -> str:
        return f"{self.network.network_address}/{self.prefixlen}"


@dataclass
class NetInfo:
    interfaces: list[Interface] = field(default_factory=list)
    primary: Interface | None = None
    gateway: str = ""
    gateway_mac: str = ""


def _run(cmd: list[str]) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, check=False
        )
        return out.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _own_ip_via_socket() -> str:
    """Discover our outbound IP without sending a packet (connect to a UDP
    socket; the kernel just picks the source address for the route)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _parse_ip_addr() -> list[Interface]:
    """Parse `ip -o addr show` lines into interfaces with IPv4 + prefix."""
    out = _run(["ip", "-o", "addr", "show"])
    macs = _parse_ip_link()
    found: dict[str, Interface] = {}
    for line in out.splitlines():
        # e.g. "3: wlp2s0    inet 192.168.1.175/24 brd ... scope global ..."
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        name, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        if name == "lo" or ip.startswith("127."):
            continue
        found[name] = Interface(name=name, ip=ip, prefixlen=prefix, mac=macs.get(name, ""))
    return list(found.values())


def _parse_ip_link() -> dict[str, str]:
    """Map interface name -> MAC from `ip -o link`."""
    out = _run(["ip", "-o", "link", "show"])
    macs: dict[str, str] = {}
    for line in out.splitlines():
        m = re.search(r"^\d+:\s+(\S+?):.*?link/\w+\s+([0-9a-f:]{17})", line)
        if m:
            macs[m.group(1)] = m.group(2).lower()
    return macs


def _default_gateway() -> str:
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    # /proc fallback
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    gw_hex = parts[2]
                    octets = [int(gw_hex[i:i + 2], 16) for i in (6, 4, 2, 0)]
                    return ".".join(str(o) for o in octets)
    except OSError:
        pass
    return ""


def gather() -> NetInfo:
    info = NetInfo()
    info.interfaces = _parse_ip_addr()
    own_ip = _own_ip_via_socket()

    # Pick the interface that owns our outbound IP; else the first private one.
    for iface in info.interfaces:
        if iface.ip == own_ip:
            info.primary = iface
            break
    if info.primary is None and info.interfaces:
        for iface in info.interfaces:
            if ipaddress.ip_address(iface.ip).is_private:
                info.primary = iface
                break
        info.primary = info.primary or info.interfaces[0]

    # Last-ditch: synthesize a /24 around our own IP if `ip addr` gave nothing.
    if info.primary is None and own_ip != "127.0.0.1":
        info.primary = Interface(name="?", ip=own_ip, prefixlen=24)
        info.interfaces.append(info.primary)

    info.gateway = _default_gateway()
    return info


def resolve_targets(cidr: str | None, info: NetInfo) -> tuple[ipaddress.IPv4Network, list[str]]:
    """Return (network, list-of-host-ip-strings) to scan.

    If *cidr* is None we use the primary interface's network. We cap very large
    networks so an accidental /16 doesn't try to sweep 65k hosts.
    """
    if cidr:
        net = ipaddress.ip_network(cidr, strict=False)
    elif info.primary is not None:
        net = info.primary.network
    else:
        raise SystemExit("ViperScan: could not determine a network to scan; pass one, e.g. --net 192.168.1.0/24")

    if not isinstance(net, ipaddress.IPv4Network):
        raise SystemExit("ViperScan: only IPv4 networks are supported as scan targets.")

    hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
    if len(hosts) > 4096:
        print(
            f"ViperScan: {net} has {len(hosts)} hosts; scanning the first 4096. "
            "Narrow it with --net for a focused sweep.",
            file=sys.stderr,
        )
        hosts = hosts[:4096]
    return net, [str(h) for h in hosts]
