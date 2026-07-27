"""Local network introspection: which interface, which subnet, who am I.

Everything here is best-effort and degrades gracefully. The OS-specific work
(interface enumeration, gateway, own-IP) lives in :mod:`k9.sysnet` so this stays
platform-agnostic; if that yields nothing we still synthesise a /24 around our
own IP so a scan can proceed.
"""

from __future__ import annotations

import ipaddress
import sys
from dataclasses import dataclass, field

from . import sysnet


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


def gather() -> NetInfo:
    info = NetInfo()
    info.interfaces = [
        Interface(name=a.name, ip=a.ip, prefixlen=a.prefixlen, mac=a.mac)
        for a in sysnet.interfaces()
    ]
    own_ip = sysnet.own_ip()

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

    info.gateway = sysnet.default_gateway()
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
        raise SystemExit("K-9: could not determine a network to scan; pass one, e.g. --net 192.168.1.0/24")

    if not isinstance(net, ipaddress.IPv4Network):
        raise SystemExit("K-9: only IPv4 networks are supported as scan targets.")

    hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
    if len(hosts) > 4096:
        print(
            f"K-9: {net} has {len(hosts)} hosts; scanning the first 4096. "
            "Narrow it with --net for a focused sweep.",
            file=sys.stderr,
        )
        hosts = hosts[:4096]
    return net, [str(h) for h in hosts]
