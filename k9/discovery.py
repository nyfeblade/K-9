"""Host discovery without root.

Strategy: a fast threaded ICMP ping sweep nudges the kernel into ARP-resolving
every address on the subnet, then we read the kernel's neighbour (ARP) table to
recover IP -> MAC. Crucially this catches hosts that *ignore* ICMP but still
answer ARP (almost everything does), so "silent" devices still show up — we
just mark them as not-ICMP-responsive, which is itself a useful signal.

For stubborn hosts we optionally fire a TCP connect at a couple of common ports
to force ARP resolution even when both ICMP and the ARP probe were dropped.

All of this is stdlib + the system `ping`/`ip` binaries. No raw sockets, no
CAP_NET_RAW, no scapy. If scapy *is* importable and we're root, we transparently
add a true ARP broadcast sweep for completeness.
"""

from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class Host:
    ip: str
    mac: str = ""
    icmp_alive: bool = False        # answered our ping
    arp_only: bool = False          # in ARP table but never answered ICMP
    via: str = ""                   # how we first saw it: ping / arp / tcp / scapy
    rtt_ms: float | None = None
    # filled in later by fingerprint / classify stages
    hostname: str = ""
    vendor: str = ""
    open_ports: dict[int, str] = field(default_factory=dict)
    services: dict[str, str] = field(default_factory=dict)  # ssdp/mdns/netbios/http
    device_type: str = "Unknown"
    category: str = "unknown"
    flags: list[str] = field(default_factory=list)
    flag_reasons: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    is_new: bool = False
    is_self: bool = False
    is_gateway: bool = False
    # user annotations (persist across rescans) + per-port history
    user_label: str = ""
    tags: list = field(default_factory=list)
    note: str = ""
    trust: str = ""                       # "trusted" | "untrusted" | ""
    ports_seen: dict = field(default_factory=dict)   # port -> {"first":ts,"last":ts}

    @property
    def randomized_mac(self) -> bool:
        from . import oui
        return oui.is_randomized(self.mac)


_PING_COUNT = "-c"
_PING_TIMEOUT = "-W"  # seconds on Linux
_IS_MAC = platform.system() == "Darwin"


def _ping(ip: str, timeout: float) -> tuple[bool, float | None]:
    """Return (alive, rtt_ms). Uses the system ping; no privileges needed."""
    if _IS_MAC:
        cmd = ["ping", "-c", "1", "-t", str(max(1, int(timeout))), "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(max(1, round(timeout)))), "-n", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1.5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False, None
    if out.returncode != 0:
        return False, None
    m = re.search(r"time[=<]([\d.]+)\s*ms", out.stdout)
    return True, (float(m.group(1)) if m else None)


def _tcp_knock(ip: str, ports: tuple[int, ...], timeout: float) -> bool:
    """Try to open a TCP connection to force ARP resolution. Any RST/SYN-ACK
    means the host (and thus its MAC) is reachable on L2."""
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((ip, port))
            # 0 = open, ECONNREFUSED = host is there but port closed: both prove L2.
            if rc == 0 or rc == 111:
                return True
        except OSError:
            pass
        finally:
            s.close()
    return False


def read_arp_table() -> dict[str, str]:
    """IP -> MAC from the kernel neighbour table (`ip neigh`), with a /proc fallback."""
    table: dict[str, str] = {}
    try:
        out = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5, check=False).stdout
        for line in out.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})", line)
            if m:
                mac = m.group(2).lower()
                if mac != "00:00:00:00:00:00":
                    table[m.group(1)] = mac
    except (OSError, subprocess.TimeoutExpired):
        pass
    if not table:  # /proc/net/arp fallback (older systems / no iproute2)
        try:
            with open("/proc/net/arp") as fh:
                for line in fh.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        table[parts[0]] = parts[3].lower()
        except OSError:
            pass
    return table


def _scapy_arp_sweep(cidr: str, timeout: float) -> dict[str, str]:
    """Optional true ARP broadcast sweep when scapy is present and we're root."""
    if os.geteuid() != 0:
        return {}
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except Exception:
        return {}
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
            timeout=max(2, timeout), verbose=0,
        )
        return {rcv.psrc: rcv.hwsrc.lower() for _snt, rcv in ans}
    except Exception:
        return {}


def sweep(
    targets: list[str],
    cidr: str,
    *,
    timeout: float = 1.0,
    workers: int = 256,
    tcp_fallback: bool = True,
    progress=None,
) -> dict[str, Host]:
    """Discover live hosts. Returns {ip: Host}."""
    hosts: dict[str, Host] = {}
    done = 0
    total = len(targets)

    # 1) Parallel ICMP sweep — primes the ARP cache as a side effect.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_ping, ip, timeout): ip for ip in targets}
        for fut in as_completed(futs):
            ip = futs[fut]
            alive, rtt = fut.result()
            if alive:
                hosts[ip] = Host(ip=ip, icmp_alive=True, via="ping", rtt_ms=rtt)
            done += 1
            if progress:
                progress(done, total, "ping sweep")

    # 2) Read the ARP table — pulls in ICMP-silent hosts that still answered ARP.
    for ip, mac in read_arp_table().items():
        if ip not in targets:
            continue
        if ip in hosts:
            hosts[ip].mac = mac
        else:
            hosts[ip] = Host(ip=ip, mac=mac, arp_only=True, via="arp")

    # 3) Optional scapy ARP sweep (root only) to catch anything still missing.
    for ip, mac in _scapy_arp_sweep(cidr, timeout).items():
        if ip in hosts:
            hosts[ip].mac = hosts[ip].mac or mac
        else:
            hosts[ip] = Host(ip=ip, mac=mac, arp_only=True, via="scapy")

    # 4) TCP knock on hosts we still have no MAC for, then re-read ARP.
    if tcp_fallback:
        missing = [ip for ip in targets if ip not in hosts]
        if missing:
            with ThreadPoolExecutor(max_workers=min(workers, 160)) as pool:
                kn = {pool.submit(_tcp_knock, ip, (80, 443, 22, 8080, 8443, 23), timeout): ip for ip in missing}
                for fut in as_completed(kn):
                    ip = kn[fut]
                    try:
                        if fut.result():
                            hosts.setdefault(ip, Host(ip=ip, via="tcp"))
                    except Exception:
                        pass
            for ip, mac in read_arp_table().items():
                if ip in hosts and not hosts[ip].mac:
                    hosts[ip].mac = mac

    return hosts
