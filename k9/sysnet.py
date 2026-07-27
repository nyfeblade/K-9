"""Cross-platform system-network layer.

Centralises the handful of OS-specific operations K-9 needs — interface
enumeration, the default gateway, the ARP/neighbour table, and the `ping`
invocation — so the rest of the codebase stays platform-agnostic.

  * Linux  : iproute2 (`ip`) with a /proc fallback
  * macOS  : `ifconfig` / `route -n get default` / `arp -a` (BSD userland)
  * Windows: `ipconfig`-style parsing / `route print` / `arp -a`  (partial;
             filled in with the Windows port)

Everything degrades gracefully to empty results — a caller that gets nothing
back still works, because K-9 can synthesise a /24 around its own IP and scan
by ICMP alone.
"""

from __future__ import annotations

import json
import platform
import re
import socket
import subprocess
from dataclasses import dataclass

SYSTEM = platform.system()          # 'Linux' | 'Darwin' | 'Windows' | ...
IS_LINUX = SYSTEM == "Linux"
IS_MAC = SYSTEM == "Darwin"
IS_WINDOWS = SYSTEM == "Windows"


@dataclass
class IfAddr:
    name: str
    ip: str
    prefixlen: int
    mac: str = ""


def _run(cmd: list[str], timeout: float = 5) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def own_ip() -> str:
    """Our outbound IPv4 without sending a packet — the kernel picks the source
    address for the route to a public IP. Works on every platform."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# --------------------------------------------------------------------------- #
#  MAC normalisation (BSD arp drops leading zeros; Windows uses dashes)        #
# --------------------------------------------------------------------------- #
def norm_mac(raw: str) -> str:
    """Return a canonical aa:bb:cc:dd:ee:ff, or '' if it isn't a 6-octet MAC.

    Handles BSD's short octets ('a4:83:e7:1:2:3') and Windows' dash form
    ('a4-83-e7-01-02-03')."""
    parts = raw.strip().lower().replace("-", ":").split(":")
    if len(parts) != 6:
        return ""
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return ""


# --------------------------------------------------------------------------- #
#  Interfaces                                                                  #
# --------------------------------------------------------------------------- #
def interfaces() -> list[IfAddr]:
    if IS_LINUX:
        return _linux_interfaces()
    if IS_MAC:
        return _bsd_interfaces()
    if IS_WINDOWS:
        return _windows_interfaces()
    return []


def _linux_interfaces() -> list[IfAddr]:
    macs = _linux_iface_macs()
    found: dict[str, IfAddr] = {}
    for line in _run(["ip", "-o", "addr", "show"]).splitlines():
        # "3: wlp2s0    inet 192.168.1.175/24 brd ... scope global ..."
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        name, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        if name == "lo" or ip.startswith("127."):
            continue
        found[name] = IfAddr(name=name, ip=ip, prefixlen=prefix, mac=macs.get(name, ""))
    return list(found.values())


def _linux_iface_macs() -> dict[str, str]:
    macs: dict[str, str] = {}
    for line in _run(["ip", "-o", "link", "show"]).splitlines():
        m = re.search(r"^\d+:\s+(\S+?):.*?link/\w+\s+([0-9a-f:]{17})", line)
        if m:
            macs[m.group(1)] = m.group(2).lower()
    return macs


def _mask_to_prefix(hexmask: str) -> int:
    """macOS/BSD 'inet' lines carry a hex netmask like 0xffffff00 -> 24."""
    try:
        return bin(int(hexmask, 16)).count("1")
    except ValueError:
        return 24


def _bsd_interfaces() -> list[IfAddr]:
    """Parse plain `ifconfig` output (macOS / BSD)."""
    out = _run(["ifconfig"])
    result: list[IfAddr] = []
    name: str | None = None
    mac = ""
    pending: list[tuple[str, int]] = []   # (ip, prefix) for the current iface

    def flush():
        for ip, prefix in pending:
            result.append(IfAddr(name=name or "?", ip=ip, prefixlen=prefix, mac=mac))

    for line in out.splitlines():
        head = re.match(r"^([A-Za-z0-9._-]+):\s+flags=", line)
        if head:
            flush()
            name, mac, pending = head.group(1), "", []
            continue
        if name is None:
            continue
        m = re.search(r"\bether\s+([0-9a-fA-F:]{17})", line)
        if m:
            mac = m.group(1).lower()
            continue
        # IPv4 only ('inet ' with a trailing space excludes 'inet6')
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)", line)
        if m:
            ip = m.group(1)
            if name != "lo0" and not ip.startswith("127."):
                pending.append((ip, _mask_to_prefix(m.group(2))))
    flush()
    return result


# One PowerShell call yields interfaces + gateway as JSON. We use cmdlets
# (Get-NetIPAddress / Get-NetAdapter / Get-NetRoute) rather than parsing
# `ipconfig`, because their output is localisation-independent — the property
# names are fixed English regardless of the machine's display language.
_WIN_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$gw=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric |"
    " Select-Object -First 1).NextHop;"
    "$ifs=Get-NetIPAddress -AddressFamily IPv4 |"
    " Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |"
    " ForEach-Object { $a=Get-NetAdapter -InterfaceIndex $_.InterfaceIndex;"
    " [PSCustomObject]@{ip=$_.IPAddress;prefix=[int]$_.PrefixLength;"
    "name=$_.InterfaceAlias;mac=$a.MacAddress} };"
    "[PSCustomObject]@{gateway=$gw;interfaces=@($ifs)} | ConvertTo-Json -Compress -Depth 4"
)

_win_probe_cache: tuple[list, str] | None = None


def _windows_probe() -> tuple[list, str]:
    """Run the PowerShell probe once and cache (interfaces, gateway)."""
    global _win_probe_cache
    if _win_probe_cache is None:
        out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _WIN_PS], timeout=12)
        _win_probe_cache = _parse_windows_probe(out)
    return _win_probe_cache


def _parse_windows_probe(js: str) -> tuple[list, str]:
    """Parse the probe's JSON into (interfaces, gateway). Pure — unit-tested."""
    try:
        data = json.loads(js) if js and js.strip() else {}
    except (ValueError, TypeError):
        return [], ""
    gw = str(data.get("gateway") or "")
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
        gw = ""
    raw = data.get("interfaces") or []
    if isinstance(raw, dict):          # ConvertTo-Json emits a bare object for one item
        raw = [raw]
    ifs: list[IfAddr] = []
    for e in raw:
        if not isinstance(e, dict):
            continue
        ip = str(e.get("ip", ""))
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            continue
        try:
            prefix = int(e.get("prefix") or 24)
        except (ValueError, TypeError):
            prefix = 24
        ifs.append(IfAddr(name=str(e.get("name", "?")), ip=ip,
                          prefixlen=prefix, mac=norm_mac(str(e.get("mac", "")))))
    return ifs, gw


def _parse_route_print(text: str) -> str:
    """Default gateway from `route print -4` — the 0.0.0.0/0.0.0.0 row is numeric
    and language-independent. Returns the lowest-metric gateway."""
    best, best_metric = "", 1 << 30
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0" \
                and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[2]):
            try:
                metric = int(parts[-1])
            except ValueError:
                metric = 0
            if metric < best_metric:
                best, best_metric = parts[2], metric
    return best


def _windows_interfaces() -> list[IfAddr]:
    return _windows_probe()[0]


# --------------------------------------------------------------------------- #
#  Default gateway                                                            #
# --------------------------------------------------------------------------- #
def default_gateway() -> str:
    if IS_LINUX:
        return _linux_gateway()
    if IS_MAC:
        return _bsd_gateway()
    if IS_WINDOWS:
        return _windows_gateway()
    return ""


def _linux_gateway() -> str:
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", _run(["ip", "route", "show", "default"]))
    if m:
        return m.group(1)
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    octets = [int(parts[2][i:i + 2], 16) for i in (6, 4, 2, 0)]
                    return ".".join(str(o) for o in octets)
    except OSError:
        pass
    return ""


def _bsd_gateway() -> str:
    m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", _run(["route", "-n", "get", "default"]))
    if m:
        return m.group(1)
    for line in _run(["netstat", "-rn", "-f", "inet"]).splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("default", "0.0.0.0") \
                and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1]):
            return parts[1]
    return ""


def _windows_gateway() -> str:
    gw = _windows_probe()[1]
    if gw:
        return gw
    return _parse_route_print(_run(["route", "print", "-4"]))


# --------------------------------------------------------------------------- #
#  ARP / neighbour table                                                      #
# --------------------------------------------------------------------------- #
def arp_table() -> dict[str, str]:
    """IP -> MAC from the OS neighbour cache."""
    if IS_LINUX:
        return _linux_arp()
    return _arp_a_table()   # macOS + Windows both speak `arp -a`


def _linux_arp() -> dict[str, str]:
    table: dict[str, str] = {}
    for line in _run(["ip", "neigh"]).splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})", line)
        if m and m.group(2).lower() != "00:00:00:00:00:00":
            table[m.group(1)] = m.group(2).lower()
    if not table:  # older systems / no iproute2
        try:
            with open("/proc/net/arp") as fh:
                for line in fh.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        table[parts[0]] = parts[3].lower()
        except OSError:
            pass
    return table


# BSD:      "host (192.168.1.1) at ac:83:e7:1:2:3 on en0 ifscope [ethernet]"
# Windows:  "  192.168.1.1           ac-83-e7-01-02-03     dynamic"
_ARP_BSD = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)")
_ARP_WIN = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{11,17})\s")


def _arp_a_table() -> dict[str, str]:
    cmd = ["arp", "-a"] if IS_WINDOWS else ["arp", "-a", "-n"]
    table: dict[str, str] = {}
    for line in _run(cmd).splitlines():
        if "incomplete" in line.lower():
            continue
        m = _ARP_BSD.search(line) or _ARP_WIN.match(line)
        if not m:
            continue
        mac = norm_mac(m.group(2))
        if mac and mac != "00:00:00:00:00:00":
            table[m.group(1)] = mac
    return table


# --------------------------------------------------------------------------- #
#  Ping                                                                        #
# --------------------------------------------------------------------------- #
def ping_command(ip: str, timeout: float) -> list[str]:
    """A single-shot ping appropriate to the OS. rtt is parsed by the caller."""
    secs = max(1, int(round(timeout)))
    ms = max(1, int(timeout * 1000))
    if IS_WINDOWS:
        return ["ping", "-n", "1", "-w", str(ms), ip]
    if IS_MAC:
        # macOS: -t = overall timeout (s), -W = per-reply wait (ms)
        return ["ping", "-c", "1", "-t", str(secs), "-W", str(ms), ip]
    # Linux: -W = per-reply wait (s), -n = numeric output
    return ["ping", "-c", "1", "-W", str(secs), "-n", ip]
