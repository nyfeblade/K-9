"""Pull authoritative hostnames from local DHCP-server lease files.

If the machine running ViperScan is also the DHCP server (a router, a Pi-hole /
dnsmasq box, an OpenWrt device), its lease file is the single most reliable
source of device names — every device tells the DHCP server its hostname at
join time. We read the common dnsmasq and ISC-dhcpd lease locations and map
both MAC→name and IP→name. Returns empty when no lease file is present (i.e.
this box isn't the DHCP server), which is the common laptop case — a clean no-op.
"""

from __future__ import annotations

import glob
import os
import re

_DNSMASQ_PATHS = [
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dnsmasq/dnsmasq.leases",
    "/etc/pihole/dhcp.leases",
    "/tmp/dhcp.leases",
    "/tmp/dnsmasq.leases",
]
_ISC_PATHS = ["/var/lib/dhcp/dhcpd.leases", "/var/lib/dhcpd/dhcpd.leases"]


def _read_dnsmasq(path, by_mac, by_ip):
    # "<expiry> <mac> <ip> <hostname> <client-id>"
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    mac, ip, host = parts[1].lower(), parts[2], parts[3]
                    if host and host != "*":
                        by_mac[mac] = host
                        by_ip[ip] = host
    except OSError:
        pass


def _read_isc(path, by_mac, by_ip):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return
    for block in re.findall(r"lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\}", text, re.S):
        ip, body = block
        mac = re.search(r"hardware ethernet\s+([0-9a-fA-F:]{17})", body)
        host = re.search(r'client-hostname\s+"([^"]+)"', body)
        if host:
            by_ip[ip] = host.group(1)
            if mac:
                by_mac[mac.group(1).lower()] = host.group(1)


def leases() -> tuple[dict, dict]:
    """Return (by_mac, by_ip) hostname maps, or ({}, {}) if no lease file."""
    by_mac, by_ip = {}, {}
    for path in _DNSMASQ_PATHS + glob.glob("/var/lib/NetworkManager/dnsmasq-*.leases"):
        if os.path.isfile(path):
            _read_dnsmasq(path, by_mac, by_ip)
    for path in _ISC_PATHS:
        if os.path.isfile(path):
            _read_isc(path, by_mac, by_ip)
    return by_mac, by_ip
