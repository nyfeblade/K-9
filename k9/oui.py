"""MAC address vendor lookup, fully offline.

Coverage comes from whatever OUI database already lives on the machine — we
auto-detect nmap's `nmap-mac-prefixes` (42k entries), Wireshark's `manuf`, and
IEEE's `oui.txt`. On top of that we ship a small curated map of camera / IoT /
smart-home vendors so the security-relevant brands are *always* recognised even
on a box with no system database at all.

We also decode two structural facts straight out of the MAC itself:
  * locally-administered (randomised / privacy) addresses, and
  * multicast addresses,
both of which matter when you're deciding whether a host is trying to hide.
"""

from __future__ import annotations

import os
import re

# System databases we know how to parse, in order of preference.
_DB_PATHS = [
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/wireshark/manuf",
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/arp-scan/ieee-oui.txt",
]

# Always-on fallback: vendors that matter for *flagging*, keyed by 6-hex OUI.
# Curated, not exhaustive — the system DB fills in the long tail.
_CURATED: dict[str, str] = {
    # ---- Cameras / surveillance / DVR ----
    "00408C": "Axis Communications (camera)",
    "ACCC8E": "Axis Communications (camera)",
    "00408F": "Axis Communications (camera)",
    "B8A44F": "Axis Communications (camera)",
    "001C27": "Hikvision (camera)",
    "C0560E": "Hikvision (camera)",
    "4CBD8F": "Hikvision (camera)",
    "BCAD28": "Hikvision (camera)",
    "44190B": "Hikvision (camera)",
    "ECC89C": "Hikvision (camera)",
    "28571C": "Dahua Technology (camera)",
    "3C1B9E": "Dahua Technology (camera)",
    "90021B": "Dahua Technology (camera)",
    "E0509D": "Dahua Technology (camera)",
    "001597": "Dahua Technology (camera)",
    "00126E": "Mobotix (camera)",
    "001049": "Foscam / Shenzhen (camera)",
    "00626E": "Foscam (camera)",
    "8CEAC8": "Reolink (camera)",
    "EC71DB": "Reolink (camera)",
    "B0C5CA": "Wyze / IEEE (camera)",
    "2CAA8E": "Wyze Labs (camera)",
    "7C78B2": "Wyze Labs (camera)",
    "44A463": "Ubiquiti (UniFi/camera)",
    "FCECDA": "Ubiquiti (UniFi)",
    "B4FB7E": "Ubiquiti (UniFi)",
    "002722": "Ubiquiti Networks",
    "001D5C": "Arlo / Netgear (camera)",
    "00045F": "Vivotek (camera)",
    "000F7C": "ACTi (camera)",
    "001178": "Geovision (camera/DVR)",
    "000B5F": "Cisco (network)",
    # ---- Voice assistants / streaming / smart home ----
    "44650D": "Amazon (Echo/Alexa)",
    "F0272D": "Amazon (Echo/Alexa)",
    "68374A": "Amazon Technologies",
    "FCA183": "Amazon Technologies",
    "747548": "Amazon (device)",
    "087190": "Amazon (Fire/Echo)",
    "F0EF86": "Google (Nest/Home)",
    "1844E6": "Google (Nest)",
    "D86C63": "Google (Chromecast/Home)",
    "54600A": "Google",
    "DA0D0D": "Google (Cast)",
    "3C5AB4": "Google",
    "20DF B9": "Google",
    "001788": "Philips Hue (bridge)",
    "ECB5FA": "Philips Lighting (Hue)",
    "00170880": "Philips Hue",
    "B0F893": "Sonos (speaker)",
    "5CAAFD": "Sonos (speaker)",
    "949F3E": "Sonos (speaker)",
    "78284F": "Sonos (speaker)",
    "00125A": "Microsoft (Xbox)",
    "7C1E52": "Microsoft",
    "001315": "Sony (PlayStation)",
    "FC0FE6": "Sony Interactive (PS)",
    "00D9D1": "Sony Interactive",
    "98B6E9": "Nintendo",
    "8CCDE8": "Nintendo (Switch)",
    "606BFF": "Ring (doorbell/camera)",
    "0CAE7D": "Texas Instruments (IoT)",
    # ---- Computers / phones / common gear (helps typing, not flagging) ----
    "DCA632": "Raspberry Pi",
    "B827EB": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "28CDC1": "Raspberry Pi",
    "D83ADD": "Raspberry Pi",
    "001451": "Apple",
    "F0DBF8": "Apple",
    "ACBC32": "Apple",
    "A4831E": "Apple",
    "3C2EFF": "Apple",
    "5855CA": "Apple",
    "F4F951": "Apple",
}

# Regexes for the two prevailing DB formats.
_RE_NMAP = re.compile(r"^([0-9A-Fa-f]{6})\s+(.*\S)")          # "0001C8  Vendor"
_RE_MANUF = re.compile(r"^([0-9A-Fa-f:]{8,})\s+(\S.*)")        # "00:01:C8  Vendor"
_RE_IEEE = re.compile(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(\S.*)")


class OuiDB:
    """Lazy-loaded vendor database. Construct once, reuse for every lookup."""

    def __init__(self) -> None:
        self._table: dict[str, str] = dict(_CURATED)
        self.source = "curated"
        self._load_system_db()

    def _load_system_db(self) -> None:
        for path in _DB_PATHS:
            if not os.path.isfile(path):
                continue
            added = self._load_file(path)
            if added:
                self.source = path
                return  # first usable DB wins; curated entries already seeded

    def _load_file(self, path: str) -> int:
        added = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    key = vendor = None
                    m = _RE_IEEE.match(line)
                    if m:
                        key = m.group(1).replace("-", "").upper()
                        vendor = m.group(2).strip()
                    else:
                        m = _RE_MANUF.match(line)
                        if m and ":" in m.group(1):
                            key = m.group(1).replace(":", "").upper()[:6]
                            vendor = m.group(2).split("\t")[0].strip()
                        else:
                            m = _RE_NMAP.match(line)
                            if m:
                                key = m.group(1).upper()
                                vendor = m.group(2).strip()
                    if key and vendor and len(key) == 6:
                        # Don't clobber a curated (camera-aware) label.
                        self._table.setdefault(key, vendor)
                        added += 1
        except OSError:
            return 0
        return added

    def lookup(self, mac: str) -> str:
        key = normalize(mac)[:6]
        if not key:
            return ""
        return self._table.get(key, "")

    def __len__(self) -> int:
        return len(self._table)


def normalize(mac: str) -> str:
    """Strip separators, upper-case, keep hex only."""
    return re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()


def is_randomized(mac: str) -> bool:
    """True for locally-administered MACs (phones' privacy/random addresses).

    The U/L bit is bit 1 of the first octet; when set the address was not
    issued by the IEEE to a manufacturer — i.e. it's software-chosen.
    """
    n = normalize(mac)
    if len(n) < 2:
        return False
    try:
        first = int(n[:2], 16)
    except ValueError:
        return False
    return bool(first & 0b10) and not bool(first & 0b01)


def is_multicast(mac: str) -> bool:
    n = normalize(mac)
    if len(n) < 2:
        return False
    try:
        return bool(int(n[:2], 16) & 0b01)
    except ValueError:
        return False
