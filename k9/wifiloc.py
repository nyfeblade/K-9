"""Wi-Fi "hot/cold" device finder — a live signal-strength proximity meter.

Pick a device and walk around: the meter climbs as you get closer. It's the
real way to physically track down a hidden camera or a mystery device. It gives
*relative proximity*, not coordinates — a single antenna can't triangulate.

How it works: put a monitor-mode-capable Wi-Fi adapter into monitor mode, sniff
802.11 frames with a raw AF_PACKET socket, and read each frame's RSSI (signal,
dBm) straight out of the radiotap header — matching the target device's MAC.
Pure stdlib (no scapy). Needs a monitor-capable adapter and root.

Requirements & caveats:
  * needs sudo + an adapter that supports monitor mode (`iw`).
  * monitor mode disconnects that adapter from Wi-Fi — use a 2nd USB adapter to
    stay online, or accept the primary drops while hunting (the dashboard is on
    localhost, so it keeps working).
  * RSSI→distance is rough (walls/orientation/TX-power); trust the *trend*, not
    the absolute number.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

ETH_P_ALL = 0x0003

# radiotap standard fields, in it_present bit order, up to the signal field we
# want: (bit, align, size). DBM_ANTSIGNAL is bit 5 (signed 8-bit dBm).
_RT_FIELDS = [(0, 8, 8), (1, 1, 1), (2, 1, 1), (3, 2, 4), (4, 2, 2), (5, 1, 1)]
_DBM_ANTSIGNAL_BIT = 5


def parse_radiotap_rssi(buf: bytes):
    """Return (rssi_dbm or None, radiotap_len). Walks the present bitmap and the
    field alignment rules to locate the DBM_ANTSIGNAL byte."""
    if len(buf) < 8:
        return None, 0
    _ver, _pad, it_len = struct.unpack_from("<BBH", buf, 0)
    if it_len < 8 or it_len > len(buf):
        return None, it_len
    present = struct.unpack_from("<I", buf, 4)[0]
    pos = 8
    # skip any extended present words (bit 31 chains another u32)
    p = present
    while p & (1 << 31):
        if pos + 4 > len(buf):
            return None, it_len
        p = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
    # walk standard fields up to DBM_ANTSIGNAL
    for bit, align, size in _RT_FIELDS:
        if not (present & (1 << bit)):
            continue
        pos = (pos + (align - 1)) & ~(align - 1)   # align relative to header start
        if bit == _DBM_ANTSIGNAL_BIT:
            if pos < it_len and pos < len(buf):
                return struct.unpack_from("<b", buf, pos)[0], it_len
            return None, it_len
        pos += size
    return None, it_len


def parse_frame(buf: bytes):
    """Return (transmitter_mac, rssi_dbm) for an 802.11 frame, or None."""
    rssi, rtlen = parse_radiotap_rssi(buf)
    if rssi is None or rtlen == 0 or len(buf) < rtlen + 16:
        return None
    src = buf[rtlen + 10:rtlen + 16]
    if len(src) != 6:
        return None
    return ":".join("%02x" % b for b in src), rssi


def _mac(b):
    return ":".join("%02x" % x for x in b)


def parse_frame_full(buf: bytes):
    """Return (transmitter_mac, receiver_mac, addr3_mac, rssi, ftype).

    Length-aware so it also catches CONTROL frames (ACK/CTS/RTS/Block-Ack) — an
    ACK to the device, or a CTS the device sends, reveals its presence on a
    channel even when it's transmitting almost no data. addr1 is always present;
    addr2/addr3 only on mgmt/data frames. RSSI is only meaningful from addr2
    (frames the device itself transmitted), which is what proximity uses.
    ftype: 0=mgmt 1=control 2=data."""
    rssi, rtlen = parse_radiotap_rssi(buf)
    if rtlen == 0 or len(buf) < rtlen + 10:          # need at least FC + dur + addr1
        return None
    ftype = (buf[rtlen] >> 2) & 0x3
    ra = _mac(buf[rtlen + 4:rtlen + 10])             # addr1 (always present)
    if ftype == 1:                                   # control frame: only addr1 is reliable
        return "", ra, "", rssi, ftype
    ta = _mac(buf[rtlen + 10:rtlen + 16]) if len(buf) >= rtlen + 16 else ""   # addr2
    a3 = _mac(buf[rtlen + 16:rtlen + 22]) if len(buf) >= rtlen + 22 else ""   # addr3
    return ta, ra, a3, rssi, ftype


# --------------------------------------------------------------- capability / setup

def _run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def wifi_interfaces():
    """List wireless interfaces and whether each is in monitor mode (via `iw dev`)."""
    out = _run(["iw", "dev"])
    ifaces = {}
    cur = None
    if out:
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                cur = line.split(" ", 1)[1]
                ifaces[cur] = {"type": ""}
            elif line.startswith("type ") and cur:
                ifaces[cur]["type"] = line.split(" ", 1)[1]
    return ifaces


def default_route_iface() -> str:
    out = _run(["ip", "route", "show", "default"])
    if out:
        m = re.search(r"\bdev (\S+)", out.stdout)
        if m:
            return m.group(1)
    return ""


def _freq_to_chan(freq: int):
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:                 # 6 GHz (Wi-Fi 6E)
        return (freq - 5950) // 5
    return None


def current_channel(iface: str):
    """Channel an associated (managed) interface is currently using, via
    `iw dev <iface> link`/`info`. Lets us PRIME the locate survey with the AP's
    channel — most LAN devices share that AP, so we lock on near-instantly
    instead of blind-hopping ~20 channels first."""
    if not iface:
        return None
    for cmd in (["iw", "dev", iface, "link"], ["iw", "dev", iface, "info"]):
        out = _run(cmd)
        if not out:
            continue
        m = re.search(r"freq:?\s*(\d+)", out.stdout)
        if m:
            ch = _freq_to_chan(int(m.group(1)))
            if ch:
                return ch
        m = re.search(r"channel\s+(\d+)", out.stdout)
        if m:
            return int(m.group(1))
    return None


def _iface_phy_map() -> dict:
    """Map wireless interface name → its phy (e.g. wlx... → phy1)."""
    out = _run(["iw", "dev"])
    m, phy = {}, None
    if out:
        for line in out.stdout.splitlines():
            s = line.strip()
            if s.startswith("phy#"):
                phy = "phy" + s[4:]
            elif s.startswith("Interface "):
                m[s.split(" ", 1)[1]] = phy
    return m


def _phy_supports_monitor(phy: str) -> bool:
    out = _run(["iw", "phy", phy, "info"])
    if not out:
        return False
    t = out.stdout
    i = t.find("Supported interface modes")
    seg = t[i:i + 700] if i != -1 else t
    return "* monitor" in seg or "\tmonitor" in seg


def monitor_capable_ifaces() -> list:
    return [ifc for ifc, phy in _iface_phy_map().items() if phy and _phy_supports_monitor(phy)]


def pick_monitor_iface(prefer_secondary: bool = True, allow_primary: bool = False) -> str | None:
    """Auto-pick a monitor-capable adapter. Prefers one that is NOT carrying the
    default route, so we never knock the user offline. Crucially, if the ONLY
    monitor-capable adapter is the primary internet adapter, we return None (not a
    silent fallback) — otherwise unplugging the dedicated A8000 would make Find
    quietly hijack the built-in Wi-Fi and 'scan' on the wrong radio."""
    caps = monitor_capable_ifaces()
    if not caps:
        return None
    primary = default_route_iface()
    secondary = [c for c in caps if c != primary]
    if secondary:
        return secondary[0]
    if allow_primary or not prefer_secondary:
        return caps[0]
    return None


def capability() -> dict:
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    have_iw = shutil.which("iw") is not None
    ifaces = list(_iface_phy_map()) if have_iw else []
    caps = monitor_capable_ifaces() if have_iw else []
    primary = default_route_iface() if have_iw else ""
    recommended = pick_monitor_iface() if have_iw else None
    monitor_now = [n for n, v in (wifi_interfaces() if have_iw else {}).items() if v.get("type") == "monitor"]
    return {
        "root": is_root,
        "iw": have_iw,
        "interfaces": ifaces,
        "monitor_capable": caps,
        "monitor_ifaces": monitor_now,
        "primary": primary,
        "recommended": recommended,
        "ready": bool(is_root and have_iw and recommended),
    }


def monitor_state() -> dict:
    """Lightweight current monitor-mode status for the top-bar toggle button.
    Cheaper than full capability(): one `iw dev` to see which adapters are
    already in monitor mode, plus the recommended sniffer adapter."""
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    have_iw = shutil.which("iw") is not None
    mon = [n for n, v in (wifi_interfaces() if have_iw else {}).items() if v.get("type") == "monitor"]
    rec = pick_monitor_iface() if have_iw else None
    return {"root": is_root, "iw": have_iw, "monitor_ifaces": mon,
            "recommended": rec, "on": bool(mon),
            "iface": (mon[0] if mon else rec)}


def _iface_type(iface: str) -> str:
    """Current 802.11 mode of an interface ('managed' / 'monitor' / …) via iw —
    the ground truth, so we never report success we didn't actually achieve."""
    out = _run(["iw", "dev", iface, "info"])
    if out:
        m = re.search(r"\btype (\w+)", out.stdout)
        if m:
            return m.group(1)
    return ""


def _unblock_rfkill() -> None:
    """Clear any soft rfkill block that would stop the radio coming back up."""
    if shutil.which("rfkill"):
        for cmd in (["rfkill", "unblock", "wifi"], ["rfkill", "unblock", "all"]):
            _run(cmd)


def _rfkill_blocked() -> bool:
    out = _run(["rfkill", "list"]) if shutil.which("rfkill") else None
    return bool(out and re.search(r"blocked:\s*yes", out.stdout, re.I))


def _nm_manages(iface: str) -> bool:
    out = _run(["nmcli", "-t", "-f", "GENERAL.STATE", "device", "show", iface])
    return bool(out and out.stdout and "unmanaged" not in out.stdout.lower())


# A dedicated monitor VIF is THE reliable way to sniff on modern drivers like the
# A8000's mt7921u: they list monitor as a "software interface mode (can always be
# added)" but DON'T include it in the hardware interface-combinations, so switching
# the managed interface's type is rejected — yet adding a separate monitor vif
# always works. We track the vif we create so we can clean it up afterwards.
_VIF_NAME = "vsmon0"
_MON_VIFS: dict = {}        # base iface -> monitor vif we created on it
_LAST_MON_ERR = ""


def current_monitor_iface() -> str:
    """Any interface currently in monitor mode (our vif, or a type-switched one)."""
    for n, v in wifi_interfaces().items():
        if v.get("type") == "monitor":
            return n
    return ""


def _remove_monitor_vif(base: str) -> None:
    vif = _MON_VIFS.pop(base, None) or _VIF_NAME
    if wifi_interfaces().get(vif, {}).get("type") == "monitor":
        _run(["iw", "dev", vif, "del"])


def _free_phy_radio(iface: str, phy: str, keep: str | None = None) -> None:
    """Free a phy's radio so a monitor VIF can actually tune a channel.

    On mt7921u the base managed interface AND NetworkManager's auto-created
    P2P-device interface both sit on the same phy and hold the radio — so a fresh
    monitor vif gets EBUSY ("Device or resource busy") when you set its channel,
    and captures nothing. We evict the P2P-device vif, delete any stale monitor
    vif, and bring the managed base DOWN, leaving the radio free for monitor.

    `keep` is the monitor vif we're CURRENTLY capturing on — never delete it
    (the mid-session self-heal must free the radio WITHOUT killing its own
    capture interface)."""
    _run(["nmcli", "device", "set", "p2p-dev-" + iface, "managed", "no"])
    _run(["iw", "dev", "p2p-dev-" + iface, "del"])
    for n, v in list(wifi_interfaces().items()):
        if v.get("type") == "monitor" and _iface_phy_map().get(n) == phy and n != keep:
            _run(["iw", "dev", n, "del"])
    _run(["ip", "link", "set", iface, "down"])


def set_monitor(iface: str) -> str:
    """Engage monitor mode; return the interface to SNIFF ON ('' on failure).

    Strategy (each VERIFIED via `iw dev info`):
      A. add a dedicated monitor VIF on the adapter's phy — works on mt7921u/
         A8000 and most modern drivers ('monitor' is a software mode that "can
         always be added", even though it's absent from the interface-
         combinations, which is why a plain type-switch is rejected);
      B. fall back to switching the existing interface's type (older adapters).
    Captures the kernel's real error so failures are explainable, not silent."""
    global _LAST_MON_ERR
    _LAST_MON_ERR = ""
    if _iface_type(iface) == "monitor":
        return iface
    _unblock_rfkill()
    _run(["nmcli", "device", "set", iface, "managed", "no"])
    _run(["nmcli", "device", "disconnect", iface])
    errs = []

    # strategy A — dedicated monitor VIF (the reliable path for mt7921u)
    phy = _iface_phy_map().get(iface)
    if phy:
        _free_phy_radio(iface, phy)                         # free the radio first (critical!)
        r = _run(["iw", "phy", phy, "interface", "add", _VIF_NAME, "type", "monitor"])
        if r is not None and r.returncode != 0 and r.stderr:
            errs.append("add-vif: " + r.stderr.strip())
        _run(["ip", "link", "set", _VIF_NAME, "up"])
        if _iface_type(_VIF_NAME) == "monitor":
            # prove the radio is genuinely free by tuning a channel (this is what
            # was failing with EBUSY before we freed it)
            ch = current_channel(default_route_iface()) or 6
            rc = _run(["iw", "dev", _VIF_NAME, "set", "channel", str(ch)])
            if rc is None or rc.returncode == 0:
                _MON_VIFS[iface] = _VIF_NAME
                return _VIF_NAME
            errs.append("set-chan: " + ((rc.stderr or "").strip() or "busy"))
        _run(["iw", "dev", _VIF_NAME, "del"])

    # strategy B — switch the existing interface's type
    def attempt(pre=None):
        _run(["ip", "link", "set", iface, "down"])
        if pre:
            _run(pre)
        r = _run(["iw", "dev", iface, "set", "type", "monitor"])
        if r is not None and r.returncode != 0 and r.stderr:
            errs.append("set-type: " + r.stderr.strip())
        _run(["ip", "link", "set", iface, "up"])
        return _iface_type(iface) == "monitor"

    if attempt():
        return iface
    time.sleep(0.4)
    if attempt(["iw", "dev", iface, "set", "monitor", "none"]):
        return iface

    _LAST_MON_ERR = "; ".join(dict.fromkeys(errs))[:300] or "kernel rejected monitor mode"
    return ""


def set_managed(iface: str) -> None:
    for cmd in (["ip", "link", "set", iface, "down"],
                ["iw", "dev", iface, "set", "type", "managed"],
                ["ip", "link", "set", iface, "up"]):
        _run(cmd)


def monitor_diagnose(iface: str) -> dict:
    """Why monitor mode can't engage on <iface> — drives clear UI errors."""
    return {
        "iface": iface,
        "monitor_capable": iface in monitor_capable_ifaces(),
        "rfkill_blocked": _rfkill_blocked(),
        "nm_managed": _nm_manages(iface),
        "current_type": _iface_type(iface),
        "phy": _iface_phy_map().get(iface, ""),
    }


def _monitor_fail_reason(diag: dict) -> str:
    if not diag.get("monitor_capable"):
        return "this adapter's driver doesn't support monitor mode"
    if diag.get("rfkill_blocked"):
        return "the Wi-Fi radio is rfkill-blocked (run: sudo rfkill unblock all)"
    if _LAST_MON_ERR:
        return "kernel rejected it — " + _LAST_MON_ERR
    if diag.get("nm_managed"):
        return "NetworkManager keeps re-claiming the adapter"
    return "the driver rejected monitor mode (try re-plugging the adapter)"


def enable_monitor(iface: str | None = None) -> dict:
    """Top-bar one-click: engage monitor mode (dedicated VIF), VERIFIED. On
    failure returns the exact kernel reason + a manual command to try."""
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return {"ok": False, "error": "needs_root"}
    if shutil.which("iw") is None:
        return {"ok": False, "error": "needs_iw"}
    iface = iface or pick_monitor_iface()
    if not iface:
        return {"ok": False, "error": "no_adapter",
                "reason": "no monitor-capable Wi-Fi adapter detected — plug in your A8000"}
    existing = current_monitor_iface()
    if existing:
        return {"ok": True, "iface": existing, "already": True, "verified": True}
    cap_if = set_monitor(iface)
    if cap_if:
        return {"ok": True, "iface": cap_if, "base": iface, "verified": True}
    diag = monitor_diagnose(iface)
    _run(["nmcli", "device", "set", iface, "managed", "yes"])      # restore on failure
    phy = _iface_phy_map().get(iface, "phyX")
    return {"ok": False, "error": "monitor_failed", "iface": iface,
            "reason": _monitor_fail_reason(diag), "diag": diag,
            "kernel_error": _LAST_MON_ERR,
            "fix": f"sudo iw phy {phy} interface add {_VIF_NAME} type monitor && "
                   f"sudo ip link set {_VIF_NAME} up"}


def disable_monitor(iface: str | None = None) -> dict:
    """Top-bar one-click: tear down monitor mode and restore normal Wi-Fi —
    deletes any monitor VIF we created and reconnects the base adapter."""
    if shutil.which("iw") is None:
        return {"ok": False, "error": "needs_iw"}
    base = iface or pick_monitor_iface()
    # remove the dedicated monitor vif if present
    if wifi_interfaces().get(_VIF_NAME, {}).get("type") == "monitor":
        _run(["iw", "dev", _VIF_NAME, "del"])
    _MON_VIFS.clear()
    if base:
        if _iface_type(base) == "monitor":          # was type-switched → flip back
            set_managed(base)
        _run(["nmcli", "device", "set", base, "managed", "yes"])
        _run(["nmcli", "device", "connect", base])
    return {"ok": True, "iface": base}


def set_channel(iface: str, channel: int) -> bool:
    r = _run(["iw", "dev", iface, "set", "channel", str(channel)])
    return r is not None and r.returncode == 0


def _chan_to_freq(ch: int):
    if 1 <= ch <= 13:
        return 2412 + (ch - 1) * 5
    if ch == 14:
        return 2484
    if 32 <= ch <= 177:                              # 5 GHz
        return 5000 + ch * 5
    return None


def ap_chan_config(iface: str):
    """The channel + WIDTH the managed adapter's AP is using, e.g.
    {channel:157, width:80, center:5775}. Lets the monitor capture match the AP's
    full bandwidth so it catches every frame on a wide (40/80/160 MHz) channel
    instead of only the primary 20 MHz."""
    text = ""
    for cmd in (["iw", "dev", iface, "info"], ["iw", "dev", iface, "link"]):
        out = _run(cmd)
        if out and out.stdout:
            text += out.stdout + "\n"
    m = re.search(r"channel (\d+)[^\n]*?width:\s*(\d+)\s*MHz(?:[^\n]*?center1:\s*(\d+))?", text)
    if m:
        return {"channel": int(m.group(1)), "width": int(m.group(2)),
                "center": int(m.group(3)) if m.group(3) else None}
    return None


def set_channel_wide(iface: str, channel: int, ap_cfg=None) -> bool:
    """Tune the monitor iface, matching the AP's channel WIDTH when we're on the
    AP's channel (so we hear the whole 40/80/160 MHz, not just 20). Falls back to
    a plain 20 MHz set if the wide set is rejected."""
    if ap_cfg and ap_cfg.get("channel") == channel and ap_cfg.get("width", 20) >= 40:
        freq = _chan_to_freq(channel)
        width, center = ap_cfg["width"], ap_cfg.get("center")
        if freq:
            cmd = ["iw", "dev", iface, "set", "freq", str(freq), str(width)]
            if center:
                cmd.append(str(center))
            r = _run(cmd)
            if r is not None and r.returncode == 0:
                return True
    return set_channel(iface, channel)


def supported_channels(iface: str) -> list:
    """Channels this adapter's phy can actually tune to (excluding ones the
    regulatory domain has disabled), so the survey never dwells on a channel the
    driver silently rejects. Falls back to [] if it can't be determined."""
    phy = _iface_phy_map().get(iface)
    if not phy:
        return []
    out = _run(["iw", "phy", phy, "info"])
    if not out:
        return []
    chans = []
    for line in out.stdout.splitlines():
        if "MHz" not in line or "[" not in line or "disabled" in line:
            continue
        m = re.search(r"\[(\d+)\]", line)
        if m:
            c = int(m.group(1))
            if c not in chans:
                chans.append(c)
    return chans


# --------------------------------------------------------------- RSSI smoothing / distance

class Meter:
    """Exponentially-smoothed RSSI with a recent-trend readout."""

    def __init__(self, alpha=0.35):
        self.alpha = alpha
        self.smooth = None
        self.history = []   # (ts, smoothed)

    def update(self, rssi: int):
        self.smooth = rssi if self.smooth is None else (self.alpha * rssi + (1 - self.alpha) * self.smooth)
        self.history.append((time.time(), self.smooth))
        self.history = self.history[-50:]
        return self.smooth

    def trend(self, window=2.5):
        """+1 getting closer (stronger), -1 farther, 0 steady."""
        if len(self.history) < 2:
            return 0
        now = self.history[-1][0]
        old = next((s for t, s in self.history if now - t <= window), self.history[0][1])
        delta = self.history[-1][1] - old
        return 1 if delta > 1.0 else (-1 if delta < -1.0 else 0)


def rssi_to_distance(rssi: float, tx_at_1m: float = -45.0, n: float = 3.0) -> float:
    """Very rough log-distance path-loss estimate (metres). Indoors n≈3-4."""
    try:
        return round(10 ** ((tx_at_1m - rssi) / (10 * n)), 1)
    except (OverflowError, ValueError):
        return 0.0


def rssi_pct(rssi: float) -> int:
    """Map dBm (-90 far … -30 very close) to a 0–100 proximity bar."""
    return max(0, min(100, round((rssi + 90) / 60 * 100)))


# --------------------------------------------------------------- live JSON bridge

def _locate_path() -> str:
    base = os.environ.get("VIPERSCAN_HOME") or os.path.expanduser("~/.viperscan")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "locate.json")


def write_state(state: dict) -> None:
    try:
        with open(_locate_path(), "w") as fh:
            json.dump(state, fh)
    except OSError:
        pass


def read_state() -> dict:
    try:
        with open(_locate_path()) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


# --------------------------------------------------------------- live capture / CLI

# Channel hop set: 2.4 GHz (1/6/11 weighted) + common 5 GHz channels.
_CHANNELS = [1, 6, 11, 1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161, 2, 3, 4, 5, 7, 8, 9, 10]


def _resolve_target(target: str):
    """Return (mac_lower, label) for an IP or MAC target."""
    if re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", target):
        return target.lower(), target
    from . import discovery, report
    mac = discovery.read_arp_table().get(target, "")
    if not mac:
        for net in report.load_store().values():
            for rec in net.get("devices", {}).values():
                if rec.get("ip") == target and rec.get("mac"):
                    mac = rec["mac"]
                    break
    return (mac.lower() if mac else ""), target


def _render(label, rssi, sm, trend, ch):
    pct = rssi_pct(sm)
    fill = int(40 * pct / 100)
    bar = "█" * fill + "·" * (40 - fill)
    arrow = "🔥 warmer" if trend > 0 else ("❄  colder" if trend < 0 else "•  steady")
    sys.stdout.write(f"\r  [{bar}] {pct:3d}%  {sm:6.1f} dBm  ~{rssi_to_distance(sm)} m  {arrow}  ch{ch or '?'}   ")
    sys.stdout.flush()


def _live_meter(iface, mac, label, fixed_channel=None):
    print(f"  Hunting {label} ({mac}) on {iface}.")
    print("  Walk around — the bar rises as you get CLOSER. Ctrl-C to stop.\n")

    def emit(st):
        if "error" in st:
            print("\n  " + st["error"], file=sys.stderr)
            return
        if st.get("phase") == "tracking" and st.get("rssi_smooth") is not None:
            _render(label, st.get("rssi", 0), st["rssi_smooth"], st.get("trend", 0), st.get("channel"))
            write_state({"ip": label, "mac": mac, **st})
        else:   # surveying / locked-but-no-signal: show diagnostics so you can see it working
            sys.stdout.write("\r  %-10s ch%-4s · frames:%-6d device-matches:%-5d unique-MACs:%-4d   " % (
                "● LOCKED" if st.get("phase") == "locked" else "scanning…",
                str(st.get("channel", "?")), st.get("frames", 0), st.get("hits", 0), st.get("unique_macs", 0)))
            sys.stdout.flush()

    capture(iface, mac, lambda: False, emit, fixed_channel=fixed_channel)


def run_cli(args) -> int:
    target = args.locate
    mac, label = _resolve_target(target)
    cap = capability()
    if not mac:
        print(f"ViperScan: no MAC found for '{target}'. Pass the MAC directly, or run a scan first.", file=sys.stderr)
        return 1
    if not cap["iw"]:
        print("ViperScan locate needs the `iw` tool — install it (e.g. `sudo apt install iw`).", file=sys.stderr)
        return 1
    if not cap["root"]:
        print("ViperScan locate needs root for monitor mode. Re-run with sudo, e.g.:", file=sys.stderr)
        print(f"   sudo python3 {sys.argv[0]} --locate {target}", file=sys.stderr)
        return 1
    iface = args.iface or pick_monitor_iface(allow_primary=bool(args.iface))
    if not iface:
        print("ViperScan locate: no DEDICATED monitor adapter found. Plug in your A8000 "
              "(or pass --iface <dev> to force your built-in Wi-Fi, which will drop your internet).",
              file=sys.stderr)
        return 1
    if iface == cap.get("primary"):
        print(f"  Note: {iface} is your active connection — monitor mode will drop it.")
    existing = current_monitor_iface()
    created = False
    if existing:
        capiface = existing
        print(f"  Using existing monitor interface {capiface}.")
    else:
        print(f"  Preparing {iface} (monitor mode via dedicated VIF)…")
        capiface = set_monitor(iface)
        if not capiface:
            print(f"ViperScan locate: couldn't engage monitor mode on {iface}: "
                  f"{_LAST_MON_ERR or 'driver rejected it'}.", file=sys.stderr)
            _run(["nmcli", "device", "set", iface, "managed", "yes"])
            return 1
        created = True
        print(f"  Monitor mode engaged on {capiface}.")
    waker = start_waker(label)   # ping + TCP knocks so the device keeps transmitting
    try:
        _live_meter(capiface, mac, label, args.channel)
    except KeyboardInterrupt:
        print("\n  stopped.")
    except OSError as exc:
        print(f"\n  capture error: {exc}", file=sys.stderr)
    finally:
        stop_waker(waker)
        write_state({})
        if created:
            print("  Restoring managed mode…")
            _remove_monitor_vif(iface)
            if _iface_type(iface) == "monitor":
                set_managed(iface)
            _run(["nmcli", "device", "set", iface, "managed", "yes"])
            _run(["nmcli", "device", "connect", iface])
    return 0


# --------------------------------------------------------------- auto-pinger

def start_pinger(ip: str):
    """Continuously ping an IP to keep the device awake and transmitting (so we
    can actually hear its frames). Routes out the normal interface, not the
    monitor one. Returns a Popen handle, or None."""
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip or ""):
        return None
    try:
        return subprocess.Popen(["ping", "-n", "-i", "0.3", ip],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return None


def stop_pinger(proc) -> None:
    if proc is not None:
        try:
            proc.terminate()
        except OSError:
            pass


# Ports we knock to provoke a transmitted frame. A closed port still answers
# with a TCP RST — itself a data frame the *device* transmits (addr2 = device),
# which is exactly what we need to hear its MAC + RSSI.
_WAKE_PORTS = [80, 443, 8080, 22, 23, 554, 8443, 8000, 8888, 9000, 8081, 49152]


def start_waker(ip: str, stealth: bool = True):
    """Keep the target transmitting DATA frames so we can hear its MAC + signal.

    STEALTH (default): ICMP echo only. The device's kernel auto-replies to a ping
    and nothing on the device logs it (no service sees a connection). We send a
    fast small ping plus a large-payload ping so each reply is a big, easy-to-
    catch 802.11 frame. With stealth off we ALSO rotate TCP knocks to common
    ports (louder, services may log the connection) for stubborn devices."""
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip or ""):
        return None
    stop = threading.Event()
    procs = []
    for args in (["ping", "-n", "-i", "0.2", ip],
                 ["ping", "-n", "-i", "0.5", "-s", "1400", ip]):
        try:
            procs.append(subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        except OSError:
            pass

    t = None
    if not stealth:
        def knock():
            while not stop.is_set():
                for p in _WAKE_PORTS:
                    if stop.is_set():
                        break
                    try:
                        k = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        k.settimeout(0.4)
                        k.connect_ex((ip, p))
                        k.close()
                    except OSError:
                        pass
                    stop.wait(0.1)
                stop.wait(0.3)
        t = threading.Thread(target=knock, daemon=True)
        t.start()
    return {"procs": procs, "stop": stop, "thread": t}


def stop_waker(handle) -> None:
    if not handle:
        return
    handle["stop"].set()
    for p in handle.get("procs", []):
        try:
            p.terminate()
        except OSError:
            pass


# --------------------------------------------------------------- stealthy RTS injection

# Radiotap header for injection: present = RATE(bit2) + TX_FLAGS(bit15); rate=1Mbit
# (2 x 500kbps), TX_FLAGS=0x0008 (NO_ACK). Many mac80211 drivers need the TX-flags
# field present to actually transmit an injected frame.
_RADIOTAP_TX = b"\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x08\x00"


def _iface_mac(iface: str) -> str:
    try:
        with open("/sys/class/net/%s/address" % iface) as fh:
            return fh.read().strip()
    except OSError:
        return "02:00:00:00:00:01"


def _mac_bytes(macstr: str) -> bytes:
    try:
        return bytes(int(x, 16) for x in macstr.split(":"))
    except (ValueError, AttributeError):
        return b"\x02\x00\x00\x00\x00\x01"


def build_rts(device_mac: str, our_mac: str) -> bytes:
    """An 802.11 RTS addressed to the device. Its Wi-Fi chip answers with a CTS
    at the MAC layer (firmware — the device OS never sees it, nothing logs it),
    and that CTS is transmitted BY the device, so we can read its RSSI. RTS/CTS
    is ordinary control traffic, not an attack."""
    fc = b"\xb4\x00"          # type=control, subtype=RTS
    dur = b"\x3c\x00"         # duration ~60us
    return _RADIOTAP_TX + fc + dur + _mac_bytes(device_mac) + _mac_bytes(our_mac)


# --------------------------------------------------------------- server-side session (one-click Find)

# Preferred survey order: 2.4 GHz first (most IoT/cameras), then common 5 GHz.
_SURVEY = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161, 165]
# 2.4 GHz fillers so we cover every channel a device might sit on.
_SURVEY_24_FILL = [2, 3, 4, 5, 7, 8, 9, 10, 13]


# Per-device channel memory: once we hear a device on a channel, remember it so
# re-locating that same device later goes STRAIGHT to its channel instead of
# blind-sweeping (the #1 reason re-finding a known device was hit-and-miss).
def _chan_store_path() -> str:
    base = os.environ.get("VIPERSCAN_HOME") or os.path.expanduser("~/.viperscan")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "locate_channels.json")


def _load_chan_store() -> dict:
    try:
        with open(_chan_store_path()) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def remember_channel(mac: str, channel) -> None:
    if not mac or not channel:
        return
    d = _load_chan_store()
    d[mac.lower()] = {"channel": int(channel), "ts": int(time.time())}
    try:
        with open(_chan_store_path(), "w") as fh:
            json.dump(d, fh)
    except OSError:
        pass


def known_channel(mac: str):
    e = _load_chan_store().get((mac or "").lower())
    return e.get("channel") if e else None


# Channel preference by device CLASS. Cameras / IoT / smart-home / printers are
# overwhelmingly 2.4 GHz (range + cheap radios); computers / phones / TVs / consoles
# are usually 5 GHz. So we don't waste time flipping through the wrong band.
_CH_24_PRIMARY = [1, 6, 11]
_CH_24_REST = [2, 3, 4, 5, 7, 8, 9, 10, 13]
_CH_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
_CAT_24 = ("camera", "voice", "printer", "iot", "smart", "doorbell", "sensor",
           "plug", "bulb", "light", "thermostat", "lock", "speaker", "hub")
_CAT_5 = ("computer", "laptop", "phone", "mobile", "media", "tv", "console", "stream")


def _band_for_category(category):
    """Return '24', '5', or '' (unknown) for a device class."""
    cat = (category or "").lower()
    if any(k in cat for k in _CAT_24):
        return "24"
    if any(k in cat for k in _CAT_5):
        return "5"
    return ""


def _category_channel_order(category):
    """Channel order biased to where this device CLASS most likely lives."""
    band = _band_for_category(category)
    if band == "24":
        return _CH_24_PRIMARY + _CH_24_REST + _CH_5            # camera/IoT: 2.4 hard-first
    if band == "5":
        return _CH_5 + _CH_24_PRIMARY + _CH_24_REST            # computer/phone: 5 GHz first
    return _CH_24_PRIMARY + _CH_5 + _CH_24_REST                # unknown: balanced, 2.4-leaning


def _build_survey(iface, fixed_channel, mac=None, category=None):
    """Survey order tailored to (1) the channel we last HEARD this exact device on,
    (2) the band/channels its DEVICE TYPE most likely uses (cameras→2.4, computers→
    5 GHz), and (3) the AP channel — but only promoted if it's the right band for
    this device class. Only channels the adapter supports are ever dwelt on."""
    if fixed_channel:
        return [fixed_channel]
    sup = supported_channels(iface)

    def ok(c):
        return c and (not sup or c in sup)

    primed = []
    kc = known_channel(mac) if mac else None
    if ok(kc):
        primed.append(kc)                        # strongest signal: where we heard THIS device before
    band = _band_for_category(category)
    # the AP channel our laptop is on — promote it only if it matches the device's band
    for prim in ({default_route_iface()} | set(monitor_capable_ifaces())):
        if prim and prim != iface:
            ac = current_channel(prim)
            if ok(ac) and ac not in primed:
                ac_is_24 = ac <= 14
                if band == "" or (band == "24") == ac_is_24:
                    primed.append(ac)            # right band (or unknown) → try the AP channel early
                # else (e.g. camera but AP is 5 GHz): skip — it'll come later
            break
    ordered = list(primed)
    ordered += [c for c in _category_channel_order(category) if ok(c) and c not in ordered]
    if sup:
        ordered += [c for c in sup if c not in ordered]       # finally, any remaining supported channel
    else:
        ordered += [c for c in (_SURVEY + _SURVEY_24_FILL) if c not in ordered]
    return ordered or (_SURVEY + _SURVEY_24_FILL)


def capture(iface, mac, stop_check, emit, fixed_channel=None, dwell=1.0, recover=None,
            provoke=False, our_mac=None, category=None):
    """Survey channels to find the target, lock onto its channel, then track its
    RSSI. Emits state dicts (with live diagnostics) continuously.

    Robustness ("foolproof") measures:
      * survey only channels the adapter supports, 2.4 GHz first;
      * match the device on addr1 OR addr2 OR addr3 — detects it whichever way
        traffic flows, so we lock the channel fast even when it's mostly being
        pinged (only addr2 frames give RSSI for proximity);
      * adaptive dwell — speed through the first sweep to find the channel fast,
        then lengthen dwell if a whole sweep finds nothing (slow transmitters);
      * sticky lock — once locked we stay put as long as we hear ANY frame from
        the device within ~22 s (paired with the waker that keeps it talking),
        only re-surveying if it truly goes silent (it changed channel / left)."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((iface, 0))
        s.settimeout(0.25)
    except OSError as exc:
        emit({"error": "capture: %s" % exc})
        return
    mac = (mac or "").lower()
    meter = Meter()
    frames = hits = 0
    macs = set()
    bad = set()                                       # channels the driver won't tune to
    survey = _build_survey(iface, fixed_channel, mac, category)
    ap_cfg = ap_chan_config(default_route_iface())    # so we capture the AP channel at full width
    locked = fixed_channel
    si, cur = 0, survey[0]
    started = time.time()
    dwell_end = last_rssi = last_match = last_emit = 0.0
    sweeps = 0
    ever_tracked = False
    chan_fails = chan_tries = 0
    last_recover = 0.0
    our_mac_l = (our_mac or _iface_mac(iface) or "").lower()
    rts_frame = build_rts(mac, our_mac_l) if provoke else None
    last_rts = 0.0
    inject_ok = True
    _run(["ip", "link", "set", iface, "up"])          # ensure the monitor iface is up
    set_channel_wide(iface, cur, ap_cfg)
    try:
        while not stop_check():
            now = time.time()
            if locked is None and now >= dwell_end:
                # advance to the next channel the driver actually accepts
                nxt = None
                for _ in range(len(survey)):
                    cand = survey[si % len(survey)]; si += 1
                    if si % len(survey) == 0:
                        sweeps += 1                   # finished a full sweep with no lock
                    if cand not in bad:
                        nxt = cand; break
                cur = nxt if nxt is not None else survey[si % len(survey)]
                chan_tries += 1
                pos = (si - 1) % len(survey)          # position of cur within the survey
                if set_channel_wide(iface, cur, ap_cfg):
                    chan_fails = 0                    # reset on success — DFS/no-IR channel
                    #                                   failures must NOT accumulate into a
                    #                                   false "radio busy" self-heal trigger.
                    # CAMP HARD on the top 3 most-likely channels (for a camera those
                    # are its known channel + 1/6/11) EVERY pass — a power-saving device
                    # transmits so rarely a quick hop misses it. We spend ~75% of the
                    # time on the 3 likeliest channels and only quick-scan the rest.
                    if pos == 0:
                        base = 9.0                    # the #1 likeliest channel
                    elif pos <= 2:
                        base = 7.0                    # the other 2 likely channels
                    elif sweeps == 0:
                        base = 1.5                    # quick first scan of the rest
                    else:
                        base = 2.5                    # brief revisit of the rest
                    dwell_end = now + base
                else:
                    bad.add(cur); chan_fails += 1; dwell_end = now   # unsettable → skip immediately
                # self-heal: if NO channel will tune, the radio was re-occupied
                # mid-session — re-free it and retry instead of spinning uselessly.
                if recover and chan_fails >= len(survey) and (now - last_recover) > 8:
                    try:
                        recover()
                    except Exception:
                        pass
                    _run(["ip", "link", "set", iface, "up"])
                    bad.clear(); chan_fails = 0; last_recover = now
                    set_channel_wide(iface, cur, ap_cfg); dwell_end = now + dwell
            # STEALTH PROVOKE: poke the device with an RTS ~every 120ms. Its chip
            # answers with a CTS (firmware-level, unlogged) that we read for RSSI,
            # so even a silent/power-saving device gives us a signal on demand.
            if rts_frame and inject_ok and (now - last_rts) > 0.12:
                try:
                    s.send(rts_frame)
                    last_rts = now
                except OSError:
                    inject_ok = False           # driver won't inject → fall back to passive
            try:
                buf = s.recv(4096)
            except socket.timeout:
                buf = None
            except OSError as exc:
                # the monitor interface went away (adapter unplugged, or NM tore it
                # down) — say so instead of silently freezing on stale numbers.
                emit({"error": "monitor capture stopped — the sniffer adapter "
                               "disappeared (unplugged or reset?) [%s]" % exc})
                break
            if buf:
                frames += 1
                fr = parse_frame_full(buf)
                if fr:
                    ta, ra, a3, rssi, ftype = fr
                    if ta and ta != "ff:ff:ff:ff:ff:ff":
                        macs.add(ta)
                    # The device's CTS reply to our RTS is addressed to US (its
                    # addr1 == our injected TA), so any control frame to our MAC
                    # is the device responding — transmitted BY it, so its RSSI is
                    # the device's signal. Deterministic, no fragile timing.
                    cts_hit = (rts_frame and ftype == 1 and rssi is not None
                               and ra == our_mac_l)
                    if mac in (ta, ra, a3) or cts_hit:
                        hits += 1
                        last_match = now
                        if locked is None:
                            locked = cur                 # heard it here → lock the channel
                            remember_channel(mac, cur)   # so we re-find it instantly next time
                        if (ta == mac or cts_hit) and rssi is not None:
                            last_rssi = now
                            ever_tracked = True
                            sm = meter.update(rssi)
                            emit({"rssi": rssi, "rssi_smooth": round(sm, 1), "pct": rssi_pct(sm),
                                  "distance_m": rssi_to_distance(sm), "trend": meter.trend(),
                                  "channel": locked, "frames": frames, "hits": hits,
                                  "unique_macs": len(macs), "phase": "tracking",
                                  "elapsed": int(now - started), "ts": now,
                                  "via": "cts" if cts_hit else "data"})
                            last_emit = now
            # sticky lock: give up the channel only after a long silence (any frame
            # from the device resets the timer). Once we've actually tracked it we
            # KNOW this is the right channel, so hold on much longer before bailing.
            unlock_after = 45 if ever_tracked else 16
            if locked is not None and fixed_channel is None and last_match and now - last_match > unlock_after:
                locked = None; dwell_end = 0.0; sweeps = 0
            if now - last_emit > 0.6:               # heartbeat so the UI always shows progress
                el = int(now - started)
                # actionable diagnostics so it never spins silently:
                hint = ""
                if chan_tries >= 5 and chan_fails >= chan_tries - 1 and el > 3:
                    hint = "cant_tune"               # radio busy — couldn't set ANY channel
                elif frames == 0 and el > 6:
                    hint = "no_frames"               # adapter isn't really sniffing
                elif locked is None and hits == 0 and el > 22:
                    hint = "not_heard"               # device wired / off / out of range / randomized MAC
                emit({"channel": locked if locked is not None else cur, "frames": frames, "hits": hits,
                      "unique_macs": len(macs), "phase": "locked" if locked is not None else "surveying",
                      "searching": locked is None, "elapsed": el, "hint": hint, "ts": now})
                last_emit = now
    finally:
        try:
            s.close()
        except OSError:
            pass


class LocateSession:
    """Drives the whole locate flow from the (root) web server: auto-detect
    adapter, release it from NetworkManager, monitor mode, auto-ping the target,
    capture RSSI in a thread, and restore everything on stop."""

    def __init__(self):
        self._t = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._state = {}
        self._iface = None          # base adapter (for restore bookkeeping)
        self._capiface = None       # the monitor iface we actually sniff on (vif or base)
        self._restore = False
        self._pinger = None
        self._provoke = False
        self._category = ""
        self.error = ""

    def status(self) -> dict:
        with self._lock:
            running = self._t is not None and self._t.is_alive()
            return {"running": running, "iface": self._capiface or self._iface, "error": self.error,
                    "live": dict(self._state) if (running and self._state.get("ts")) else None}

    def start(self, mac: str, ip: str, iface: str | None = None, channel=None,
              provoke: bool = False, category: str = "") -> dict:
        self.stop()
        self.error = ""
        self._provoke = bool(provoke)
        self._category = category or ""
        cap = capability()
        if not cap["root"]:
            self.error = "needs_root"
            return {"ok": False, "error": "needs_root"}
        if not cap["iw"]:
            self.error = "needs_iw"
            return {"ok": False, "error": "needs_iw"}
        iface = iface or cap.get("recommended")
        if not iface:
            # no DEDICATED monitor adapter present (the A8000 is unplugged, or only
            # the primary internet adapter is monitor-capable) — refuse, don't
            # silently hijack the built-in Wi-Fi.
            self.error = "no_adapter"
            return {"ok": False, "error": "no_adapter",
                    "reason": "no dedicated monitor adapter detected — plug in your A8000 "
                              "(ViperScan won't use your main Wi-Fi for monitor mode, it'd drop your internet)"}
        # ALWAYS do a clean engage — never blindly reuse an existing vif. A
        # lingering vsmon0 may have a busy radio (NetworkManager brought the base
        # adapter back up), which makes set_channel fail on every channel and
        # capture see 0 frames. set_monitor frees the radio, (re)creates the vif,
        # and verifies it can actually tune a channel.
        capiface = set_monitor(iface)                 # returns the vif/iface to sniff on, '' on fail
        if not capiface:
            diag = monitor_diagnose(iface)
            _run(["nmcli", "device", "set", iface, "managed", "yes"])
            self.error = "monitor_failed"
            return {"ok": False, "error": "monitor_failed", "iface": iface,
                    "reason": _monitor_fail_reason(diag), "kernel_error": _LAST_MON_ERR}
        self._restore = True
        # final guard: confirm the sniff interface really is in monitor mode + exists
        if _iface_type(capiface) != "monitor":
            self.error = "monitor_failed"
            return {"ok": False, "error": "monitor_failed", "iface": iface,
                    "reason": "monitor interface vanished right after setup (adapter unplugged?)"}
        self._iface = iface
        self._capiface = capiface
        self._stop.clear()
        with self._lock:
            self._state = {"target": mac, "label": ip}
        self._pinger = start_waker(ip, stealth=True)   # ICMP only — nothing the device logs
        self._t = threading.Thread(target=self._capture, args=(capiface, mac, ip, channel), daemon=True)
        self._t.start()
        return {"ok": True, "iface": capiface, "provoke": self._provoke}

    def _capture(self, iface, mac, label, channel):
        def emit(st):
            if "error" in st:
                with self._lock:
                    self.error = st["error"]
                return
            with self._lock:
                self._state = {**self._state, **st, "target": mac, "label": label}
        base = self._iface
        phy = _iface_phy_map().get(base) if base else None
        # keep=iface so the self-heal frees the radio WITHOUT deleting the vif we sniff on
        recover = (lambda: _free_phy_radio(base, phy, keep=iface)) if (base and phy) else None
        our_mac = _iface_mac(iface)
        capture(iface, mac, self._stop.is_set, emit, fixed_channel=channel, recover=recover,
                provoke=getattr(self, "_provoke", False), our_mac=our_mac,
                category=getattr(self, "_category", ""))

    def stop(self) -> None:
        self._stop.set()
        t = self._t
        if t:
            t.join(timeout=2.5)
        self._t = None
        stop_waker(self._pinger)
        self._pinger = None
        if self._iface and self._restore:
            _remove_monitor_vif(self._iface)                 # delete the vif we created
            if _iface_type(self._iface) == "monitor":        # or flip a type-switched iface back
                set_managed(self._iface)
            _run(["nmcli", "device", "set", self._iface, "managed", "yes"])
            _run(["nmcli", "device", "connect", self._iface])
        self._restore = False
        self._iface = None
        self._capiface = None
        with self._lock:
            self._state = {}
