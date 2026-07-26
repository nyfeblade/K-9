"""Terminal rendering, JSON export, and cross-scan device memory.

The persistence layer is what makes "tell me what's *new* on this network"
work: we remember every MAC we've ever seen on a given network (keyed by the
gateway MAC so "home" and "the coffee shop" stay separate) along with when we
first and last saw it. A device whose MAC we've never recorded for this network
gets the NEW flag.
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from dataclasses import asdict

from . import classify
from .discovery import Host

# ----------------------------------------------------------------- ANSI colours

_USE_COLOR = os.environ.get("NO_COLOR") is None and os.isatty(1) if hasattr(os, "isatty") else True


def _c(code: str, s: str) -> str:
    if not _USE_COLOR:
        return s
    return f"\033[{code}m{s}\033[0m"


def red(s):     return _c("91", s)
def green(s):   return _c("92", s)
def yellow(s):  return _c("93", s)
def blue(s):    return _c("94", s)
def magenta(s): return _c("95", s)
def cyan(s):    return _c("96", s)
def grey(s):    return _c("90", s)
def bold(s):    return _c("1", s)
def on_red(s):  return _c("1;97;41", s)


_CATEGORY_ICON = {
    "camera": "📷", "voice": "🎙", "media": "📺", "printer": "🖨",
    "network": "📶", "computer": "💻", "mobile": "📱", "iot": "🔌",
    "unknown": "❓",
}

_FLAG_STYLE = {
    "CAMERA": red, "SURVEILLANCE": red, "CAMERA?": yellow, "MIC": magenta,
    "HIDDEN": yellow, "UNKNOWN": yellow, "INSECURE": red, "EXPOSED": red,
    "REMOTE": red, "ISP-MGMT": grey, "RANDOM-MAC": grey, "NEW": cyan,
    "ROUTER": blue,
}


def style_flag(flag: str) -> str:
    fn = _FLAG_STYLE.get(flag, yellow)
    return fn(f"[{flag}]")


# --------------------------------------------------------------- persistence

def _store_path() -> str:
    base = os.environ.get("VIPERSCAN_HOME") or os.path.expanduser("~/.viperscan")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "known_devices.json")


def _resolve_netkey(store: dict, gateway_mac: str, cidr: str) -> str:
    """A *stable* per-network bucket key.

    Prefer the gateway MAC (distinguishes two networks that share a CIDR, e.g.
    home vs. a café both on 192.168.1.0/24). But if this particular scan didn't
    manage to read the gateway's MAC, DON'T invent a new bucket — reuse the
    existing bucket for this CIDR, otherwise every device would look brand-new.
    """
    if gateway_mac:
        return gateway_mac.lower()
    for key, val in store.items():
        if val.get("label") == cidr:
            return key
    return f"net:{cidr}"


# Guards every read-modify-write of the device store (the scan loop and the
# /api/annotate request thread both mutate it). Re-entrant so a holder can call
# save_store() while holding it.
STORE_LOCK = threading.RLock()


def load_store() -> dict:
    try:
        with open(_store_path()) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def save_store(store: dict) -> None:
    # Atomic write: never leave a half-written JSON file behind on a crash or a
    # concurrent reader, even though STORE_LOCK already serialises writers.
    path = _store_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(store, fh, indent=2)
        os.replace(tmp, path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def apply_memory(hosts: list[Host], gateway_mac: str, cidr: str, now: float) -> dict:
    """Mark NEW devices and update first/last-seen. Serialised against other
    writers (e.g. /api/annotate) so concurrent read-modify-writes can't corrupt
    the store."""
    with STORE_LOCK:
        return _apply_memory_locked(hosts, gateway_mac, cidr, now)


def _apply_memory_locked(hosts: list[Host], gateway_mac: str, cidr: str, now: float) -> dict:
    store = load_store()
    netkey = _resolve_netkey(store, gateway_mac, cidr)
    net = store.setdefault(netkey, {"label": cidr, "devices": {}})
    devices = net["devices"]
    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(now))

    # First contact with this network: everything is "new", which is just
    # noise. Record a baseline silently — NEW only means something on a
    # network we've scanned before.
    first_contact = len(devices) == 0

    # Index existing records by IP so we can still recognise a device on a scan
    # where its MAC didn't resolve (the ARP cache lags on rapid rescans).
    by_ip = {}
    for k, rec in devices.items():
        ip = rec.get("ip")
        if ip and ip not in by_ip:
            by_ip[ip] = k

    for h in hosts:
        mac = (h.mac or "").lower()
        # Couldn't read a MAC this scan? Carry forward the one we recorded for
        # this IP — keeps identity (and the displayed MAC) stable.
        if not mac and h.ip in by_ip and devices[by_ip[h.ip]].get("mac"):
            mac = devices[by_ip[h.ip]]["mac"]
            h.mac = mac

        key = mac or h.ip.lower()
        rec = devices.get(key)
        if rec is None and h.ip in by_ip:   # fall back to matching by IP
            cand_key = by_ip[h.ip]
            cand = devices[cand_key]
            cand_mac = (cand.get("mac") or "").lower()
            # Only adopt the IP match if the MACs don't actively disagree —
            # otherwise a new device that grabbed a recycled IP would hijack the
            # previous device's identity/annotations. Different MAC ⇒ new device.
            if not mac or not cand_mac or cand_mac == mac:
                key, rec = cand_key, cand

        if rec is None:
            h.is_new = not first_contact
            h.first_seen = stamp
            h.last_seen = stamp
            if not first_contact:
                classify._add_flag(h, "NEW", "First time this device has been seen on this network")
            devices[key] = {
                "ip": h.ip, "mac": h.mac, "name": h.hostname or h.device_type,
                "vendor": h.vendor, "first_seen": stamp, "last_seen": stamp,
            }
        else:
            h.first_seen = rec.get("first_seen", stamp)
            h.last_seen = stamp
            rec["last_seen"] = stamp
            rec["ip"] = h.ip
            if h.mac and not rec.get("mac"):
                rec["mac"] = h.mac
            if h.hostname:
                rec["name"] = h.hostname
            if h.vendor:
                rec["vendor"] = h.vendor

        # Overlay persisted user annotations onto the host, and maintain a
        # first/last-seen history for each open port (the finding/port timeline).
        rec = devices[key]
        h.user_label = rec.get("user_label", "")
        h.tags = list(rec.get("tags", []))
        h.note = rec.get("note", "")
        h.trust = rec.get("trust", "")
        # A device you've named is identified by definition — it's no longer
        # "unknown", so drop the UNKNOWN flag (and its reason).
        if h.user_label and "UNKNOWN" in h.flags:
            h.flags.remove("UNKNOWN")
            h.flag_reasons = [r for r in h.flag_reasons if "could not identify" not in r.lower()]
        ph = rec.setdefault("ports_seen", {})
        for p in (h.open_ports or {}):
            ps = str(p)
            if ps in ph:
                ph[ps]["last"] = stamp
            else:
                ph[ps] = {"first": stamp, "last": stamp}
        h.ports_seen = dict(ph)
    save_store(store)
    return store


# --------------------------------------------------------------- rendering

def _ip_key(ip: str):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def _name_for(h: Host) -> str:
    # A name you set by hand always wins.
    if getattr(h, "user_label", ""):
        return h.user_label
    # The gateway is prone to mDNS reflection (it re-announces other hosts'
    # names with its own source IP), so never let a discovered service name
    # win for it — use its reverse-DNS name or just call it the gateway.
    if h.is_gateway:
        return h.hostname or h.device_type
    # Best display name: explicit service name > hostname > device type.
    for k in ("ssdp_name", "mdns_name", "ssdp_model", "netbios", "snmp_name"):
        if h.services.get(k):
            return h.services[k]
    return h.hostname or h.device_type


def render(hosts: list[Host], meta: dict) -> str:
    hosts = sorted(hosts, key=lambda h: _ip_key(h.ip))
    alerts = [h for h in hosts if classify.is_alert(h)]
    cameras = [h for h in hosts if h.category == "camera"]
    lines: list[str] = []

    width = 64
    lines.append("")
    lines.append(bold(cyan("  ╔" + "═" * width + "╗")))
    title = "ViperScan — network device awareness"
    lines.append(bold(cyan("  ║")) + bold(f"  {title}".ljust(width)) + bold(cyan("║")))
    lines.append(bold(cyan("  ╚" + "═" * width + "╝")))
    lines.append("")
    lines.append(
        f"  Network   {bold(meta['cidr'])}   via {meta.get('iface','?')}"
        f"   gw {meta.get('gateway','?')}"
    )
    lines.append(
        f"  Scanned   {meta['scanned']} addresses in {meta['elapsed']:.1f}s"
        f"   ·  {bold(str(len(hosts)))} live"
        f"   ·  {red(str(len(alerts)))} flagged"
        f"   ·  {red(str(len(cameras)))} camera(s)"
    )
    lines.append(f"  Vendor DB {grey(meta.get('oui_source','?'))}")
    lines.append("")

    # ---- the table ----
    lines.append(bold("  " + _row("IP", "DEVICE", "VENDOR", "FLAGS")))
    lines.append(grey("  " + "─" * 100))
    for h in hosts:
        flags = classify.sort_flags(h.flags)
        flag_str = " ".join(style_flag(f) for f in flags) if flags else grey("—")
        icon = _CATEGORY_ICON.get(h.category, "·")
        name = _name_for(h)
        marker = ""
        if h.is_self:
            marker = green(" (this device)")
        elif h.is_gateway:
            marker = blue(" (gateway)")
        dev = f"{icon} {name}{marker}"
        vendor = (h.vendor or "—")
        if "(camera)" in vendor.lower():
            vendor = red(vendor)
        row = _row(h.ip, _clip(dev, 34), _clip(vendor, 24), flag_str, raw_last=True)
        if classify.is_alert(h):
            lines.append("  " + row)
        else:
            lines.append("  " + grey_ip(row, h.ip))

    # ---- spotlight on the flagged devices ----
    if alerts:
        lines.append("")
        lines.append(bold(on_red("  ⚠  DEVICES WORTH A SECOND LOOK  ")))
        lines.append("")
        for h in sorted(alerts, key=lambda x: _ip_key(x.ip)):
            flags = classify.sort_flags(h.flags)
            head = f"  {bold(h.ip)}  {_name_for(h)}"
            if h.mac:
                head += grey(f"  {h.mac}")
            lines.append(head)
            lines.append("     " + " ".join(style_flag(f) for f in flags))
            for reason in h.flag_reasons:
                lines.append(grey(f"       • {reason}"))
            if h.open_ports:
                ports = ", ".join(f"{p}/{lbl}" for p, lbl in list(h.open_ports.items())[:10])
                lines.append(grey(f"       ports: {ports}"))
            # Identity strings recovered by --unhide / --deep probes.
            ident = []
            for k, label in (("snmp", "SNMP"), ("nmap_os", "OS"),
                             ("nmap_services", "services"), ("ssdp_model", "model")):
                if h.services.get(k):
                    ident.append(f"{label}: {h.services[k]}")
            for s in ident:
                lines.append(grey(f"       id · {s}"[:160]))
            lines.append("")
    else:
        lines.append("")
        lines.append(green("  ✓ Nothing flagged — no cameras, hidden hosts or exposed panels detected."))
        lines.append("")

    return "\n".join(lines)


def _row(a, b, c, d, raw_last=False):
    return f"{a:<16}{b:<36}{c:<26}{d}"


def _clip(s: str, n: int) -> str:
    # Clip on *visible* length, ignoring ANSI we may have injected.
    import re
    visible = re.sub(r"\033\[[0-9;]*m", "", s)
    if len(visible) <= n:
        return s
    return visible[: n - 1] + "…"


def grey_ip(row: str, ip: str) -> str:
    return row  # non-alert rows kept plain for readability


# --------------------------------------------------------------- JSON export

def to_json(hosts: list[Host], meta: dict) -> str:
    payload = {"meta": meta, "devices": []}
    for h in sorted(hosts, key=lambda x: _ip_key(x.ip)):
        d = asdict(h)
        d["flags"] = classify.sort_flags(h.flags)
        d["display_name"] = _name_for(h)
        d["is_alert"] = classify.is_alert(h)
        payload["devices"].append(d)
    return json.dumps(payload, indent=2, default=str)
