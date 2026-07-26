"""Per-device history timeline + anomaly surfacing.

Read-only: it reconstructs and presents what ViperScan already recorded across
scans — the monitoring event log (events.jsonl: new_device / new_ports /
internet_exposure / device_left) plus each device's persisted first/last-seen
and per-port open history. No new data is collected here; this is the "when did
it appear, when was it offline, what changed" view over existing evidence.
"""

from __future__ import annotations

import time

# event type -> (default human label, severity) when no detail string is present
_EVENT_LABEL = {
    "new_device": ("Joined the network", "info"),
    "new_ports": ("Opened new port(s)", "info"),
    "internet_exposure": ("Became reachable from the INTERNET", "high"),
    "device_left": ("Left the network", "muted"),
    "default_creds": ("Default credentials worked", "high"),
}

# ports worth calling out by name when first opened
_NOTABLE_PORTS = {21: "FTP", 22: "SSH", 23: "telnet", 80: "web admin",
                  443: "web admin", 554: "RTSP/camera", 3389: "RDP",
                  5555: "ADB", 5900: "VNC", 8080: "web admin", 8443: "web admin"}


def _epoch(ts):
    if not ts:
        return 0.0
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return time.mktime(time.strptime(ts, fmt))
        except (ValueError, TypeError):
            continue
    return 0.0


def _ago(ts, now=None):
    e = _epoch(ts)
    if not e:
        return ""
    secs = max(0.0, (now or time.time()) - e)
    if secs < 90:
        return "just now"
    if secs < 3600:
        return "%d min ago" % (secs / 60)
    if secs < 129600:                       # < 36 h
        return "%d hr ago" % (secs / 3600)
    return "%d days ago" % (secs / 86400)


def device_timeline(ip, dev, events, now=None):
    """Chronological history for one device, plus a summary line."""
    dev = dev or {}
    now = now or time.time()
    entries = []
    fs = dev.get("first_seen")
    if fs:
        entries.append({"ts": fs, "kind": "first_seen", "sev": "info",
                        "label": "First seen on this network"})
    for port, span in (dev.get("ports_seen") or {}).items():
        first = (span or {}).get("first")
        if first:
            note = _NOTABLE_PORTS.get(int(port)) if str(port).isdigit() else None
            entries.append({"ts": first, "kind": "port", "sev": "info",
                            "label": "Port %s opened%s" % (port, " (%s)" % note if note else "")})
    for ev in events:
        if ev.get("ip") != ip:
            continue
        et = ev.get("type", "")
        label, sev = _EVENT_LABEL.get(et, (et.replace("_", " "), "info"))
        entries.append({"ts": ev.get("ts"), "kind": et, "sev": sev,
                        "label": ev.get("detail") or label})
    entries.sort(key=lambda e: _epoch(e.get("ts")))
    deduped = []
    for e in entries:
        if deduped and deduped[-1]["ts"] == e["ts"] and deduped[-1]["label"] == e["label"]:
            continue
        deduped.append(e)

    online = bool(dev.get("icmp_alive") or dev.get("arp_only"))
    # offline windows: a device_left followed by a later rejoin
    gaps, left_ts = [], None
    for e in deduped:
        if e["kind"] == "device_left":
            left_ts = e["ts"]
        elif e["kind"] in ("new_device", "first_seen") and left_ts:
            dur = _epoch(e["ts"]) - _epoch(left_ts)
            if dur > 0:
                gaps.append({"from": left_ts, "to": e["ts"], "hours": round(dur / 3600, 1)})
            left_ts = None
    summary = {
        "ip": ip,
        "first_seen": fs, "first_seen_ago": _ago(fs, now),
        "last_seen": dev.get("last_seen"), "last_seen_ago": _ago(dev.get("last_seen"), now),
        "online": online,
        "days_known": round((now - _epoch(fs)) / 86400, 1) if fs else None,
        "event_count": len([e for e in deduped if e["kind"] not in ("first_seen", "port")]),
        "offline_gaps": gaps[-5:],
        "offline_since": left_ts if (left_ts and not online) else None,
    }
    return {"summary": summary, "entries": deduped[-250:]}


def anomalies(devices, events, now=None):
    """Notable recent patterns worth a second look, newest first."""
    now = now or time.time()
    cat = {d.get("ip"): (d.get("category") or "") for d in (devices or [])}
    name = {d.get("ip"): (d.get("display_name") or d.get("device_type") or d.get("ip"))
            for d in (devices or [])}
    out = []
    for ev in events:
        ip = ev.get("ip", "")
        et = ev.get("type", "")
        ts = ev.get("ts", "")
        e = _epoch(ts)
        hour = time.localtime(e).tm_hour if e else 12
        who = name.get(ip) or ip
        if et == "internet_exposure":
            out.append({"ts": ts, "ip": ip, "sev": "high",
                        "label": "%s became reachable from the internet" % who})
        elif et == "new_ports" and any(t in (ev.get("detail") or "")
                                       for t in (" 23", " 3389", " 5900", " 21", " 22")):
            out.append({"ts": ts, "ip": ip, "sev": "high",
                        "label": "%s opened a remote/admin service — %s" % (who, ev.get("detail", ""))})
        elif et == "device_left" and cat.get(ip) in ("camera", "surveillance"):
            out.append({"ts": ts, "ip": ip, "sev": "medium",
                        "label": "%s (camera) went offline" % who})
        elif et == "new_device" and hour < 6:
            out.append({"ts": ts, "ip": ip, "sev": "medium",
                        "label": "%s appeared overnight (%02d:00)" % (who, hour)})
    out.sort(key=lambda x: _epoch(x["ts"]), reverse=True)
    return out[:40]


def history_export(devices, events, now=None):
    """Compliance-style JSON: each device's identity + full reconstructed timeline,
    plus the raw event log."""
    now = now or time.time()
    devs = []
    for d in (devices or []):
        tl = device_timeline(d.get("ip"), d, events, now)
        devs.append({
            "ip": d.get("ip"), "mac": d.get("mac"), "vendor": d.get("vendor"),
            "display_name": d.get("display_name") or d.get("device_type"),
            "category": d.get("category"), "flags": d.get("flags"),
            "first_seen": d.get("first_seen"), "last_seen": d.get("last_seen"),
            "ports_seen": d.get("ports_seen"),
            "summary": tl["summary"], "timeline": tl["entries"],
        })
    return {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        "tool": "ViperScan", "device_count": len(devs),
        "anomalies": anomalies(devices, events, now),
        "devices": devs,
        "events": [e for e in events if e.get("ts")][-2000:],
    }
