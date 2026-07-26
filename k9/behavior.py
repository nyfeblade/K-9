"""ViperScan's own engine — a passive BEHAVIORAL OBSERVATION core.

This is not a wrapper around any tool. It is ViperScan's "senses": every scan,
keep-alive and activity probe feeds a per-device time-series here, and from that
raw behavior the engine computes things no MAC lookup or nmap scan can:

  * Device DNA      — what a device IS, from how it BEHAVES (presence rhythm,
                      latency regime, port/service stability, chattiness) — works
                      even when the MAC is randomised or the vendor is unknown.
  * Immune System   — each device's learned NORMAL, and deviations from it
                      (new open port, presence flip, latency-regime change, a
                      quiet device suddenly busy).
  * (Bug Hunter / Spatial Radar layer on the same profiles, adding RF + motion.)

Pure stdlib. Persists a rolling window to VIPERSCAN_HOME so the baseline survives
restarts and gets smarter the longer ViperScan runs.
"""

from __future__ import annotations

import json
import os
import statistics
import threading
import time

_LOCK = threading.RLock()
_MAX_OBS = 240          # rolling observations kept per device (~3h at 45s scans)
_MIN_BASELINE = 6       # observations before we trust a baseline


def _store_path() -> str:
    base = os.environ.get("VIPERSCAN_HOME") or os.path.expanduser("~/.viperscan")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "behavior.json")


def _load() -> dict:
    try:
        with open(_store_path()) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _save(store: dict) -> None:
    path = _store_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(store, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def _ports_of(dev: dict) -> list:
    op = dev.get("open_ports") or {}
    out = []
    for p in op:
        try:
            out.append(int(p))
        except (TypeError, ValueError):
            pass
    return sorted(out)


def record(devices: list) -> None:
    """Append a compact behavioral snapshot for every device this scan. Cheap and
    crash-proof — never let observation break the scan loop."""
    now = int(time.time())
    hour = time.localtime(now).tm_hour
    try:
        with _LOCK:
            store = _load()
            seen = set()
            for d in devices or []:
                mac = (d.get("mac") or "").lower()
                key = mac or d.get("ip")
                if not key:
                    continue
                seen.add(key)
                rec = store.setdefault(key, {"first": now, "obs": [], "hours": [0] * 24})
                rec["last"] = now
                rec["ip"] = d.get("ip")
                rec["mac"] = mac
                rec["vendor"] = d.get("vendor") or rec.get("vendor", "")
                rec["category"] = d.get("category") or rec.get("category", "")
                rtt = d.get("rtt_ms")
                rec["obs"].append({
                    "t": now,
                    "rtt": round(float(rtt), 1) if isinstance(rtt, (int, float)) else None,
                    "ports": _ports_of(d),
                    "svc": len(d.get("services") or {}),
                    "alive": bool(d.get("rtt_ms") is not None or d.get("open_ports")),
                })
                rec["obs"] = rec["obs"][-_MAX_OBS:]
                rec["hours"][hour] = rec["hours"][hour] + 1
            # mark devices that were NOT seen this scan as an absence observation
            for key, rec in store.items():
                if key not in seen and rec.get("obs"):
                    if rec["obs"][-1].get("t") != now:
                        rec["obs"].append({"t": now, "rtt": None, "ports": [], "svc": 0, "alive": False})
                        rec["obs"] = rec["obs"][-_MAX_OBS:]
            _save(store)
    except Exception:
        pass


# --------------------------------------------------------------------------- profile

def _profile(rec: dict) -> dict:
    obs = rec.get("obs") or []
    n = len(obs)
    alive = [o for o in obs if o.get("alive")]
    rtts = [o["rtt"] for o in obs if o.get("rtt") is not None]
    prof = {
        "samples": n,
        "uptime_ratio": round(len(alive) / n, 2) if n else 0.0,
        "first_seen": rec.get("first"),
        "last_seen": rec.get("last"),
    }
    if rtts:
        m = statistics.fmean(rtts)
        sd = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
        prof["rtt_mean"] = round(m, 1)
        prof["rtt_cv"] = round(sd / m, 2) if m else 0.0          # variability of latency
        # latency regime: wired-fast / active-wireless / power-saving
        if m < 5 and prof["rtt_cv"] < 0.6:
            prof["link"] = "wired-or-active"
        elif m > 200 or prof["rtt_cv"] > 1.2:
            prof["link"] = "power-saving"
        else:
            prof["link"] = "wireless-active"
    # port stability + the union of every port ever seen
    everywhere = set()
    per_scan = []
    for o in obs:
        ps = set(o.get("ports") or [])
        per_scan.append(ps)
        everywhere |= ps
    prof["ports_ever"] = sorted(everywhere)
    changes = sum(1 for i in range(1, len(per_scan)) if per_scan[i] != per_scan[i - 1])
    prof["port_churn"] = round(changes / n, 2) if n else 0.0
    # presence pattern: always-on vs intermittent
    prof["presence"] = ("always-on" if prof["uptime_ratio"] > 0.9
                        else "intermittent" if prof["uptime_ratio"] > 0.3 else "rare")
    # active hours (top 3 hours it tends to be seen)
    hours = rec.get("hours") or [0] * 24
    if any(hours):
        ranked = sorted(range(24), key=lambda h: -hours[h])
        prof["active_hours"] = [h for h in ranked[:3] if hours[h]]
    return prof


def _dna(rec: dict, prof: dict) -> dict:
    """A behavioral identity + signature, independent of MAC/vendor lookups."""
    link = prof.get("link", "")
    presence = prof.get("presence", "")
    ports = set(prof.get("ports_ever", []))
    cat = rec.get("category", "")
    traits, guess = [], cat or "unknown"
    conf = 30 if cat and cat != "unknown" else 10

    if presence == "always-on":
        traits.append("always-on")
        conf += 10
    if link == "power-saving":
        traits.append("battery/power-save radio")
    if link == "wired-or-active":
        traits.append("wired or always-active")

    # behavioral hints toward a class (heuristic, refines the scan's category)
    if {554, 8554, 80, 443} & ports and presence == "always-on" and link != "wired-or-active":
        traits.append("steady media/stream endpoint")
        if guess in ("unknown", ""):
            guess = "camera?"
            conf += 15
    if {139, 445, 3389, 22} & ports and link == "wired-or-active":
        traits.append("computer-like services")
        if guess in ("unknown", ""):
            guess = "computer?"
            conf += 15
    if {631, 9100, 515} & ports:
        traits.append("printer ports")
        guess = "printer?" if guess in ("unknown", "") else guess
        conf += 20
    if presence == "intermittent" and link in ("power-saving", "wireless-active"):
        traits.append("comes-and-goes (phone/laptop pattern)")

    sig = "%s|%s|p%d|c%.1f" % (link[:1] or "?", presence[:3], len(ports), prof.get("port_churn", 0))
    return {"identity": guess, "confidence": min(95, conf), "traits": traits, "signature": sig}


def _anomalies(rec: dict, prof: dict) -> list:
    """Deviations from this device's learned normal."""
    obs = rec.get("obs") or []
    if len(obs) < _MIN_BASELINE:
        return []
    out = []
    base, recent = obs[:-3] or obs[:-1], obs[-3:]
    base_ports = set()
    for o in base:
        base_ports |= set(o.get("ports") or [])
    new_ports = set()
    for o in recent:
        new_ports |= set(o.get("ports") or [])
    appeared = sorted(new_ports - base_ports)
    if appeared:
        out.append({"sev": "high", "kind": "new_ports",
                    "detail": "newly open: " + ", ".join(map(str, appeared)) +
                              " — a new service came up (compromise, new app, or config change)."})
    # presence flip: an always-on device just went dark
    base_alive = [o for o in base if o.get("alive")]
    if base and len(base_alive) / len(base) > 0.9 and not any(o.get("alive") for o in recent):
        out.append({"sev": "medium", "kind": "went_dark",
                    "detail": "an always-on device just stopped responding (powered off, unplugged, or blocked)."})
    # latency-regime change: wired↔wireless or sudden jump
    rb = [o["rtt"] for o in base if o.get("rtt") is not None]
    rr = [o["rtt"] for o in recent if o.get("rtt") is not None]
    if rb and rr:
        mb, mr = statistics.fmean(rb), statistics.fmean(rr)
        if mb and (mr > mb * 6 or mr < mb / 6):
            out.append({"sev": "low", "kind": "latency_shift",
                        "detail": "latency regime changed (~%.0fms → ~%.0fms) — link type or load shifted." % (mb, mr)})
    return out


def intel(devices: list) -> dict:
    """The whole behavioral picture for the dashboard: per-device DNA + profile +
    anomalies, plus a network-level summary of what ViperScan has learned."""
    with _LOCK:
        store = _load()
    by_key = {}
    for d in devices or []:
        k = (d.get("mac") or "").lower() or d.get("ip")
        if k:
            by_key[k] = d
    rows, all_anoms, learning = [], [], 0
    for key, rec in store.items():
        prof = _profile(rec)
        learning += prof.get("samples", 0)
        dna = _dna(rec, prof)
        anoms = _anomalies(rec, prof)
        live = by_key.get(key) or {}
        rows.append({
            "ip": live.get("ip") or rec.get("ip"),
            "mac": rec.get("mac"),
            "name": live.get("display_name") or live.get("device_type") or rec.get("category") or rec.get("ip"),
            "dna": dna, "profile": prof, "anomalies": anoms,
            "online": bool(live),
        })
        for a in anoms:
            all_anoms.append({**a, "ip": live.get("ip") or rec.get("ip"), "name": rows[-1]["name"]})
    rows.sort(key=lambda r: (-len(r["anomalies"]), -r["profile"].get("samples", 0)))
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    all_anoms.sort(key=lambda a: sev_rank.get(a.get("sev"), 3))
    return {"devices": rows, "anomalies": all_anoms,
            "tracked": len(store), "observations": learning,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S")}


def device_intel(ip: str, mac: str, device: dict) -> dict:
    """Behavioral intel for ONE device (for its modal)."""
    with _LOCK:
        store = _load()
    rec = store.get((mac or "").lower()) or store.get(ip)
    if not rec:
        return {"known": False}
    prof = _profile(rec)
    return {"known": True, "dna": _dna(rec, prof), "profile": prof,
            "anomalies": _anomalies(rec, prof)}
