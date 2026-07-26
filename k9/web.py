"""Live web dashboard — stdlib http.server, no Flask, no build step.

This is the whole app: one command launches it and every mode lives in the
browser. A background thread reruns the scan on a loop using a mutable config
(scan mode, target network, interval) that the page can change on the fly, and
a "scan now" trigger that interrupts the wait. The page polls /api/devices and
redraws. One self-contained HTML/CSS/JS blob, so it's still "copy one folder,
run python3".
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import re as _re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_BUILD_ID = ""   # changes whenever source changes / the server restarts
_TOKEN = ""      # per-session CSRF token; required on state-changing endpoints


def _launcher_path() -> str:
    """Absolute path to the viperscan.py launcher, for copy-paste CLI hints — so
    they work from any directory. (Running `python3 viperscan.py` from the wrong
    folder is the #1 'it crashed' cause; an absolute path side-steps it.)"""
    cand = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "viperscan.py")
    if os.path.isfile(cand):
        return cand
    argv0 = sys.argv[0] if sys.argv else ""
    if argv0 and os.path.isfile(argv0):
        return os.path.abspath(argv0)
    return os.path.expanduser("~/ViperScan/viperscan.py")


_LAUNCHER = _launcher_path()


def _source_mtime() -> float:
    d = os.path.dirname(os.path.abspath(__file__))
    try:
        return max(os.path.getmtime(os.path.join(d, f))
                   for f in os.listdir(d) if f.endswith(".py"))
    except (OSError, ValueError):
        return 0.0


def _free_port(port: int) -> None:
    """Kill whatever holds the TCP port so --reload can take it over."""
    if shutil.which("fuser"):
        subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, timeout=5, check=False)
        time.sleep(0.6)
        return
    try:
        out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if f":{port} " in line:
                m = _re.search(r"pid=(\d+)", line)
                if m:
                    try:
                        os.kill(int(m.group(1)), 15)
                    except OSError:
                        pass
        time.sleep(0.6)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _watch_and_reload(interval=1.0):
    """Re-exec the server when any source file changes (dev mode)."""
    baseline = _source_mtime()
    while True:
        time.sleep(interval)
        try:
            if _source_mtime() > baseline + 0.01:
                print("\n  source changed -> reloading ViperScan...\n")
                try:
                    _LOCATE.stop()
                except Exception:
                    pass
                # Tell the re-exec'd process this is a reload so it does NOT open
                # a fresh browser tab — the existing tab auto-refreshes itself via
                # the build-id check. (Otherwise every file save spawns a new tab.)
                os.environ["VIPERSCAN_RELOADED"] = "1"
                os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception:
            pass

# The official ViperShard logo, bundled with the project so the app stays
# self-contained ("copy one folder, run python3").
_LOGO_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "assets", "ViperShardOfficialLogo-4x.png",
)


def _logo_bytes() -> bytes:
    try:
        with open(_LOGO_PATH, "rb") as fh:
            return fh.read()
    except OSError:
        return b""

from concurrent.futures import ThreadPoolExecutor

from . import activity, audit, auditreport, behavior, bypass, classify, discovery, identity, probe, report, scope, timeline, upnp, wifiloc
from .cli import run_scan

# Server-driven Wi-Fi locate session (one-click Find; active only when the
# dashboard runs as root).
_LOCATE = wifiloc.LocateSession()


def _config_path() -> str:
    base = os.environ.get("VIPERSCAN_HOME") or os.path.expanduser("~/.viperscan")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "dashboard.json")


def _load_saved_config() -> dict:
    try:
        with open(_config_path()) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


_PERSIST_LOCK = threading.Lock()


def _persist_config() -> None:
    try:
        with _LOCK:
            data = dict(_CONFIG)
        # serialize writers (a dedicated lock, NOT _LOCK, so we don't hold the hot
        # state lock across file IO) + write-temp-then-rename so a concurrent writer
        # can never truncate a half-written file.
        with _PERSIST_LOCK:
            path = _config_path()
            tmp = path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(data, fh)
            os.replace(tmp, path)
    except OSError:
        pass

# Previous-scan snapshot for monitoring/change-detection (ip -> state).
_PREV: dict = {}


def _detect_changes(devices: list, exposure: list) -> None:
    """Diff this scan against the last and log monitoring events (new device,
    newly-opened port, new internet-exposure, device left)."""
    global _PREV
    exposed = {m.get("internal_ip") for m in (exposure or [])}
    cur = {}
    for d in devices:
        ip = d.get("ip")
        if not ip:
            continue
        cur[ip] = {
            "mac": d.get("mac", ""),
            "ports": set((d.get("open_ports") or {}).keys()),
            "exposed": ip in exposed,
            "name": d.get("display_name") or d.get("device_type") or "device",
        }
    if _PREV:  # skip the very first scan (that's the baseline, not "changes")
        for ip, c in cur.items():
            prev = _PREV.get(ip)
            if prev is None:
                scope.log_event("new_device", ip, f"{c['name']} ({c['mac'] or 'no MAC'}) joined the network")
                continue
            new_ports = c["ports"] - prev["ports"]
            if new_ports:
                scope.log_event("new_ports", ip, f"{c['name']} opened port(s) {', '.join(sorted(new_ports))}")
            if c["exposed"] and not prev["exposed"]:
                scope.log_event("internet_exposure", ip, f"{c['name']} became reachable from the INTERNET")
        for ip in set(_PREV) - set(cur):
            scope.log_event("device_left", ip, f"{_PREV[ip]['name']} left the network")
    _PREV = cur

# Network-wide UPnP internet-exposure map, cached with a TTL so an audit doesn't
# re-pay the SSDP discovery wait every click.
_EXPOSURE = {"map": [], "ts": 0.0}
_EXPOSURE_TTL = 300.0
_EXPOSURE_LOCK = threading.Lock()


def get_exposure(force: bool = False) -> list:
    # Serialise refreshes so concurrent request threads + the scan loop don't
    # both launch the (slow) UPnP discovery or race on the cache dict.
    with _EXPOSURE_LOCK:
        now = time.time()
        if force or (now - _EXPOSURE["ts"]) > _EXPOSURE_TTL:
            try:
                _EXPOSURE["map"] = upnp.port_mappings(timeout=2.5)
            except Exception:
                _EXPOSURE["map"] = []
            _EXPOSURE["ts"] = now
        return list(_EXPOSURE["map"])

_STATE = {"meta": {}, "devices": [], "scanning": False, "last": 0, "events": []}
_CONFIG = {"mode": "quick", "net": None, "interval": 45.0, "no_nmap": False,
           "keepalive": True, "keepalive_interval": 10.0}
_LOCK = threading.Lock()


def _prom_escape(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _metrics_text():
    """Prometheus text-format exposition of the latest scan (for Grafana/homelab
    monitoring stacks). Read-only counts — no per-device detail leaks."""
    with _LOCK:
        devices = list(_STATE["devices"])
        meta = dict(_STATE["meta"])
        scanning = _STATE.get("scanning")
        last = _STATE.get("last") or 0
    by_flag, by_cat = {}, {}
    online = newc = flagged = ports = 0
    for d in devices:
        if d.get("icmp_alive"):
            online += 1
        if d.get("is_new") or "NEW" in (d.get("flags") or []):
            newc += 1
        if d.get("is_alert"):
            flagged += 1
        ports += len(d.get("open_ports") or {})
        for f in (d.get("flags") or []):
            by_flag[f] = by_flag.get(f, 0) + 1
        cat = d.get("category") or "unknown"
        by_cat[cat] = by_cat.get(cat, 0) + 1
    out = []

    def metric(name, helptext, val, typ="gauge"):
        out.append("# HELP %s %s" % (name, helptext))
        out.append("# TYPE %s %s" % (name, typ))
        out.append("%s %s" % (name, val))

    metric("viperscan_devices_total", "Devices found in the last scan.", len(devices))
    metric("viperscan_devices_online", "Devices that answered ICMP in the last scan.", online)
    metric("viperscan_devices_new", "Devices first seen on this network in the last scan.", newc)
    metric("viperscan_devices_flagged", "Devices carrying at least one alert flag.", flagged)
    metric("viperscan_open_ports_total", "Open ports across all devices.", ports)
    metric("viperscan_scanning", "1 while a scan is in progress, else 0.", 1 if scanning else 0)
    metric("viperscan_last_scan_timestamp_seconds", "Unix time of the last completed scan.", int(last))
    if isinstance(meta.get("elapsed"), (int, float)):
        metric("viperscan_scan_duration_seconds", "Duration of the last scan, seconds.", round(meta["elapsed"], 2))
    if isinstance(meta.get("scanned"), int):
        metric("viperscan_scanned_addresses", "Addresses probed in the last scan.", meta["scanned"])
    out.append("# HELP viperscan_devices_by_flag Devices per flag.")
    out.append("# TYPE viperscan_devices_by_flag gauge")
    for f, n in sorted(by_flag.items()):
        out.append('viperscan_devices_by_flag{flag="%s"} %d' % (_prom_escape(f), n))
    out.append("# HELP viperscan_devices_by_category Devices per category.")
    out.append("# TYPE viperscan_devices_by_category gauge")
    for c, n in sorted(by_cat.items()):
        out.append('viperscan_devices_by_category{category="%s"} %d' % (_prom_escape(c), n))
    return "\n".join(out) + "\n"
_RESCAN = threading.Event()

# State-changing GET endpoints that must carry the per-session token + a loopback
# Host (defeats CSRF + DNS-rebinding). The conditionally-mutating routes (/api/scope
# only with add/remove, /api/audit only with deep/creds) are guarded inline instead.
_GUARDED_PATHS = frozenset({
    "/api/set", "/api/scan", "/api/annotate",
    "/api/locate/start", "/api/locate/stop",
    "/api/sniffer/on", "/api/sniffer/off",
})

def _apply(args, cfg) -> None:
    """Project the live web config onto the argparse namespace run_scan reads."""
    args.net = cfg["net"]
    args.deep = cfg["mode"] in ("deep", "unhide")
    args.unhide = cfg["mode"] == "unhide"
    args.no_nmap = cfg["no_nmap"]


def _wol(mac):
    """Send a Wake-on-LAN magic packet (6×0xFF + 16×the MAC) to the broadcast
    address on the standard WoL ports. Harmless if the device isn't WoL-capable;
    returns True if a well-formed packet was sent."""
    hexmac = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(hexmac) != 12:
        return False
    try:
        payload = b"\xff" * 6 + bytes.fromhex(hexmac) * 16
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for port in (9, 7):                 # 9 = discard (standard WoL), 7 = echo
            try:
                s.sendto(payload, ("255.255.255.255", port))
            except OSError:
                pass
        s.close()
        return True
    except OSError:
        return False


def _wake_device(ip, attempts=4):
    """Wake-on-LAN magic packet (if we know the MAC) + burst-ping + TCP-knock, then
    report whether it came online. WoL first (the real wake), then ICMP (cheap); if
    still silent, knock common TCP ports — that nudges devices that ignore ping."""
    wol_sent = _wol((_find_device(ip) or {}).get("mac"))
    alive = False
    rtt = None
    pings = 0
    knocked = []
    for _ in range(attempts):
        pings += 1
        a, r = discovery._ping(ip, 1.0)
        if a:
            alive, rtt = True, r
            break
    if not alive:
        for p in (80, 443, 8080, 22, 23, 554, 8443, 9000, 8000, 8888, 445, 139):
            k = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            k.settimeout(0.5)
            try:
                if k.connect_ex((ip, p)) == 0:
                    knocked.append(p)
            except OSError:
                pass
            finally:
                try:
                    k.close()
                except OSError:
                    pass
        pings += 1
        a, r = discovery._ping(ip, 1.0)
        if a:
            alive, rtt = True, r
    return {"ip": ip, "alive": alive, "rtt": rtt, "pings": pings,
            "knocked": knocked, "wol": wol_sent, "ts": time.strftime("%H:%M:%S")}


def _keepalive_loop():
    """Constantly ping every discovered device (low rate, ICMP only) so it stays
    in the kernel ARP/neighbour table, keeps answering, and doesn't drop off the
    dashboard or fall asleep between full scans. Gentle: one echo per device per
    cycle, in parallel, skipped while a full scan is already pinging everything."""
    while True:
        interval = 10.0
        try:
            with _LOCK:
                on = _CONFIG.get("keepalive", True)
                interval = float(_CONFIG.get("keepalive_interval", 10.0) or 10.0)
                scanning = _STATE.get("scanning", False)
                ips = [d.get("ip") for d in _STATE["devices"] if d.get("ip")] if on else []
            if on and ips and not scanning:
                with ThreadPoolExecutor(max_workers=min(96, max(4, len(ips)))) as ex:
                    list(ex.map(lambda ip: discovery._ping(ip, 1.0), ips))
        except Exception:
            pass
        time.sleep(max(2.0, interval))


def _scan_forever(args):
    while True:
        with _LOCK:
            cfg = dict(_CONFIG)
            _STATE["scanning"] = True
        _apply(args, cfg)
        try:
            hosts, meta = run_scan(args)
            payload = json.loads(report.to_json(hosts, meta))
            with _LOCK:
                _STATE["meta"] = payload["meta"]
                _STATE["devices"] = payload["devices"]
                _STATE["last"] = time.time()
            # Monitoring: diff against the previous scan and log change events.
            try:
                _detect_changes(payload["devices"], get_exposure())
                with _LOCK:
                    _STATE["events"] = scope.read_events(60)
            except Exception:
                pass
            # Feed ViperScan's own behavioral engine — it learns each device's
            # normal over time (Device DNA + Immune System anomalies).
            try:
                behavior.record(payload["devices"])
            except Exception:
                pass
        except (Exception, SystemExit) as exc:  # keep serving across scan errors
            with _LOCK:
                _STATE["meta"] = {"error": str(exc), "cidr": cfg.get("net") or "?"}
        finally:
            with _LOCK:
                _STATE["scanning"] = False
        # Sleep until the interval elapses OR someone hits "scan now".
        _RESCAN.wait(timeout=max(5.0, cfg["interval"]))
        _RESCAN.clear()


def _update_config(q: dict) -> None:
    with _LOCK:
        mode = q.get("mode", [None])[0]
        if mode in ("quick", "deep", "unhide"):
            _CONFIG["mode"] = mode
        if "interval" in q:
            try:
                _CONFIG["interval"] = max(10.0, min(3600.0, float(q["interval"][0])))
            except ValueError:
                pass
        if "no_nmap" in q:
            _CONFIG["no_nmap"] = q["no_nmap"][0] in ("1", "true", "yes", "on")
        if "keepalive" in q:
            _CONFIG["keepalive"] = q["keepalive"][0] in ("1", "true", "yes", "on")
        if "net" in q:
            val = (q["net"][0] or "").strip()
            if val == "":
                _CONFIG["net"] = None
            else:
                try:
                    ipaddress.ip_network(val, strict=False)
                    _CONFIG["net"] = val
                except ValueError:
                    pass  # reject bad CIDR silently; keep the previous target
    _persist_config()   # remember mode/network/interval across restarts
    if "scan" in q:
        _RESCAN.set()


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _find_device(ip: str) -> dict | None:
    with _LOCK:
        for d in _STATE["devices"]:
            if d.get("ip") == ip:
                return d
    return None


def _annotate_default_creds(ip: str, hit: dict) -> None:
    """Pin a DEFAULT-CREDS finding onto the live device so its card lights up
    until the next scan overwrites state."""
    reason = (f"Factory login still works: {hit['user']} / {hit['password']} "
              f"at {hit['url']}")
    with _LOCK:
        for d in _STATE["devices"]:
            if d.get("ip") == ip:
                flags = d.setdefault("flags", [])
                if "DEFAULT-CREDS" not in flags:
                    flags.insert(0, "DEFAULT-CREDS")
                d["is_alert"] = True
                reasons = d.setdefault("flag_reasons", [])
                if reason not in reasons:
                    reasons.append(reason)
                return


def _annotate_findings(ip: str, res: dict) -> None:
    """Pin critical audit findings onto the live device so its card reflects them
    until the next scan. Maps findings → short card flags."""
    flags_to_add = []
    for f in res.get("findings", []):
        t = f["title"].lower()
        if "default" in t or "factory password" in t:
            flags_to_add.append(("DEFAULT-CREDS", f["title"]))
        elif "camera stream is open" in t:
            flags_to_add.append(("OPEN-CAM", f["title"]))
        elif "exposed to the internet" in t:
            flags_to_add.append(("INTERNET", f["title"]))
        elif "anonymous ftp" in t:
            flags_to_add.append(("OPEN-FTP", f["title"]))
    if not flags_to_add:
        return
    with _LOCK:
        for d in _STATE["devices"]:
            if d.get("ip") == ip:
                flags = d.setdefault("flags", [])
                reasons = d.setdefault("flag_reasons", [])
                for fl, reason in flags_to_add:
                    if fl not in flags:
                        flags.insert(0, fl)
                    if reason not in reasons:
                        reasons.append(reason)
                d["is_alert"] = True
                d["risk"] = res.get("risk")
                return


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def handle(self):
        # The dashboard polls fast; a browser routinely closes a connection
        # mid-reply. That's harmless — swallow the disconnect instead of dumping
        # a BrokenPipe/ConnectionReset traceback to the console.
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self, parsed):
        """Guard for state-changing endpoints: a loopback Host (defeats DNS-rebinding)
        plus the per-session token (defeats CSRF — a malicious page can't read it)."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in ("127.0.0.1", "localhost", "::1"):
            return False
        token = parse_qs(parsed.query).get("t", [""])[0]
        return bool(_TOKEN) and secrets.compare_digest(token, _TOKEN)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in _GUARDED_PATHS and not self._authed(parsed):
            self._json({"error": "forbidden"}, 403)
            return
        if path == "/api/devices":
            with _LOCK:
                self._json({**_STATE, "config": _CONFIG, "build": _BUILD_ID})
        elif path == "/metrics":            # Prometheus scrape target (read-only counts)
            body = _metrics_text().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/selfcheck":
            from . import selfcheck
            self._json(selfcheck.run())
        elif path == "/api/set":
            _update_config(parse_qs(parsed.query))
            with _LOCK:
                self._json({"ok": True, "config": _CONFIG})
        elif path == "/api/scan":
            _RESCAN.set()
            self._json({"ok": True})
        elif path == "/api/panel":
            ip = parse_qs(parsed.query).get("ip", [""])[0]
            dev = _find_device(ip)
            if not _valid_ip(ip):
                self._json({"error": "bad ip"}, 400)
            else:
                self._json(probe.panels(ip, dev.get("open_ports") if dev else None))
        elif path == "/api/audit":
            q = parse_qs(parsed.query)
            ip = q.get("ip", [""])[0]
            deep = q.get("deep", ["0"])[0] in ("1", "true", "yes")
            creds = q.get("creds", ["0"])[0] in ("1", "true", "yes")
            weak = q.get("weak", ["0"])[0] in ("1", "true", "yes")
            if not _valid_ip(ip):
                self._json({"error": "bad ip"}, 400)
            elif (deep or creds) and not self._authed(parsed):
                # Active checks (real logins) are state-changing → require the token.
                self._json({"error": "forbidden"}, 403)
            elif (deep or creds) and not scope.is_authorized(ip):
                # Active checks require the target's network to be in scope.
                self._json({"error": "out_of_scope", "ip": ip,
                            "cidr": scope.suggested_cidr(ip)}, 403)
            else:
                dev = _find_device(ip) or {}
                res = audit.audit(ip, dev, deep=deep, creds=creds, weak=weak, exposure=get_exposure())
                _annotate_findings(ip, res)
                if creds:
                    hit = res.get("default_creds")
                    scope.log_engagement(
                        "weak_password_test" if weak else "factory_password_test", ip,
                        f"cracked {hit['user']}/{hit['password']}" if hit
                        else f"tested {res.get('creds_tested',0)} logins, none worked")
                elif deep:
                    scope.log_engagement("deep_audit", ip,
                                         f"{len(res.get('findings',[]))} findings, risk {res.get('risk',{}).get('score')}")
                self._json(res)
        elif path == "/api/exposure":
            self._json({"mappings": get_exposure(force=("force" in parse_qs(parsed.query)))})
        elif path == "/api/scope":
            q = parse_qs(parsed.query)
            if (q.get("add") or q.get("remove")) and not self._authed(parsed):
                self._json({"error": "forbidden"}, 403)
                return
            if q.get("add"):
                scope.add_cidr(q["add"][0])
            if q.get("remove"):
                scope.remove_cidr(q["remove"][0])
            self._json({"authorized": scope.authorized_list()})
        elif path == "/api/annotate":
            q = parse_qs(parsed.query)
            ip = q.get("ip", [""])[0]
            if not _valid_ip(ip):
                self._json({"error": "bad ip"}, 400)
            else:
                mac = q.get("mac", [""])[0]
                ann = identity.annotate(
                    ip, mac,
                    user_label=q.get("user_label", [None])[0],
                    note=q.get("note", [None])[0],
                    trust=q.get("trust", [None])[0],
                    tags=q.get("tags", [None])[0])
                with _LOCK:
                    for d in _STATE["devices"]:
                        if d.get("ip") == ip:
                            d["user_label"] = ann.get("user_label", "")
                            d["note"] = ann.get("note", "")
                            d["trust"] = ann.get("trust", "")
                            d["tags"] = ann.get("tags", [])
                            if ann.get("user_label"):
                                d["display_name"] = ann["user_label"]
                                if "UNKNOWN" in d.get("flags", []):
                                    d["flags"].remove("UNKNOWN")
                                    d["flag_reasons"] = [r for r in d.get("flag_reasons", []) if "could not identify" not in r.lower()]
                                d["is_alert"] = any(f in classify.ALERT_FLAGS for f in d.get("flags", []))
                            break
                scope.log_engagement("annotate", ip, (ann.get("user_label") or "") + (" [" + ann.get("trust") + "]" if ann.get("trust") else ""))
                self._json(ann)
        elif path == "/api/export":
            with _LOCK:
                payload = json.dumps({"meta": _STATE["meta"], "devices": _STATE["devices"]}, indent=2)
            body = payload.encode()
            scope.log_engagement("export", "", f"{len(_STATE['devices'])} devices")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", 'attachment; filename="viperscan-export.json"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/timeline":
            ip = parse_qs(parsed.query).get("ip", [""])[0]
            if not _valid_ip(ip):
                self._json({"error": "bad ip"}, 400)
            else:
                self._json(timeline.device_timeline(ip, _find_device(ip), scope.read_events(3000)))
        elif path == "/api/history":
            with _LOCK:
                devices = list(_STATE["devices"])
            events = scope.read_events(3000)
            self._json({"anomalies": timeline.anomalies(devices, events),
                        "recent": events[:120]})
        elif path == "/api/history/export":
            with _LOCK:
                devices = list(_STATE["devices"])
            payload = json.dumps(timeline.history_export(devices, scope.read_events(5000)), indent=2)
            body = payload.encode()
            scope.log_engagement("history_export", "", f"{len(devices)} devices")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", 'attachment; filename="viperscan-history.json"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/wake":
            ip = parse_qs(parsed.query).get("ip", [""])[0]
            if not _valid_ip(ip):
                self._json({"error": "bad ip"}, 400)
            else:
                scope.log_engagement("wake", ip, "manual ping/wake")
                self._json(_wake_device(ip))
        elif path == "/api/activity":
            ip = parse_qs(parsed.query).get("ip", [""])[0]
            if not _valid_ip(ip):
                self._json({"error": "bad ip"}, 400)
            else:
                dev = _find_device(ip) or {}
                res = activity.probe(ip, dev)
                res["events"] = [e for e in scope.read_events(300) if e.get("ip") == ip][:8]
                self._json(res)
        elif path == "/api/locate":
            ip = parse_qs(parsed.query).get("ip", [""])[0]
            if not _valid_ip(ip):
                self._json({"error": "bad ip"}, 400)
            else:
                st = _LOCATE.status()
                filest = wifiloc.read_state()      # a CLI finder, if one is running
                filelive = filest if (filest and filest.get("ip") == ip and (time.time() - filest.get("ts", 0)) < 8) else None
                self._json({"capability": wifiloc.capability(),
                            "running": st["running"], "iface": st.get("iface"), "error": st.get("error"),
                            "live": st.get("live") or filelive,
                            "command": f"sudo python3 {_LAUNCHER} --locate {ip}"})
        elif path == "/api/locate/start":
            ip = parse_qs(parsed.query).get("ip", [""])[0]
            if not _valid_ip(ip):
                self._json({"error": "bad ip"}, 400)
            else:
                dev = _find_device(ip) or {}
                mac = (dev.get("mac") or wifiloc._resolve_target(ip)[0] or "").lower()
                provoke = parse_qs(parsed.query).get("provoke", ["0"])[0] in ("1", "true", "yes", "on")
                if not mac:
                    self._json({"ok": False, "error": "no_mac"})
                else:
                    scope.log_engagement("locate", ip, "started Wi-Fi finder" + (" (RTS-provoke)" if provoke else ""))
                    self._json(_LOCATE.start(mac, ip, provoke=provoke,
                                            category=(dev.get("category") or dev.get("device_type") or "")))
        elif path == "/api/locate/stop":
            _LOCATE.stop()
            self._json({"ok": True})
        elif path == "/api/sniffer":
            self._json(wifiloc.monitor_state())
        elif path == "/api/sniffer/on":
            res = wifiloc.enable_monitor()
            if res.get("ok"):
                scope.log_engagement("monitor_mode", res.get("iface", ""), "armed monitor mode (toolbar)")
            self._json(res)
        elif path == "/api/sniffer/off":
            _LOCATE.stop()                       # end any Find session using the adapter
            res = wifiloc.disable_monitor()
            scope.log_engagement("monitor_mode", res.get("iface", ""), "disarmed monitor mode (toolbar)")
            self._json(res)
        elif path == "/api/intel":
            with _LOCK:
                devices = list(_STATE["devices"])
            self._json(behavior.intel(devices))
        elif path == "/api/events":
            self._json({"events": scope.read_events(100)})
        elif path == "/api/engagement":
            self._json({"log": scope.read_engagement(300)})
        elif path == "/api/report":
            with _LOCK:
                devices = list(_STATE["devices"])
                meta = dict(_STATE["meta"])
            html_doc = auditreport.build(devices, meta, get_exposure(), scope.authorized_list())
            scope.log_engagement("report_generated", meta.get("cidr", ""), f"{len(devices)} devices")
            body = html_doc.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/bypass/view":
            vid = parse_qs(parsed.query).get("id", [""])[0]
            v = bypass.read_view(vid)
            if not v:
                self.send_response(404)
                self.end_headers()
                return
            ctype, data = v
            self.send_response(200)
            self.send_header("Content-Type", ctype or "text/html; charset=utf-8")
            # Render the captured page but neutralise it: sandbox blocks its
            # scripts and same-origin access to the dashboard; nosniff stops
            # content-type tricks. It's a snapshot of the bypassed page, not live.
            self.send_header("Content-Security-Policy", "sandbox allow-popups; default-src 'none'; img-src data: *; style-src 'unsafe-inline' *; font-src *")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/logo.png":
            data = _logo_bytes()
            if not data:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Cache-Control", "max-age=86400")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path in ("/", "/index.html"):
            body = PAGE.replace("__LAUNCHER__", _LAUNCHER).replace("__TOKEN__", _TOKEN).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def serve(args) -> int:
    global _BUILD_ID, _TOKEN
    _BUILD_ID = str(int(_source_mtime() * 1000))
    _TOKEN = secrets.token_hex(16)
    reload_on = bool(getattr(args, "reload", False))
    saved = _load_saved_config()
    with _LOCK:
        # CLI flags win when given; otherwise restore the last saved dashboard state.
        _CONFIG["mode"] = "unhide" if args.unhide else ("deep" if args.deep else saved.get("mode", "quick"))
        _CONFIG["net"] = args.net or saved.get("net")
        _CONFIG["interval"] = float(args.watch) if args.watch else float(saved.get("interval", 45.0))
        _CONFIG["no_nmap"] = bool(getattr(args, "no_nmap", False)) or bool(saved.get("no_nmap", False))

    if reload_on:
        _free_port(args.port)   # take over a busy port automatically

    bind = getattr(args, "bind", None) or "127.0.0.1"   # loopback by default — the
    if bind == "0.0.0.0":                                # dashboard exposes host-root
        print("  ⚠ --bind 0.0.0.0: the dashboard is reachable from your LAN. It controls")
        print("    host-level actions — only do this on a trusted, firewalled network.")
    try:
        httpd = ThreadingHTTPServer((bind, args.port), Handler)
    except OSError as exc:
        print(f"\n  ViperScan: can't bind port {args.port} ({exc.strerror}).")
        print(f"  Another ViperScan may already be running — open http://localhost:{args.port}")
        print(f"  or free it:  sudo fuser -k {args.port}/tcp   (or use --reload, or --port {args.port + 1})\n")
        return 1

    with _LOCK:
        # --no-keepalive (when given) forces it off; otherwise restore the saved value
        # like mode/net/interval do (default on). The flag only ever turns it OFF.
        if bool(getattr(args, "no_keepalive", False)):
            _CONFIG["keepalive"] = False
        else:
            _CONFIG["keepalive"] = bool(saved.get("keepalive", True))
    t = threading.Thread(target=_scan_forever, args=(args,), daemon=True)
    t.start()
    threading.Thread(target=_keepalive_loop, daemon=True).start()   # keep devices live
    if reload_on:
        threading.Thread(target=_watch_and_reload, daemon=True).start()
    url = f"http://localhost:{args.port}"
    print(f"\n  ViperScan dashboard live → {url}")
    if reload_on:
        print("  --reload: editing source auto-restarts the server AND auto-refreshes your browser.")
    print("  Ctrl-C to stop.\n")

    if getattr(args, "open", True) and not os.environ.get("VIPERSCAN_RELOADED"):
        # ViperScan needs raw-socket/ARP privileges, so it's normally started with
        # sudo. Launching a GUI browser as root fails — Chromium-based browsers
        # (Edge/Chrome/Chromium) refuse with "Running as root without --no-sandbox
        # is not supported" (the zygote_host error). So when we're root, re-open
        # the tab as the real invoking user; if we can't tell who that is, just
        # print the URL and let them open it.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user:
                threading.Thread(target=lambda: subprocess.run(
                    ["sudo", "-u", sudo_user, "xdg-open", url],
                    capture_output=True, check=False), daemon=True).start()
            else:
                print(f"  (running as root — open the dashboard yourself: {url})")
        else:
            import webbrowser
            threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped.")
    finally:
        _LOCATE.stop()   # restore the adapter if a Find was running
    return 0


PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ViperScan — network device awareness</title>
<link rel="icon" type="image/png" href="/logo.png">
<link rel="shortcut icon" type="image/png" href="/logo.png">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0e0c; --bg2:#0d1311; --card:#0f1513;
    --line:rgba(255,255,255,.09); --txt:#e8edf6; --dim:#8595ad;
    --red:#ff4d5e; --amber:#e0a93b; --cyan:#34e27a; --green:#34e27a;
    --violet:#6a92e8; --blue:#5c86e6;
  }
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    color:var(--txt);background:#080b0a;}
  header{position:sticky;top:0;backdrop-filter:blur(14px);background:rgba(7,11,20,.7);
    border-bottom:1px solid var(--line);padding:14px 22px;display:flex;align-items:center;gap:16px;z-index:5;flex-wrap:wrap}
  .brand{display:flex;align-items:center;gap:10px}
  .logomark{height:28px;width:auto;display:block;filter:drop-shadow(0 2px 8px rgba(0,0,0,.5))}
  .logo{font-weight:800;letter-spacing:.4px;font-size:18px;color:var(--green);font-family:ui-monospace,monospace}
  .pill{font-size:12px;color:var(--dim);border:1px solid var(--line);border-radius:999px;padding:3px 10px}
  .spacer{flex:1}
  .stat{font-size:13px;color:var(--dim)} .stat b{color:var(--txt);font-size:16px}
  .stat.alert b{color:var(--red)} .stat.cam b{color:var(--red)}
  .tools{display:flex;gap:6px;flex-wrap:wrap}
  .tbtn{background:rgba(255,255,255,.06);border:1px solid var(--line);color:var(--txt);border-radius:9px;
    padding:6px 11px;font-size:12.5px;cursor:pointer;transition:.15s}
  .tbtn:hover{border-color:var(--cyan)}
  .tbtn.on{border-color:var(--green);color:var(--green);background:rgba(52,226,122,.13)}
  .tbtn.on .ic{opacity:1}
  .tbtn:disabled{opacity:.55}
  .evrow{border:1px solid var(--line);border-left:3px solid var(--dim);border-radius:8px;padding:8px 11px;margin-bottom:7px;font-size:13px}
  .evrow.ev-new_device{border-left-color:var(--cyan)} .evrow.ev-internet_exposure{border-left-color:var(--red)}
  .evrow.ev-new_ports{border-left-color:var(--amber)} .evrow.ev-device_left{border-left-color:var(--dim)}
  .evt{font-size:10px;font-weight:800;letter-spacing:.4px;text-transform:uppercase;color:var(--dim);margin-right:6px}
  .evts{color:var(--dim);font-size:11px;margin-top:3px;font-variant-numeric:tabular-nums}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);margin-right:6px;
    box-shadow:0 0 10px var(--green)} .dot.busy{background:var(--amber);box-shadow:0 0 10px var(--amber);animation:pulse 1s infinite}
  @keyframes pulse{50%{opacity:.3}}
  main{max-width:1180px;margin:0 auto;padding:22px}

  .controls{display:flex;gap:14px;flex-wrap:wrap;align-items:center;background:var(--card);
    border:1px solid var(--line);border-radius:14px;padding:12px 14px;margin-bottom:16px}
  .ctl{display:flex;align-items:center;gap:8px}
  .ctl-label{font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:var(--dim)}
  .seg{display:flex;border:1px solid var(--line);border-radius:10px;overflow:hidden}
  .seg button{background:transparent;color:var(--dim);border:0;padding:7px 14px;font:inherit;font-size:13px;cursor:pointer;transition:.15s}
  .seg button+button{border-left:1px solid var(--line)}
  .seg button.on{background:rgba(52,226,122,.16);color:var(--txt)}
  .seg button:hover:not(.on){color:var(--txt);background:rgba(255,255,255,.04)}
  input,select{background:#0a1120;color:var(--txt);border:1px solid var(--line);border-radius:9px;
    padding:7px 10px;font:inherit;font-size:13px;outline:none}
  input{width:170px;font-variant-numeric:tabular-nums} input:focus,select:focus{border-color:var(--cyan)}
  .btn{background:rgba(255,255,255,.06);color:var(--txt);border:1px solid var(--line);border-radius:9px;
    padding:7px 13px;font:inherit;font-size:13px;cursor:pointer;transition:.15s}
  .btn:hover{border-color:rgba(255,255,255,.3)}
  .btn.primary{background:var(--green);color:#04111c;font-weight:700;border:0}
  .btn.primary:disabled{opacity:.5;cursor:default}
  .hint{font-size:12px;color:var(--amber);flex-basis:100%;min-height:0}
  .hint:empty{display:none}

  .viewtoggle{display:flex;border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-left:auto}
  .viewtoggle button{background:transparent;color:var(--dim);border:0;padding:6px 13px;font:inherit;font-size:13px;cursor:pointer}
  .viewtoggle button+button{border-left:1px solid var(--line)}
  .viewtoggle button.on{background:rgba(52,226,122,.16);color:var(--txt)}
  #netmap-wrap{position:relative;display:none}
  #netmap{width:100%;height:640px;display:block;border:1px solid var(--line);border-radius:16px;cursor:pointer;
    background:#0a0e0c}
  #maptip{position:absolute;pointer-events:none;background:rgba(7,11,20,.94);border:1px solid var(--line);border-radius:8px;
    padding:6px 10px;font-size:12px;color:var(--txt);display:none;white-space:nowrap;z-index:3;transform:translate(-50%,-130%)}
  .filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px;align-items:center}
  .chip{cursor:pointer;font-size:12.5px;border:1px solid var(--line);border-radius:999px;padding:5px 12px;color:var(--dim);
    background:var(--card);user-select:none;transition:.15s}
  .chip.on{color:var(--txt);border-color:var(--cyan);box-shadow:0 0 0 1px rgba(52,226,122,.3) inset}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:15px 16px;position:relative;
    transition:.18s;overflow:hidden}
  .card:hover{border-color:rgba(255,255,255,.22);transform:translateY(-2px)}
  .card.alert{border-color:rgba(255,93,108,.45);background:rgba(255,77,94,.05)}
  .card.cam::before{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:var(--red)}
  .top{display:flex;align-items:center;gap:10px}
  .ico{font-size:24px;line-height:1}
  .name{font-weight:650;font-size:15.5px}
  .ip{color:var(--dim);font-size:12.5px;font-variant-numeric:tabular-nums}
  .mac{color:var(--dim);font-size:11.5px;font-family:ui-monospace,monospace;margin-top:2px;letter-spacing:.3px}
  .vendor{font-size:12.5px;color:var(--blue);margin-top:6px}
  .flags{display:flex;flex-wrap:wrap;gap:6px;margin-top:11px}
  .flag{font-size:10.5px;font-weight:700;letter-spacing:.5px;padding:3px 8px;border-radius:6px;
    background:rgba(255,255,255,.06);color:var(--dim);border:1px solid var(--line)}
  .flag.CAMERA,.flag.SURVEILLANCE,.flag.INSECURE,.flag.EXPOSED,.flag.REMOTE{background:rgba(255,93,108,.16);color:var(--red);border-color:transparent}
  .flag.CAMERAq,.flag.HIDDEN,.flag.UNKNOWN{background:rgba(255,193,77,.15);color:var(--amber);border-color:transparent}
  .flag.MIC{background:rgba(185,139,255,.16);color:var(--violet);border-color:transparent}
  .flag.NEW{background:rgba(52,226,122,.15);color:var(--cyan);border-color:transparent}
  .flag.ROUTER{background:rgba(90,166,255,.15);color:var(--blue);border-color:transparent}
  .ports{margin-top:10px;font-size:11.5px;color:var(--dim);font-family:ui-monospace,monospace}
  .idline{margin-top:8px;font-size:11.5px;color:var(--green);word-break:break-word}
  details{margin-top:9px} summary{cursor:pointer;font-size:12px;color:var(--dim);outline:none}
  details ul{margin:7px 0 0;padding-left:16px;color:var(--dim);font-size:12px}
  .empty{color:var(--dim);text-align:center;padding:60px 0}
  footer{color:var(--dim);font-size:12px;text-align:center;padding:24px}
  .tag{font-size:11px;color:var(--dim)}
  .card{cursor:pointer}
  .card:after{content:"details ›";position:absolute;right:14px;bottom:12px;font-size:10.5px;color:var(--dim);opacity:0;transition:.15s}
  .card:hover:after{opacity:.7}
  .modal-overlay{position:fixed;inset:0;background:rgba(3,6,12,.66);backdrop-filter:blur(4px);
    display:none;align-items:flex-start;justify-content:center;z-index:50;padding:40px 16px;overflow:auto}
  .modal-overlay.on{display:flex}
  .modal{width:min(680px,100%);background:#0d1311;border:1px solid var(--line);
    border-radius:18px;box-shadow:0 30px 80px rgba(0,0,0,.6);overflow:hidden}
  .m-head{display:flex;align-items:center;gap:12px;padding:18px 20px;border-bottom:1px solid var(--line)}
  .m-ico{font-size:30px;line-height:1}
  .m-title{font-weight:700;font-size:18px}
  .m-ip{color:var(--dim);font-size:12.5px;font-family:ui-monospace,monospace}
  .m-close{margin-left:auto;background:rgba(255,255,255,.06);border:1px solid var(--line);color:var(--txt);
    border-radius:9px;width:32px;height:32px;cursor:pointer;font-size:15px}
  .m-close:hover{border-color:var(--red);color:var(--red)}
  .m-body{padding:18px 20px;display:flex;flex-direction:column;gap:16px}
  .sec h4{margin:0 0 9px;font-size:11px;letter-spacing:.7px;text-transform:uppercase;color:var(--dim);font-weight:700}
  .kv{display:grid;grid-template-columns:118px 1fr;gap:5px 12px;font-size:13.5px}
  .kv .k{color:var(--dim)} .kv .v{color:var(--txt);word-break:break-word}
  .panelrow{display:flex;align-items:center;gap:10px;padding:9px 11px;border:1px solid var(--line);border-radius:10px;margin-bottom:8px}
  .panelrow .u{font-family:ui-monospace,monospace;font-size:12.5px;color:var(--cyan);flex:1;word-break:break-all}
  .panelrow .st{font-size:11px;color:var(--dim);white-space:nowrap}
  .openbtn{background:var(--green);color:#04111c;font-weight:700;border:0;
    border-radius:8px;padding:6px 12px;font-size:12.5px;cursor:pointer;text-decoration:none;white-space:nowrap}
  .badge-best{font-size:9.5px;background:rgba(67,224,160,.2);color:var(--green);padding:2px 7px;border-radius:5px;font-weight:700;letter-spacing:.3px}
  .warn{background:rgba(255,77,94,.1);border:1px solid rgba(255,93,108,.5);
    border-radius:12px;padding:13px 15px;color:#ffd0d5;font-size:13.5px;line-height:1.5}
  .warn b{color:#fff}
  .muted{color:var(--dim);font-size:12.5px}
  .spin{display:inline-block;width:13px;height:13px;border:2px solid var(--line);border-top-color:var(--cyan);
    border-radius:50%;animation:sp .8s linear infinite;vertical-align:-2px;margin-right:7px}
  @keyframes sp{to{transform:rotate(360deg)}}
  .disc{font-size:11px;color:var(--dim);border-top:1px solid var(--line);padding-top:11px}
  .flag.DEFAULTCREDS,.flag.OPENCAM,.flag.INTERNET,.flag.OPENFTP{background:rgba(255,93,108,.16);color:var(--red);border-color:transparent}

  /* ===== UI refinement layer (clean icon system + polish) ===== */
  .ic{width:16px;height:16px;flex:none;display:inline-block;vertical-align:-3px}
  .tbtn,.chip,.btn,.deepbtn,.credbtn,.feedbtn,.openbtn,.seg button,.viewtoggle button{display:inline-flex;align-items:center;gap:7px;line-height:1}
  .tbtn{border-radius:9px;padding:7px 12px;font-weight:500} .tbtn .ic{opacity:.8}
  .chip{font-weight:500} .chip .ic{opacity:.75} .chip.on .ic{opacity:1}
  .countpill{background:rgba(255,255,255,.1);border-radius:999px;padding:1px 7px;font-size:11px;font-weight:700;min-width:18px;text-align:center}
  .ico{width:42px;height:42px;border-radius:12px;display:flex !important;align-items:center;justify-content:center;flex:none;
    background:rgba(133,149,173,.12);color:#9aa7bd;font-size:0}
  .ico .ic{width:21px;height:21px;vertical-align:0;stroke-width:1.7}
  .ico-camera{background:rgba(255,93,108,.13);color:#ff5d6c} .ico-voice{background:rgba(185,139,255,.13);color:#b98bff}
  .ico-media{background:rgba(90,166,255,.13);color:#5aa6ff} .ico-printer{background:rgba(67,224,160,.13);color:#43e0a0}
  .ico-network{background:rgba(52,226,122,.13);color:#34e27a} .ico-computer{background:rgba(154,167,189,.13);color:#aab4c6}
  .ico-mobile{background:rgba(90,166,255,.13);color:#5aa6ff} .ico-iot{background:rgba(255,193,77,.13);color:#ffc14d}
  .ico-unknown,.ico-label{background:rgba(133,149,173,.1);color:#8595ad}
  .m-ico{width:46px !important;height:46px;border-radius:13px;display:flex;align-items:center;justify-content:center;
    background:rgba(133,149,173,.12);font-size:0 !important}
  .m-ico .ic{width:24px;height:24px}
  .sec h4{font-size:10.5px;letter-spacing:.9px;text-transform:uppercase;color:var(--dim);font-weight:600;display:flex;align-items:center;gap:7px;margin:0 0 11px}
  .sec h4 .ic{width:14px;height:14px;opacity:.8}
  .btn.primary .ic,.deepbtn .ic,.credbtn .ic{stroke-width:2}
  .locstats{font-size:13px;color:var(--txt);margin-top:9px;font-variant-numeric:tabular-nums}
  .locstats b{color:var(--cyan)}
  .locctl{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .btn.on{border-color:var(--green);color:var(--green);background:rgba(52,226,122,.13)}
  .lochint{font-size:12.5px;line-height:1.5;margin-top:9px;padding:9px 11px;border-radius:8px;border:1px solid var(--line)}
  .lochint.warn{background:rgba(226,195,78,.08);border-color:rgba(226,195,78,.35);color:#e9d9a0}
  .lochint.bad{background:rgba(255,77,94,.08);border-color:rgba(255,77,94,.4);color:#ffb3bb}
  .bypassbox{margin-top:9px;padding:9px 11px;border-radius:8px;background:rgba(255,77,94,.06);border:1px solid rgba(255,77,94,.3)}
  .bypassacts{display:flex;flex-wrap:wrap;gap:7px}
  .curlrow{display:flex;gap:7px;align-items:flex-start;margin-top:5px}
  .curlcode{flex:1;white-space:pre-wrap;max-height:130px;overflow:auto;margin-top:0}
  .copybtn{flex:0 0 auto}
  body{font-size:14px;letter-spacing:.1px;-webkit-font-smoothing:antialiased}
  header{padding:13px 24px;gap:14px}
  main{padding:24px}
  .card{border-radius:14px;padding:16px 17px;transition:border-color .15s,transform .15s,box-shadow .15s}
  .card:hover{box-shadow:0 10px 34px rgba(0,0,0,.35)}
  .card .name{font-size:15px;letter-spacing:.1px} .card .top{gap:12px}
  .controls{border-radius:13px;padding:13px 15px}
  .modal{border-radius:18px} .m-body{gap:18px}
  .filters{gap:7px}
  .flag{font-weight:600;letter-spacing:.4px}
  .risk{display:flex;align-items:center;gap:14px}
  .ring{--p:0;--rc:var(--green);width:62px;height:62px;border-radius:50%;display:grid;place-items:center;
    background:conic-gradient(var(--rc) calc(var(--p)*3.6deg), rgba(255,255,255,.08) 0)}
  .ring i{width:50px;height:50px;border-radius:50%;background:#0c1422;display:grid;place-items:center;font-style:normal;font-weight:800;font-size:17px}
  .risk .lbl{font-weight:800;text-transform:uppercase;letter-spacing:.5px;font-size:14px}
  .risk .sub{color:var(--dim);font-size:12px}
  .finding{border:1px solid var(--line);border-left:3px solid var(--dim);border-radius:10px;padding:10px 12px;margin-bottom:8px}
  .finding.critical{border-left-color:var(--red)} .finding.high{border-left-color:#ff8a3d}
  .finding.medium{border-left-color:var(--amber)} .finding.low{border-left-color:var(--blue)} .finding.info{border-left-color:var(--dim)}
  .finding .ft{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .finding .sev{font-size:9.5px;font-weight:800;letter-spacing:.5px;padding:2px 7px;border-radius:5px;text-transform:uppercase}
  .sev.critical{background:rgba(255,93,108,.18);color:var(--red)} .sev.high{background:rgba(255,138,61,.18);color:#ff8a3d}
  .sev.medium{background:rgba(255,193,77,.16);color:var(--amber)} .sev.low{background:rgba(90,166,255,.16);color:var(--blue)} .sev.info{background:rgba(255,255,255,.08);color:var(--dim)}
  .finding .ti{font-weight:600;font-size:13.5px}
  .finding .de{color:var(--dim);font-size:12.5px;margin-top:5px;line-height:1.45}
  .finding .rec{color:var(--green);font-size:12px;margin-top:5px}
  .cves{margin-top:8px;display:flex;flex-direction:column;gap:6px}
  .cverow{font-size:12px;line-height:1.45}
  .cverow a{color:var(--cyan);font-family:ui-monospace,monospace;text-decoration:none;font-weight:700}
  .cverow a:hover{text-decoration:underline}
  .cvss{font-size:10px;font-weight:800;padding:1px 6px;border-radius:5px;margin:0 5px;background:rgba(255,255,255,.08);color:var(--dim)}
  .cvss.c{background:rgba(255,93,108,.18);color:var(--red)} .cvss.h{background:rgba(255,138,61,.18);color:#ff8a3d}
  .cvss.m{background:rgba(255,193,77,.16);color:var(--amber)} .cvss.l{background:rgba(90,166,255,.16);color:var(--blue)}
  .cdesc{color:var(--dim)}
  .btnrow{display:flex;gap:8px;flex-wrap:wrap}
  .deepbtn{background:var(--green);color:#04111c;font-weight:700;border:0;border-radius:10px;
    padding:9px 14px;font-size:13px;cursor:pointer}
  .deepbtn:disabled{opacity:.6;cursor:default}
  .credbtn{background:#bb3346;color:#fff;font-weight:700;border:0;border-radius:10px;
    padding:9px 14px;font-size:13px;cursor:pointer}
  .credbtn:disabled{opacity:.6;cursor:default}
  .deepnote{font-size:11px;color:var(--amber);margin-top:7px;line-height:1.45}
  .weaklbl{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--dim);margin-top:9px;cursor:pointer}
  #credstatus{margin-top:8px}
  .hrow{border-left:3px solid var(--green);background:rgba(67,224,160,.06);border-radius:0 8px 8px 0;padding:8px 12px;margin-bottom:7px}
  .hrow b{font-size:13px} .hd{color:var(--dim);font-size:12.5px;margin-top:3px;line-height:1.45}
  textarea{font-family:inherit}
  .tmark{font-size:9.5px;font-weight:800;letter-spacing:.4px;text-transform:uppercase;padding:2px 7px;border-radius:5px}
  .tmark.t-ok{background:rgba(67,224,160,.16);color:var(--green)} .tmark.t-bad{background:rgba(255,93,108,.16);color:var(--red)}
  .tags2{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
  .tag2{font-size:10.5px;color:var(--blue);background:rgba(90,166,255,.12);border-radius:5px;padding:2px 7px}
  .locbar{height:22px;border-radius:11px;background:rgba(255,255,255,.07);overflow:hidden;border:1px solid var(--line)}
  .locfill{height:100%;border-radius:11px;background:var(--green);transition:width .6s ease}
  .loccmd{font-family:ui-monospace,monospace;font-size:12px;color:var(--cyan);background:#0a1120;border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin-top:6px;word-break:break-all}
  #locviz{width:100%;height:290px;display:block;border-radius:14px;border:1px solid var(--line);
    background:#0a0e0c}
  /* ===== terminal / professional-hacking theme ===== */
  body,input,button,textarea,select,.logo,.m-title{font-family:'Fira Code',ui-monospace,'JetBrains Mono',monospace !important}
  body{letter-spacing:0}
  .sec h4{font-family:'Fira Code',ui-monospace,monospace}
  .scrow{display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-bottom:1px solid var(--line)}
  .scmark{flex:0 0 auto;font-size:11px;font-weight:700;letter-spacing:.5px;padding:2px 7px;border-radius:4px;margin-top:1px}
  .scmark.ok{color:#04130b;background:var(--green)}
  .scmark.info{color:#0a0e0c;background:#e2c34e}
  .scbody{min-width:0}
  .scn{font-weight:600;color:var(--txt)}
  .scd{font-size:12.5px;margin-top:1px}
  .scev{font-size:12px;color:var(--dim);margin-top:3px;word-break:break-word;border-left:2px solid var(--line);padding-left:7px}
  .dnarow{padding:9px 0;border-bottom:1px solid var(--line)}
  .dnahead{display:flex;align-items:center;gap:8px}
  .dnaid{margin-left:auto;font-weight:600;color:var(--green)}
  .dnameta{font-size:12px;margin-top:3px;word-break:break-word}
  .dnatraits{display:flex;flex-wrap:wrap;gap:5px;margin-top:5px}
  .trait{font-size:11px;padding:2px 7px;border-radius:5px;background:rgba(255,255,255,.06);border:1px solid var(--line);color:var(--dim)}
  .dot-on{width:7px;height:7px;border-radius:50%;background:var(--green);display:inline-block}
  .dot-off{width:7px;height:7px;border-radius:50%;background:#5b6675;display:inline-block}
  .toolwrap{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}
  .toolpill{font-size:12px;padding:3px 9px;border-radius:5px;border:1px solid var(--line)}
  .toolpill.on{color:#04130b;background:var(--green);border-color:var(--green)}
  .toolpill.off{color:var(--dim);opacity:.65}
  .pill,.loccmd,.mac,.ip{font-family:ui-monospace,monospace}
  .card{border-radius:8px} .controls{border-radius:8px} .modal{border-radius:10px}
  .tbtn,.chip,.btn,.deepbtn,.credbtn,.feedbtn,.openbtn,.viewtoggle button{border-radius:6px}
  .ico{border-radius:8px} .m-ico{border-radius:9px}
  #netmap{border-radius:10px} #locviz{border-radius:8px}
  header{backdrop-filter:blur(8px);background:rgba(8,11,10,.85);box-shadow:0 1px 0 rgba(52,226,122,.18)}
  .card:hover{box-shadow:0 6px 22px rgba(0,0,0,.55);transform:none}
  .card.alert{box-shadow:inset 2px 0 0 var(--red)}
  a{color:var(--green)}
  ::selection{background:rgba(52,226,122,.3)}
  /* right-click device menu */
  #ctxmenu{position:fixed;display:none;z-index:90;min-width:190px;background:#0c1118;border:1px solid var(--line);border-radius:9px;padding:5px;box-shadow:0 10px 30px rgba(0,0,0,.5)}
  .ctxitem{padding:7px 11px;font-size:13px;color:var(--txt);border-radius:6px;cursor:pointer;white-space:nowrap}
  .ctxitem:hover{background:rgba(255,255,255,.07)}
  /* keyboard-shortcut help overlay */
  #helpov{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(4,6,9,.72);z-index:95}
  #helpov .hbox{background:#0c1118;border:1px solid var(--line);border-radius:14px;padding:22px 26px;min-width:300px}
  #helpov h3{margin:0 0 14px;font-size:14px;color:var(--txt)}
  #helpov .hrow{display:flex;justify-content:space-between;gap:24px;font-size:13px;padding:5px 0;color:var(--dim)}
  #helpov kbd{background:rgba(255,255,255,.08);border:1px solid var(--line);border-radius:5px;padding:1px 7px;font-family:ui-monospace,monospace;color:var(--txt)}
  /* history / timeline */
  .histsum{display:flex;gap:14px;flex-wrap:wrap;align-items:center;font-size:12.5px;color:var(--dim)}
  .histgaps{font-size:11.5px;margin:7px 0}
  .tline{margin-top:9px}
  .tlrow{display:flex;gap:12px;padding:4px 0 4px 12px;border-left:2px solid var(--line);font-size:12.5px}
  .tlrow .tlts{color:var(--dim);font-family:ui-monospace,monospace;white-space:nowrap;min-width:128px}
  .tlrow .tllbl{color:var(--txt)}
  .tlrow.sev-high{border-left-color:var(--red)} .tlrow.sev-high .tllbl{color:var(--red)}
  .tlrow.sev-medium{border-left-color:var(--amber)}
  .tlrow.sev-muted .tllbl{color:var(--dim)}
</style></head>
<body>
<header>
  <span class="brand"><img class="logomark" src="/logo.png" alt="ViperShard"><span class="logo">ViperScan</span></span>
  <span class="pill" id="net">—</span>
  <span class="spacer"></span>
  <span class="stat"><span class="dot" id="dot"></span><span id="status">starting…</span></span>
  <span class="stat"><b id="c-live">0</b> live</span>
  <span class="stat alert"><b id="c-alert">0</b> flagged</span>
  <span class="stat cam"><b id="c-cam">0</b> cameras</span>
  <span class="tools">
    <button class="tbtn" data-icon="file" onclick="window.open('/api/report','_blank')">Report</button>
    <button class="tbtn" data-icon="download" onclick="window.open('/api/export','_blank')">Export</button>
    <button class="tbtn" data-icon="shield" onclick="openPanel('scope')">Scope</button>
    <button class="tbtn" data-icon="bell" onclick="openPanel('alerts')">Alerts <span id="alertcount" class="countpill">0</span></button>
    <button class="tbtn" data-icon="activity" onclick="openPanel('activity')">Activity</button>
    <button class="tbtn" data-icon="clock" onclick="openPanel('history')">History</button>
    <button class="tbtn" data-icon="chart" onclick="openPanel('selfcheck')">System&nbsp;Check</button>
    <button class="tbtn" data-icon="sparkle" onclick="openPanel('intel')">Intelligence <span id="anomcount" class="countpill">0</span></button>
    <button class="tbtn" id="snifferbtn" data-icon="signal" onclick="toggleSniffer()" title="Put the Wi-Fi sniffer adapter into monitor mode (needed for Find / locate)"><span id="sniflabel">Monitor&nbsp;Mode</span></button>
    <button class="tbtn" id="kabtn" data-icon="activity" onclick="toggleKeepalive()" title="Constantly ping every discovered device so it stays in the ARP table and keeps responding"><span id="kalabel">Keep-alive</span></button>
  </span>
</header>
<main>
  <div class="controls">
    <div class="ctl">
      <span class="ctl-label">Mode</span>
      <div class="seg" id="modeseg">
        <button data-mode="quick" class="on">Quick</button>
        <button data-mode="deep">Deep</button>
        <button data-mode="unhide">Unhide</button>
      </div>
    </div>
    <div class="ctl">
      <span class="ctl-label">Network</span>
      <input id="netinput" placeholder="auto (current LAN)" spellcheck="false">
      <button class="btn" id="scanbtn">Scan</button>
    </div>
    <div class="ctl">
      <span class="ctl-label">Auto</span>
      <select id="interval">
        <option value="15">every 15s</option>
        <option value="30">every 30s</option>
        <option value="45" selected>every 45s</option>
        <option value="60">every 60s</option>
        <option value="300">every 5 min</option>
        <option value="3600">hourly</option>
      </select>
    </div>
    <div class="spacer"></div>
    <button class="btn primary" id="rescan">↻ Scan now</button>
    <div class="hint" id="modehint"></div>
  </div>

  <div class="filters" id="filters">
    <span class="chip on" data-f="all">All</span>
    <span class="chip" data-icon="alert" data-f="alert">Flagged</span>
    <span class="chip" data-icon="camera" data-f="camera">Cameras</span>
    <span class="chip" data-icon="voice" data-f="voice">Mics</span>
    <span class="chip" data-icon="unknown" data-f="unknown">Unknown</span>
    <span class="chip" data-icon="sparkle" data-f="new">New</span>
    <div class="viewtoggle"><button class="on" id="vt-grid" data-icon="grid" onclick="setView('grid')">Grid</button><button id="vt-map" data-icon="map" onclick="setView('map')">Map</button></div>
  </div>
  <div class="grid" id="grid"></div>
  <div class="empty" id="empty" style="display:none">No devices match this filter yet.</div>
  <div id="netmap-wrap"><canvas id="netmap"></canvas><div id="maptip"></div></div>
</main>

<div class="modal-overlay" id="overlay" onclick="closeDevice()">
  <div class="modal" onclick="event.stopPropagation()">
    <div class="m-head">
      <span class="m-ico" id="m-ico">·</span>
      <div style="min-width:0">
        <div class="m-title" id="m-title">Device</div>
        <div class="m-ip" id="m-ip"></div>
      </div>
      <button class="m-close" onclick="closeDevice()" title="Close (Esc)">✕</button>
    </div>
    <div class="m-body" id="m-body"></div>
  </div>
</div>

<div class="modal-overlay" id="panel" onclick="closePanel()">
  <div class="modal" onclick="event.stopPropagation()">
    <div class="m-head"><span class="m-title" id="panel-title">Panel</span>
      <button class="m-close" onclick="closePanel()" title="Close">✕</button></div>
    <div class="m-body" id="panel-body"></div>
  </div>
</div>
<footer>ViperScan · stdlib-only LAN awareness · data stays on this machine</footer>
<script>
let FILTER="all", DEV=[], BUSY=false, CURRENT_CIDR="", LAST_EVENTS=null;
const SVGP={
 clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
 camera:'<path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3z"/><circle cx="12" cy="13" r="3"/>',
 voice:'<rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 11a7 7 0 0 0 14 0"/><line x1="12" y1="18" x2="12" y2="22"/>',
 media:'<rect x="2" y="7" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
 printer:'<path d="M6 9V3h12v6"/><rect x="6" y="13" width="12" height="8" rx="1"/><path d="M6 17H4a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-2"/>',
 network:'<path d="M5 13a10 10 0 0 1 14 0"/><path d="M8.5 16.5a5 5 0 0 1 7 0"/><path d="M2 8.8a15 15 0 0 1 20 0"/><line x1="12" y1="20" x2="12" y2="20"/>',
 computer:'<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
 mobile:'<rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18"/>',
 iot:'<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>',
 unknown:'<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12" y2="17"/>',
 label:'<path d="M12.6 2.6A2 2 0 0 0 11.2 2H4a2 2 0 0 0-2 2v7.2a2 2 0 0 0 .6 1.4l8.7 8.7a2.4 2.4 0 0 0 3.4 0l6.6-6.6a2.4 2.4 0 0 0 0-3.4z"/><circle cx="7.5" cy="7.5" r=".6"/>',
 shield:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
 search:'<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.6" y2="16.6"/>',
 key:'<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
 activity:'<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
 chart:'<line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/>',
 signal:'<path d="M2 20h.01M7 20v-4M12 20v-9M17 20V8M22 4v16"/>',
 download:'<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
 file:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',
 bell:'<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
 map:'<polygon points="3 6 9 3 15 6 21 3 21 18 15 21 9 18 3 21"/><line x1="9" y1="3" x2="9" y2="18"/><line x1="15" y1="6" x2="15" y2="21"/>',
 grid:'<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
 alert:'<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12" y2="17"/>',
 stop:'<rect x="6" y="6" width="12" height="12" rx="1"/>',
 unlock:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
 sparkle:'<path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2 2M16 16l2 2M18 6l-2 2M8 16l-2 2"/>'};
const ALERT_FLAGS_JS=["CAMERA","SURVEILLANCE","CAMERA?","MIC","HIDDEN","UNKNOWN","INSECURE","EXPOSED","REMOTE","OPEN-CAM","INTERNET","OPEN-FTP","DEFAULT-CREDS"];
function IC(name,extra){ return '<svg class="ic'+(extra?' '+extra:'')+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'+(SVGP[name]||SVGP.unknown)+'</svg>'; }
function catKey(d){ return (d.category==="unknown"&&d.user_label)?"label":(SVGP[d.category]?d.category:"unknown"); }
function catIcon(d){ return IC(catKey(d)); }
const MODE_HINT={
  quick:"",
  deep:"Deep: full ~60-port list + SNMP/NetBIOS — slower, more thorough.",
  unhide:"Unhide: deep ports + SNMP + NetBIOS + nmap on quiet hosts — slowest, best at naming HIDDEN devices."
};
const WEB_PORTS=[80,81,443,8000,8008,8080,8081,8088,8181,8443,8888,5000,3000,9000,10000,32400];
let MODAL_IP=null;
var TOKEN="__TOKEN__";
function api(p){var u=p+(p.indexOf('?')>=0?'&':'?')+'t='+encodeURIComponent(TOKEN);return fetch(u).then(r=>r.json()).catch(()=>null);}

// ---- click a device → "about" modal + background probe + auto-open panel ----
function hasWeb(d){return (d.flags||[]).includes("EXPOSED")||Object.keys(d.open_ports||{}).some(p=>WEB_PORTS.includes(+p));}
function findDev(ip){return DEV.find(d=>d.ip===ip);}
function cardClick(ev,ip){ if(ev.target.closest("details,a,button"))return; openDevice(ip); }
function closeDevice(){ stopPoll(); stopLocVizLoop(); api("/api/locate/stop").catch(()=>{}); MODAL_IP=null; document.getElementById("overlay").classList.remove("on"); }
document.addEventListener("keydown",e=>{
  if(e.key==="Escape"){ closeDevice(); closePanel(); hideCtxMenu(); hideHelp(); return; }
  const t=e.target, tag=(t&&t.tagName||"").toLowerCase();
  if(tag==="input"||tag==="textarea"||(t&&t.isContentEditable)) return;   // don't hijack typing
  if(e.metaKey||e.ctrlKey||e.altKey) return;
  if(e.key==="s"||e.key==="r"){ e.preventDefault(); const b=document.getElementById("rescan"); if(b)b.click(); }
  else if(e.key==="e"){ e.preventDefault(); window.open("/api/export","_blank"); }
  else if(e.key==="/"){ e.preventDefault(); const n=document.getElementById("netinput"); if(n)n.focus(); }
  else if(e.key==="?"){ e.preventDefault(); toggleHelp(); }
});
// --- right-click device context menu + keyboard help overlay ---
function hideCtxMenu(){ const m=document.getElementById("ctxmenu"); if(m)m.style.display="none"; }
function copyText(t){ try{ navigator.clipboard.writeText(t); flash("Copied: "+t); }catch(_){ flash("Copy not available (needs https/localhost)"); } }
function cardMenu(e,ip){
  e.preventDefault(); e.stopPropagation();
  const d=findDev(ip); if(!d)return;
  const items=[
    ["⧉ Copy IP", ()=>copyText(d.ip)],
    d.mac?["⧉ Copy MAC", ()=>copyText(d.mac)]:null,
    ["⧉ Copy IP · MAC · vendor", ()=>copyText([d.ip,d.mac||"",d.vendor||""].filter(Boolean).join("  "))],
    ["↗ Open device card", ()=>openDevice(d.ip)],
    d.mac?["↗ Vendor (OUI) lookup", ()=>window.open("https://www.wireshark.org/tools/oui-lookup.html?q="+encodeURIComponent(d.mac.slice(0,8)),"_blank")]:null
  ].filter(Boolean);
  const m=document.getElementById("ctxmenu");
  m.innerHTML=items.map((it,i)=>'<div class="ctxitem" data-i="'+i+'">'+esc(it[0])+'</div>').join("");
  Array.from(m.children).forEach((el,i)=>el.onclick=()=>{ hideCtxMenu(); items[i][1](); });
  m.style.display="block";
  m.style.left=Math.min(e.clientX, innerWidth-210)+"px";
  m.style.top=Math.min(e.clientY, innerHeight-12-items.length*32)+"px";
}
document.addEventListener("click",hideCtxMenu);
window.addEventListener("scroll",hideCtxMenu,true);
function toggleHelp(){ const h=document.getElementById("helpov"); if(h)h.style.display=(h.style.display==="flex")?"none":"flex"; }
function hideHelp(){ const h=document.getElementById("helpov"); if(h)h.style.display="none"; }
// --- history / timeline ---
function loadTimeline(ip){ api("/api/timeline?ip="+encodeURIComponent(ip)).then(r=>{ if(MODAL_IP===ip)renderTimeline(r); }); }
function renderTimeline(r){
  const el=document.getElementById("hist-body"); if(!el)return;
  const s=(r&&r.summary)||{};
  let h='<div class="histsum">';
  h+= s.online?'<span style="color:var(--green)">● online now</span>'
             :'<span style="color:var(--dim)">○ offline'+(s.offline_since?(' since '+esc(s.offline_since)):'')+'</span>';
  if(s.first_seen)h+='<span>first seen '+esc(s.first_seen_ago||s.first_seen)+'</span>';
  if(s.days_known!=null)h+='<span>known '+s.days_known+' d</span>';
  if(s.last_seen_ago)h+='<span>last seen '+esc(s.last_seen_ago)+'</span>';
  h+='</div>';
  if((s.offline_gaps||[]).length)
    h+='<div class="muted histgaps">Offline windows: '+s.offline_gaps.map(g=>esc(g.hours+' h ('+g.from+' → '+g.to+')')).join(' · ')+'</div>';
  const ent=(r&&r.entries)||[];
  h+= ent.length
    ? '<div class="tline">'+ent.slice().reverse().map(e=>'<div class="tlrow sev-'+esc(e.sev||'info')+'"><span class="tlts">'+esc(e.ts||'')+'</span><span class="tllbl">'+esc(e.label||'')+'</span></div>').join('')+'</div>'
    : '<div class="muted">No recorded events yet — history builds as ViperScan keeps scanning.</div>';
  el.innerHTML=h;
}
function loadHistory(body){
  body.innerHTML='<span class="spin"></span> loading…';
  api("/api/history").then(r=>{
    if(!r){ body.innerHTML='<div class="muted">unavailable</div>'; return; }
    const an=r.anomalies||[], rec=r.recent||[];
    let h='<button class="btn" style="margin-bottom:14px" onclick="window.open(\'/api/history/export\',\'_blank\')">⬇ Export history (JSON)</button>';
    h+='<h4>Anomalies</h4>';
    h+= an.length? an.map(a=>'<div class="finding '+(a.sev==="high"?"critical":"high")+'"><div class="ft"><span class="sev '+(a.sev==="high"?"critical":"high")+'">'+esc(a.sev)+'</span><span class="ti">'+esc(a.ip||"")+'</span></div><div class="de">'+esc(a.label||"")+'</div><div class="evts">'+esc(a.ts||"")+'</div></div>').join('')
      : '<div class="muted">✓ Nothing unusual in the recorded history.</div>';
    h+='<h4 style="margin-top:16px">Recent changes</h4>';
    h+= rec.length? '<div class="tline">'+rec.map(e=>'<div class="tlrow"><span class="tlts">'+esc(e.ts||"")+'</span><span class="tllbl">'+esc((e.type||"").replace(/_/g," "))+' — '+esc(e.detail||"")+' <span style="color:var(--dim)">'+esc(e.ip||"")+'</span></span></div>').join('')+'</div>'
      : '<div class="muted">No change events recorded yet.</div>';
    body.innerHTML=h;
  });
}

function aboutHTML(d){
  const svc=d.services||{}, rows=[];
  rows.push(["MAC",d.mac||"—"]); rows.push(["Vendor",d.vendor||"—"]); rows.push(["Type",d.device_type||"—"]);
  const ports=Object.entries(d.open_ports||{}).map(([p,l])=>p+"/"+l).join(", ");
  if(ports)rows.push(["Open ports",ports]);
  for(const [k,lab] of [["snmp","SNMP"],["mdns_name","mDNS"],["ssdp_model","Model"],["nmap_os","OS"]]) if(svc[k])rows.push([lab,svc[k]]);
  if(d.first_seen)rows.push(["First seen",d.first_seen]);
  const flags=(d.flags||[]).map(f=>'<span class="flag '+flagClass(f)+'">'+f+'</span>').join(" ");
  const reasons=(d.flag_reasons||[]).map(r=>"<li>"+esc(r)+"</li>").join("");
  const ph=d.ports_seen||{};
  const phist=Object.keys(ph).length?'<details style="margin-top:8px"><summary>port history</summary><div style="margin-top:5px">'+
    Object.entries(ph).map(e=>'<div class="muted">'+esc(e[0])+' — open since '+esc(e[1].first||"?")+'</div>').join('')+'</div></details>':'';
  return '<div class="sec"><h4>About this device</h4><div class="kv">'+
    rows.map(r=>'<div class="k">'+r[0]+'</div><div class="v">'+esc(String(r[1]))+'</div>').join("")+'</div>'+
    (flags?'<div class="flags" style="margin-top:11px">'+flags+'</div>':'')+
    (reasons?'<details style="margin-top:8px"><summary>why flagged</summary><ul>'+reasons+'</ul></details>':'')+phist+'</div>';
}
let AN_TRUST="";
function annotHTML(d){
  const lbl=d.user_label||"", note=d.note||"", trust=d.trust||"", tags=(d.tags||[]).join(", ");
  return '<h4>Label, trust &amp; notes</h4>'+
    '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">'+
    '<input id="an-name" placeholder="custom name (e.g. Michael’s Wyze cam)" value="'+esc(lbl)+'" style="width:230px">'+
    '<div class="seg" id="an-trust">'+
      '<button onclick="setTrust(this,\'trusted\')" class="'+(trust==="trusted"?"on":"")+'">Trusted</button>'+
      '<button onclick="setTrust(this,\'untrusted\')" class="'+(trust==="untrusted"?"on":"")+'">Untrusted</button>'+
      '<button onclick="setTrust(this,\'\')" class="'+(trust===""?"on":"")+'">—</button>'+
    '</div></div>'+
    '<input id="an-tags" placeholder="tags, comma-separated" value="'+esc(tags)+'" style="width:100%;margin-top:8px">'+
    '<textarea id="an-note" placeholder="notes…" style="width:100%;margin-top:8px;min-height:48px;background:#0a1120;color:var(--txt);border:1px solid var(--line);border-radius:9px;padding:8px;font-size:13px">'+esc(note)+'</textarea>'+
    '<button class="btn primary" style="margin-top:8px" onclick="saveAnnot(\''+escJs(d.ip)+'\',\''+escJs(d.mac||"")+'\')">Save</button> <span id="an-status" class="muted"></span>';
}
function setTrust(btn,t){ AN_TRUST=t; const seg=document.getElementById("an-trust"); if(seg)seg.querySelectorAll("button").forEach(b=>b.classList.toggle("on",b===btn)); }
function saveAnnot(ip,mac){
  const name=document.getElementById("an-name").value, tags=document.getElementById("an-tags").value, note=document.getElementById("an-note").value;
  const st=document.getElementById("an-status"); if(st)st.textContent="saving…";
  api("/api/annotate?ip="+encodeURIComponent(ip)+"&mac="+encodeURIComponent(mac)+"&user_label="+encodeURIComponent(name)+
      "&tags="+encodeURIComponent(tags)+"&note="+encodeURIComponent(note)+"&trust="+encodeURIComponent(AN_TRUST)).then(()=>{
    if(st)st.textContent="saved ✓";
    const d=findDev(ip);
    if(d){ d.user_label=name; d.note=note; d.trust=AN_TRUST; d.tags=tags.split(",").map(s=>s.trim()).filter(Boolean); if(name)d.display_name=name;
      if(name){ d.flags=(d.flags||[]).filter(f=>f!=="UNKNOWN"); d.flag_reasons=(d.flag_reasons||[]).filter(r=>!/could not identify/i.test(r)); d.is_alert=(d.flags||[]).some(f=>ALERT_FLAGS_JS.indexOf(f)>=0); } }
    {const mi=document.getElementById("m-ico"); if(d){mi.className="m-ico ico-"+catKey(d); mi.innerHTML=catIcon(d);}}
    document.getElementById("m-title").textContent=name||(d?(d.display_name||d.device_type):"");
    draw();
  });
}
let LOC_TIMER=null;
function stopPoll(){ if(LOC_TIMER){clearInterval(LOC_TIMER);LOC_TIMER=null;} }
function startLocate(ip){
  const body=document.getElementById("loc-body"); if(body)body.innerHTML='<span class="spin"></span>detecting adapter &amp; starting monitor mode…';
  const pv=document.getElementById("provokechk"); const provoke=pv&&pv.checked?"&provoke=1":"";
  LOCVIZ.peak=0; LOCVIZ.peakTs=0;
  api("/api/locate/start?ip="+encodeURIComponent(ip)+provoke).then(r=>{
    if(!r)return;
    if(r.ok){ const b=document.getElementById("locbtn"); if(b){b.textContent="⏹ Stop";b.onclick=()=>stopLocate(ip);} pollLocate(ip); }
    else showLocateProblem(r,ip);
  });
}
function pollLocate(ip){
  stopPoll();
  const tick=()=>{ if(MODAL_IP!==ip){stopLocate(ip);return;} api("/api/locate?ip="+encodeURIComponent(ip)).then(r=>{ if(r&&MODAL_IP===ip)renderLocate(r,ip); }); };
  tick(); LOC_TIMER=setInterval(tick,1000);
}
function stopLocate(ip){
  stopPoll(); stopLocVizLoop(); stopLocAudio(); api("/api/locate/stop").catch(()=>{});
  const b=document.getElementById("locbtn"); if(b){b.innerHTML=IC('signal')+" Find this device";b.onclick=()=>startLocate(ip);}
  const body=document.getElementById("loc-body"); if(body)body.innerHTML='Stopped — adapter restored to normal mode.';
}
function showLocateProblem(r,ip){
  const body=document.getElementById("loc-body"); if(!body)return;
  const c=r.capability||{}, e=r.error||"";
  if(e==="needs_root"||(c&&!c.root)){
    body.innerHTML='<div class="muted">One-click Find needs the dashboard running as <b>root</b> (monitor mode requires it). Restart it with:</div>'+
      '<div class="loccmd">sudo python3 __LAUNCHER__ --web</div>'+
      '<div class="muted" style="margin-top:7px">…then press Find again. Or run the standalone finder:</div><div class="loccmd">'+esc(r.command||"")+'</div>';
  } else if(e==="needs_iw"){ body.innerHTML='<div class="muted">Needs the <code>iw</code> tool — install it:</div><div class="loccmd">sudo apt install iw</div>'; }
  else if(e==="no_adapter"){ body.innerHTML='<div class="muted">'+esc(r.reason||"No dedicated monitor adapter detected — plug in your A8000 and press Find again.")+'</div>'; }
  else if(e==="no_mac"){ body.innerHTML='<div class="muted">No MAC known for this device yet — run a scan first.</div>'; }
  else if(e==="monitor_failed"){ body.innerHTML='<div class="muted">Couldn\'t engage monitor mode on '+esc(r.iface||"the adapter")+(r.reason?(' — '+esc(r.reason)):'')+'.</div>'+
    (r.kernel_error?'<div class="muted" style="margin-top:5px">kernel said: <code>'+esc(r.kernel_error)+'</code></div>':'')+
    '<div class="muted" style="margin-top:7px">Try the <b>Monitor Mode</b> button in the top bar first, then Find.</div>'; }
  else { body.innerHTML='<div class="muted">Could not start: '+esc(r.reason||e||"unknown")+'.</div>'; }
}
let LOCVIZ={target:0,cur:0,history:[],raf:null,info:{},phase:"",frames:0,hits:0,macs:0,channel:null,lastTrack:0,peak:0,peakTs:0,via:""};
// ---- audio homing (Geiger-style: faster + higher pitch as you close in) ----
let LOC_AUDIO={on:false,ctx:null,timer:null};
function toggleLocAudio(){
  LOC_AUDIO.on=!LOC_AUDIO.on;
  const b=document.getElementById("audiobtn"); if(b){b.textContent=LOC_AUDIO.on?"🔊 Audio":"🔇 Audio"; b.classList.toggle("on",LOC_AUDIO.on);}
  if(LOC_AUDIO.on){ try{ LOC_AUDIO.ctx=LOC_AUDIO.ctx||new (window.AudioContext||window.webkitAudioContext)(); if(LOC_AUDIO.ctx.state==="suspended")LOC_AUDIO.ctx.resume(); }catch(e){ LOC_AUDIO.on=false; flash("Audio not supported in this browser."); return; } scheduleBeep(); }
  else stopLocAudio();
}
function stopLocAudio(){ if(LOC_AUDIO.timer){clearTimeout(LOC_AUDIO.timer);LOC_AUDIO.timer=null;} }
function scheduleBeep(){
  stopLocAudio(); if(!LOC_AUDIO.on)return;
  const p=Math.max(0,Math.min(100,LOCVIZ.cur));
  const fresh=LOCVIZ.phase==="tracking" && (Date.now()-LOCVIZ.lastTrack)<4000;
  // gap: 900ms (far/cold) -> 70ms (right on top). pitch: 360Hz -> 1500Hz.
  const gap=fresh? Math.max(70, 900-(p/100)*830) : 1400;
  if(fresh) beep(360+(p/100)*1140, 0.06, Math.min(0.5,0.12+p/300));
  LOC_AUDIO.timer=setTimeout(scheduleBeep, gap);
}
function beep(freq,dur,vol){
  const c=LOC_AUDIO.ctx; if(!c)return;
  try{ const o=c.createOscillator(),g=c.createGain(); o.type="sine"; o.frequency.value=freq;
    g.gain.setValueAtTime(0.0001,c.currentTime); g.gain.exponentialRampToValueAtTime(vol||0.2,c.currentTime+0.008);
    g.gain.exponentialRampToValueAtTime(0.0001,c.currentTime+(dur||0.06));
    o.connect(g); g.connect(c.destination); o.start(); o.stop(c.currentTime+(dur||0.06)+0.02);
  }catch(e){}
}
function locColor(p){ return "hsl("+Math.max(0,220-(p/100)*220)+",85%,55%)"; }
function ensureLocViz(ip){
  const body=document.getElementById("loc-body"); if(!body)return;
  if(!document.getElementById("locviz")){
    body.innerHTML='<canvas id="locviz"></canvas>'+
      '<div id="locstatus" class="locstats"></div>'+
      '<div class="muted" style="margin-top:6px">Walk around — the gauge fills and goes <b>cold→hot</b> as you close in. Trust the <b>trend graph</b>. Auto-pinging '+esc(ip)+' to keep it transmitting.</div>';
    LOCVIZ.history=[]; LOCVIZ.cur=0; LOCVIZ.target=0; LOCVIZ.lastTrack=0;
    sizeLocViz();
  }
  if(!LOCVIZ.raf)startLocVizLoop();        // keep the animation alive even after a phase flip
}
function sizeLocViz(){
  const cv=document.getElementById("locviz"); if(!cv)return;
  const dpr=window.devicePixelRatio||1, rect=cv.getBoundingClientRect();
  cv.__w=Math.max(280,rect.width); cv.__h=290;
  cv.width=cv.__w*dpr; cv.height=cv.__h*dpr; cv.getContext("2d").setTransform(dpr,0,0,dpr,0,0);
}
function startLocVizLoop(){ stopLocVizLoop(); const loop=()=>{ if(!document.getElementById("locviz")){LOCVIZ.raf=null;return;} drawLocViz(); LOCVIZ.raf=requestAnimationFrame(loop); }; loop(); }
function stopLocVizLoop(){ if(LOCVIZ.raf){cancelAnimationFrame(LOCVIZ.raf);LOCVIZ.raf=null;} }
function drawLocViz(){
  const cv=document.getElementById("locviz"); if(!cv)return;
  const ctx=cv.getContext("2d"), w=cv.__w, h=cv.__h, now=Date.now();
  const fresh = LOCVIZ.phase==="tracking" && (now-LOCVIZ.lastTrack)<3500;   // recent real reading?
  const tgt = fresh?LOCVIZ.target:Math.max(0,LOCVIZ.cur*0.92);              // hold/decay when not tracking
  LOCVIZ.cur += (tgt-LOCVIZ.cur)*0.14;
  const p=LOCVIZ.cur, col=locColor(p), I=LOCVIZ.info||{};
  ctx.clearRect(0,0,w,h);
  const cx=w/2, cy=128, R=96, a0=Math.PI*0.75, sweep=Math.PI*1.5;
  // track ring
  ctx.lineWidth=16; ctx.lineCap="round"; ctx.strokeStyle="rgba(255,255,255,0.06)";
  ctx.beginPath(); ctx.arc(cx,cy,R,a0,a0+sweep); ctx.stroke();
  if(fresh){
    // glowing value arc
    ctx.strokeStyle=col; ctx.shadowColor=col; ctx.shadowBlur=18+(I.trend>0?12:0);
    ctx.beginPath(); ctx.arc(cx,cy,R,a0,a0+sweep*(p/100)); ctx.stroke(); ctx.shadowBlur=0;
    // peak-hold marker — the hottest spot you've reached (walk back toward it)
    if(LOCVIZ.peak>2){
      const pa=a0+sweep*(Math.min(100,LOCVIZ.peak)/100);
      ctx.strokeStyle="#ffd54a"; ctx.lineWidth=5; ctx.lineCap="butt";
      ctx.beginPath(); ctx.arc(cx,cy,R,pa-0.02,pa+0.02); ctx.stroke();
      ctx.lineWidth=16; ctx.lineCap="round";
    }
  } else {
    // moving radar sweep — proves we're still listening / hunting (never static)
    const head=a0+sweep*((now/900)%1);
    ctx.strokeStyle="rgba(52,226,122,0.9)"; ctx.shadowColor="rgba(52,226,122,0.7)"; ctx.shadowBlur=14;
    ctx.beginPath(); ctx.arc(cx,cy,R,head-0.4,head); ctx.stroke(); ctx.shadowBlur=0;
  }
  // center readouts
  ctx.textAlign="center";
  if(fresh){
    ctx.fillStyle="#fff"; ctx.font="700 44px 'Fira Code',ui-monospace,monospace"; ctx.fillText(Math.round(p)+"%",cx,cy+4);
    ctx.font="13px 'Fira Code',ui-monospace,monospace"; ctx.fillStyle="#8595ad";
    ctx.fillText((I.dist!=null?"~"+I.dist+" m":"")+(I.rssi!=null?"   "+I.rssi+" dBm":"")+(LOCVIZ.channel!=null?"   ch"+LOCVIZ.channel:""),cx,cy+26);
    // direction guidance — use trend + how far below the peak we are
    const drop=LOCVIZ.peak-p;
    let guide,gcol;
    if(I.trend>0){ guide="▲ WARMER — keep going this way"; gcol="#ff7a5c"; }
    else if(drop>12){ guide="↩ COLDER — you passed it, turn back"; gcol="#5aa6ff"; }
    else if(p>=75){ guide="🎯 RIGHT HERE — it's very close"; gcol="#ff5a4a"; }
    else if(I.trend<0){ guide="▼ colder — wrong way"; gcol="#5aa6ff"; }
    else { guide="— steady — take a few steps"; gcol="#8595ad"; }
    ctx.font="700 14px 'Fira Code',ui-monospace,monospace"; ctx.fillStyle=gcol; ctx.fillText(guide,cx,cy+48);
    if(LOCVIZ.peak>2){ ctx.font="11px 'Fira Code',ui-monospace,monospace"; ctx.fillStyle="#ffd54a";
      ctx.fillText("best "+Math.round(LOCVIZ.peak)+"%"+(LOCVIZ.via==="cts"?"  · RTS/CTS":""),cx,cy+68); }
  } else {
    const lab=LOCVIZ.phase==="locked"?"LOCKED":"SCANNING";
    ctx.fillStyle="#e8edf6"; ctx.font="700 27px 'Fira Code',ui-monospace,monospace"; ctx.fillText(lab,cx,cy);
    ctx.font="12px 'Fira Code',ui-monospace,monospace"; ctx.fillStyle="#8595ad";
    ctx.fillText(LOCVIZ.channel!=null?("channel "+LOCVIZ.channel):"hopping channels…",cx,cy+22);
    const dots=".".repeat(1+(Math.floor(now/400)%3));
    ctx.fillStyle="#5b6675"; ctx.fillText((LOCVIZ.phase==="locked"?"waiting for it to transmit":"listening")+dots,cx,cy+42);
  }
  // history sparkline (bottom strip)
  const gy0=212, gy1=276, hist=LOCVIZ.history;
  ctx.strokeStyle="rgba(255,255,255,0.06)"; ctx.lineWidth=1;
  ctx.beginPath(); ctx.moveTo(14,gy1); ctx.lineTo(w-14,gy1); ctx.stroke();
  // dashed peak line — your hottest reading, so you can see when you beat it
  if(LOCVIZ.peak>2){
    const py=gy1-(gy1-gy0)*(Math.min(100,LOCVIZ.peak)/100);
    ctx.setLineDash([4,4]); ctx.strokeStyle="rgba(255,213,74,0.45)"; ctx.lineWidth=1;
    ctx.beginPath(); ctx.moveTo(14,py); ctx.lineTo(w-14,py); ctx.stroke(); ctx.setLineDash([]);
  }
  if(hist.length>1){
    const n=hist.length, x0=14, x1=w-14;
    ctx.lineWidth=2.5; ctx.beginPath();
    for(let i=0;i<n;i++){ const x=x0+(x1-x0)*(i/(n-1)), y=gy1-(gy1-gy0)*(hist[i]/100); if(i===0)ctx.moveTo(x,y); else ctx.lineTo(x,y); }
    ctx.strokeStyle=col; ctx.shadowColor=col; ctx.shadowBlur=8; ctx.stroke(); ctx.shadowBlur=0;
    const lx=x1, ly=gy1-(gy1-gy0)*(hist[n-1]/100);
    ctx.beginPath(); ctx.arc(lx,ly,4,0,Math.PI*2); ctx.fillStyle=col; ctx.fill();
  }
  ctx.textAlign="left"; ctx.fillStyle="#5b6675"; ctx.font="10px 'Fira Code',ui-monospace,monospace"; ctx.fillText("signal trend (walk to change)",16,gy0-4);
}
function renderLocate(r,ip){
  const body=document.getElementById("loc-body"); if(!body)return;
  if(r.error){ stopLocVizLoop(); showLocateProblem(r,ip); return; }
  if(!r.running){ stopLocVizLoop();
    body.innerHTML='<div class="muted">Push <b>Find</b> to start — auto-detects the adapter, enables monitor mode, pings the device awake, and shows the live signal.</div>';
    return;
  }
  ensureLocViz(ip);                          // persistent canvas — never torn down while running
  const L=r.live||{};
  if(L.frames!=null)LOCVIZ.frames=L.frames;
  if(L.hits!=null)LOCVIZ.hits=L.hits;
  if(L.unique_macs!=null)LOCVIZ.macs=L.unique_macs;
  if(L.channel!=null)LOCVIZ.channel=L.channel;
  LOCVIZ.phase=L.phase||"surveying";
  if(L.pct!=null && L.phase==="tracking"){
    LOCVIZ.target=L.pct||0; LOCVIZ.via=L.via||"";
    LOCVIZ.info={rssi:L.rssi_smooth,dist:L.distance_m,trend:L.trend,channel:L.channel};
    LOCVIZ.history.push(L.pct||0); if(LOCVIZ.history.length>140)LOCVIZ.history.shift();
    LOCVIZ.lastTrack=Date.now();
    if((L.pct||0)>=LOCVIZ.peak){ LOCVIZ.peak=L.pct||0; LOCVIZ.peakTs=Date.now(); }   // remember hottest spot
  }
  if(LOC_AUDIO.on && !LOC_AUDIO.timer) scheduleBeep();   // (re)start the homing beeps
  const st=document.getElementById("locstatus");
  if(st){
    const el=(L.elapsed!=null?L.elapsed:0);
    const ph=LOCVIZ.phase==="tracking"?'<b style="color:var(--green)">● TRACKING</b>'
      :(LOCVIZ.phase==="locked"?'<b style="color:#e2c34e">◉ LOCKED</b>':'<b>⟳ SCANNING</b>');
    st.innerHTML=ph+' · ch <b>'+esc(LOCVIZ.channel!=null?LOCVIZ.channel:"…")+'</b>'+
      ' · frames <b>'+LOCVIZ.frames+'</b> · matches <b>'+LOCVIZ.hits+'</b> · devices heard <b>'+LOCVIZ.macs+'</b>'+
      ' · '+el+'s';
  }
  // actionable diagnostics so it never spins silently
  let hd=document.getElementById("lochint");
  if(!hd){ const b=document.getElementById("loc-body"); if(b){ hd=document.createElement("div"); hd.id="lochint"; hd.className="lochint"; b.appendChild(hd); } }
  if(hd){
    if(L.hint==="cant_tune"){
      hd.style.display=""; hd.className="lochint bad";
      hd.innerHTML='⚠ <b>The monitor radio is busy — can\'t set channels.</b> Something re-claimed the adapter (NetworkManager brought it back up). '+
        'Press <b>Stop</b>, then <b>Find</b> again — ViperScan now frees the radio on each start. If it persists, toggle <b>Monitor Mode</b> off then on.';
    } else if(L.hint==="no_frames"){
      hd.style.display=""; hd.className="lochint bad";
      hd.innerHTML='⚠ <b>No 802.11 frames captured.</b> The sniffer adapter isn\'t actually in monitor mode, or it\'s the wrong adapter. '+
        'Click <b>Monitor Mode</b> in the top bar, and make sure it\'s your <b>A8000</b> (not the adapter that\'s carrying your internet).';
    } else if(L.hint==="not_heard"){
      hd.style.display=""; hd.className="lochint warn";
      hd.innerHTML='Sniffing fine (heard <b>'+LOCVIZ.macs+'</b> other Wi-Fi devices) but <b>0 frames from '+esc(ip)+'</b> yet. '+
        'Most likely it\'s <b>idle / in deep Wi-Fi power-save</b> (it barely transmits), or it\'s <b>wired/PoE</b> (can\'t be RF-located). '+
        '<b>Make it transmit</b> — open its app or live-stream from it (for a camera, pull up its feed) — then it locks within seconds. '+
        'Camping the likely channels &amp; auto-pinging it meanwhile…';
    } else { hd.style.display="none"; hd.innerHTML=""; }
  }
}
function wakeDevice(ip){
  const b=document.getElementById("wakebtn"), st=document.getElementById("wake-status");
  if(b)b.disabled=true; if(st){st.className="muted";st.innerHTML='<span class="spin"></span> waking '+esc(ip)+'…';}
  api("/api/wake?ip="+encodeURIComponent(ip)).then(r=>{
    if(b)b.disabled=false; if(!st)return;
    if(!r||r.error){ st.innerHTML='<span style="color:var(--red)">failed</span>'; return; }
    const wol = r.wol?'Wake-on-LAN packet sent · ':'';
    if(r.alive){
      st.innerHTML='<span style="color:var(--green)">● online</span> — '+wol+'replied'+(r.rtt!=null?(' in '+r.rtt+' ms'):'')+
        (r.knocked&&r.knocked.length?(' · woke via TCP '+r.knocked.join(', ')):'');
    } else {
      st.innerHTML='<span style="color:var(--red)">○ no response</span> — '+wol+'sent '+r.pings+' pings + TCP knocks; '+
        'it may be powered off, asleep, or firewalling probes'+(r.knocked&&r.knocked.length?(' (open ports: '+r.knocked.join(', ')+')'):'')+'.';
    }
  });
}
function fmtbps(b){ if(b==null)return "—"; b=+b; if(b<1000)return Math.round(b)+" bps"; if(b<1e6)return (b/1e3).toFixed(1)+" Kbps"; if(b<1e9)return (b/1e6).toFixed(2)+" Mbps"; return (b/1e9).toFixed(2)+" Gbps"; }
function fmtDur(s){ if(s==null)return "—"; s=+s; const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return (d?d+"d ":"")+(h?h+"h ":"")+m+"m"; }
function checkActivity(ip){
  MODAL_IP=ip;
  const b=document.getElementById("actbtn"); if(b){b.disabled=true;b.textContent="checking…";}
  const body=document.getElementById("act-body"); if(body)body.innerHTML='<span class="spin"></span>probing liveness, throughput &amp; live services…';
  api("/api/activity?ip="+encodeURIComponent(ip)).then(r=>{
    if(b){b.disabled=false;b.textContent="↻ Re-check activity";}
    if(r&&MODAL_IP===ip)renderActivity(r);
  });
}
function renderActivity(r){
  const body=document.getElementById("act-body"); if(!body)return;
  const lv=r.liveness||{}, sn=r.snmp||{};
  let h='<div class="kv">';
  h+='<div class="k">Status</div><div class="v">'+(lv.online?'<span style="color:var(--green)">● online</span>':'<span style="color:var(--dim)">○ no ping reply</span>')+
     (lv.avg_ms!=null?(' · '+lv.avg_ms+' ms'+(lv.jitter_ms?(' ±'+lv.jitter_ms):'')+(lv.loss_pct?(' · '+lv.loss_pct+'% loss'):'')):'')+'</div>';
  if(sn.in_bps!=null){
    h+='<div class="k">Throughput</div><div class="v">↓ '+fmtbps(sn.in_bps)+'   ↑ '+fmtbps(sn.out_bps)+' <span class="muted">(SNMP)</span></div>';
    if(sn.uptime_s!=null)h+='<div class="k">Uptime</div><div class="v">'+fmtDur(sn.uptime_s)+'</div>';
  }
  if(r.stream_active!=null)h+='<div class="k">Camera stream</div><div class="v">'+(r.stream_active?'<span style="color:var(--red)">● live / reachable</span>':'not reachable')+'</div>';
  if((r.live_ports||[]).length)h+='<div class="k">Live now</div><div class="v">'+r.live_ports.join(", ")+'</div>';
  if((r.roles||[]).length)h+='<div class="k">Acts as</div><div class="v">'+r.roles.map(esc).join(" · ")+'</div>';
  h+='</div>';
  h+='<div class="muted" style="margin-top:8px">Point-in-time. ViperScan sees what this device advertises and its live state — not the private traffic between it and the internet (that needs router-level capture).</div>';
  if((r.events||[]).length)h+='<details style="margin-top:9px"><summary>recent events</summary>'+r.events.map(e=>'<div class="muted">'+esc(e.ts)+' — '+esc((e.type||"").replace(/_/g," "))+' '+esc(e.detail||"")+'</div>').join('')+'</details>';
  body.innerHTML=h;
}
function openDevice(ip){
  const d=findDev(ip); if(!d){ flash(ip+" isn't in the current LAN scan."); return; }
  MODAL_IP=ip; CUR={findings:[],nmap:{},dev:d,deep:false,hardening:[]};
  {const mi=document.getElementById("m-ico"); mi.className="m-ico ico-"+catKey(d); mi.innerHTML=catIcon(d);}
  document.getElementById("m-title").textContent=d.display_name||d.device_type;
  document.getElementById("m-ip").textContent=d.ip+(d.mac?(" · "+d.mac):"");
  AN_TRUST=d.trust||"";
  document.getElementById("m-body").innerHTML=aboutHTML(d)+
    '<div class="sec" id="sec-wake" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
    '<button class="btn" id="wakebtn" onclick="wakeDevice(\''+escJs(ip)+'\')" title="Ping + TCP-knock this device to wake it / bring it online">'+IC('activity')+' Ping / wake</button>'+
    '<span id="wake-status" class="muted"></span></div>'+
    '<div class="sec" id="sec-annot">'+annotHTML(d)+'</div>'+
    '<div class="sec" id="sec-history"><h4>History — timeline</h4><div id="hist-body" class="muted"><span class="spin"></span>loading history…</div></div>'+
    '<div class="sec" id="sec-risk"><h4>Risk</h4><div class="muted"><span class="spin"></span>assessing…</div></div>'+
    '<div class="sec" id="sec-panels"><h4>Web / admin panels</h4><div class="muted"><span class="spin"></span>looking for a reachable panel…</div></div>'+
    '<div class="sec" id="sec-findings"><h4>Findings</h4><div class="muted"><span class="spin"></span>running quiet checks…</div></div>'+
    '<div class="sec" id="sec-activity"><h4>Activity — what it’s doing now</h4>'+
    '<button class="btn" id="actbtn" onclick="checkActivity(\''+escJs(ip)+'\')">'+IC('chart')+' Check activity</button>'+
    '<div id="act-body" class="muted" style="margin-top:9px">Live throughput (SNMP), responsiveness, which services are live right now, and the role it plays.</div></div>'+
    '<div class="sec" id="sec-locate"><h4>Locate — Wi-Fi proximity finder</h4>'+
    '<div class="locctl"><button class="btn primary" id="locbtn" onclick="startLocate(\''+escJs(ip)+'\')">'+IC('signal')+' Find this device</button>'+
    '<button class="btn" id="audiobtn" onclick="toggleLocAudio()" title="Geiger-style audio: faster + higher pitch as you get closer">🔇 Audio</button>'+
    '<label class="weaklbl" title="Inject RTS so the device\'s chip replies with a CTS — gives a signal on demand from silent/power-saving devices. Stealthy: handled in firmware, nothing the device logs."><input type="checkbox" id="provokechk"> RTS&nbsp;provoke (find silent devices)</label></div>'+
    '<div id="loc-body" class="muted" style="margin-top:9px">One click: auto-detects your Wi-Fi adapter, flips it to monitor mode, pings the device awake, and shows a live signal meter to walk it down. (Dashboard must run as <b>sudo</b> for one-click.)</div></div>'+
    '<div class="sec"><div class="btnrow">'+
    '<button class="deepbtn" id="deepbtn" onclick="runAudit(\''+escJs(ip)+'\',true)">'+IC('search')+' Deep audit</button>'+
    '<button class="credbtn" id="credbtn" onclick="runCreds(\''+escJs(ip)+'\')">'+IC('key')+' Test factory passwords</button></div>'+
    '<label class="weaklbl"><input type="checkbox" id="weakchk"> also try ~30 common weak passwords (bounded &amp; lockout-aware)</label>'+
    '<div id="credstatus" class="muted"></div>'+
    '<div class="deepnote">Deep audit = nmap + open-stream + anonymous-FTP checks (identification — no password guessing). “Test factory passwords” sends real login attempts the device will log. Both are for devices you own or are authorised to test.</div></div>';
  document.getElementById("overlay").classList.add("on");
  api("/api/panel?ip="+encodeURIComponent(ip)).then(p=>{ if(MODAL_IP===ip)renderPanels(p,ip); });
  loadTimeline(ip);
  runAudit(ip,false);
}
let CUR={findings:[],nmap:{},dev:null,deep:false};
const SEVO={critical:4,high:3,medium:2,low:1,info:0};
const SW={critical:45,high:28,medium:14,low:5,info:0};
function riskFrom(findings,dev){
  let s=(findings||[]).reduce((a,f)=>a+(SW[f.severity]||0),0);
  if(dev&&dev.category==="camera"&&findings.some(f=>f.severity==="critical"||f.severity==="high"))s+=10;
  s=Math.min(100,s);
  let label="clean",color="green";
  if(s>0&&s<25){label="low";color="blue";}else if(s>=25&&s<55){label="elevated";color="amber";}else if(s>=55){label="critical";color="red";}
  return {score:s,label,color};
}
function mergeAudit(r){
  if(!r)return;
  const by={}; (CUR.findings||[]).forEach(f=>by[f.title]=f); (r.findings||[]).forEach(f=>by[f.title]=f);
  CUR.findings=Object.values(by).sort((a,b)=>SEVO[b.severity]-SEVO[a.severity]);
  if(r.nmap&&(r.nmap.nmap_os||r.nmap.nmap_services))CUR.nmap=r.nmap;
  if(r.hardening&&r.hardening.length)CUR.hardening=r.hardening;
  if(r.tools)CUR.tools=r.tools;
  if(r.intel_summary&&r.intel_summary.length)CUR.intel=r.intel_summary;
  if(r.deep)CUR.deep=true;
  renderRisk(riskFrom(CUR.findings,CUR.dev));
  renderFindings({findings:CUR.findings,nmap:CUR.nmap,deep:CUR.deep,hardening:CUR.hardening,tools:CUR.tools,intel:CUR.intel});
}
function runAudit(ip,deep){
  MODAL_IP=ip;
  if(!deep){ api("/api/audit?ip="+encodeURIComponent(ip)+"&deep=0").then(r=>{ if(MODAL_IP===ip)mergeAudit(r); }); return; }
  const fsec=document.getElementById("sec-findings");
  if(fsec&&!CUR.findings.length)fsec.innerHTML='<h4>Findings</h4><div class="muted"><span class="spin"></span>deep audit: nmap + NSE scripts, open-stream/FTP/SNMP, 403-bypass &amp; the full intel toolchain — can take a couple of minutes…</div>';
  const db=document.getElementById("deepbtn"); if(db){db.disabled=true;db.textContent="auditing…";}
  api("/api/audit?ip="+encodeURIComponent(ip)+"&deep=1").then(r=>{
    if(db){db.disabled=false;db.textContent="↻ Re-run deep audit";}
    if(r&&r.error==="out_of_scope"){scopeBlocked(r,"deep");return;}
    if(r&&MODAL_IP===ip)mergeAudit(r);
  });
}
function runCreds(ip){
  const wc=document.getElementById("weakchk"); const weak=(wc&&wc.checked)?1:0;
  const msg=weak
    ?("Run a WEAK-PASSWORD audit against "+ip+"?\n\nTries factory defaults PLUS ~30 common weak passwords (capped, and it stops the moment the device locks out). It sends real login attempts the device logs and may briefly lock the account. Only on devices you OWN or are authorised to test.")
    :("Test factory / default passwords against "+ip+"?\n\nThis sends real login attempts the device logs. Only on devices you OWN or are authorised to test.");
  if(!confirm(msg))return;
  MODAL_IP=ip;
  const cb=document.getElementById("credbtn"); if(cb){cb.disabled=true;cb.textContent="testing logins…";}
  const cs=document.getElementById("credstatus"); if(cs)cs.innerHTML='<span class="spin"></span>'+(weak?'auditing passwords + lockout…':'trying factory logins…');
  api("/api/audit?ip="+encodeURIComponent(ip)+"&creds=1&weak="+weak).then(r=>{
    if(cb){cb.disabled=false;cb.textContent="↻ Re-test factory passwords";}
    if(!r||MODAL_IP!==ip)return;
    if(r.error==="out_of_scope"){scopeBlocked(r,"creds");return;}
    mergeAudit(r);
    if(cs){
      if(r.default_creds)cs.innerHTML='<span style="color:var(--red);font-weight:700">⚠ Factory login works — see findings.</span>';
      else if(r.creds_tested)cs.textContent='✓ Tried '+r.creds_tested+' factory logins — none worked.';
      else cs.textContent='No HTTP Basic/Digest login panel to test (device likely uses a form login).';
    }
  });
}
// ---- authorization scope / report / monitoring / engagement panels ----
function scopeBlocked(r,which){
  const h='<div class="warn">✕ <b>'+esc(r.ip)+' is outside your authorised scope.</b><br>'+
    'Active checks (nmap, open-stream, factory-password tests) are blocked until you authorise its network.'+
    '<br><button class="btn primary" style="margin-top:9px" onclick="authorizeNet(\''+escJs(r.cidr)+'\')">Authorise '+esc(r.cidr)+'</button></div>';
  if(which==="creds"){const cs=document.getElementById("credstatus");if(cs)cs.innerHTML=h;}
  else{const f=document.getElementById("sec-findings");if(f)f.innerHTML='<h4>Findings</h4>'+h;}
}
function authorizeNet(cidr){ api("/api/scope?add="+encodeURIComponent(cidr)).then(()=>{
  const cs=document.getElementById("credstatus"); if(cs)cs.innerHTML='<span style="color:var(--green)">✓ '+esc(cidr)+' authorised — click the button again to run the check.</span>';
  const f=document.getElementById("sec-findings"); if(f&&f.innerHTML.indexOf("outside your authorised")>-1)f.innerHTML='<h4>Findings</h4><div class="muted">✓ '+esc(cidr)+' authorised — click Deep audit again.</div>';
}); }
function openPanel(kind){
  document.getElementById("panel-title").textContent={scope:"Authorised scope",alerts:"Monitoring alerts",activity:"Engagement log",history:"History — timeline & anomalies",selfcheck:"System check — live data proof",intel:"Behavioral intelligence — what ViperScan has learned"}[kind]||"Panel";
  const body=document.getElementById("panel-body"); body.innerHTML='<div class="muted"><span class="spin"></span>loading…</div>';
  document.getElementById("panel").classList.add("on");
  if(kind==="scope")loadScope(body);
  else if(kind==="alerts"){ if(window.Notification&&Notification.permission==="default")Notification.requestPermission(); loadAlerts(body); }
  else if(kind==="activity")loadActivity(body);
  else if(kind==="selfcheck")loadSelfcheck(body);
  else if(kind==="history")loadHistory(body);
  else if(kind==="intel")loadIntel(body);
}
function huntDown(ip){
  closePanel();
  if(findDev(ip)){ openDevice(ip); setTimeout(()=>startLocate(ip),400); }
  else { flash("Attacker "+ip+" isn't in the current scan — run a scan, then Find it."); }
}
function loadIntel(body){
  api("/api/intel").then(r=>{
    if(!r){body.innerHTML='<div class="muted">no intel yet</div>';return;}
    let h='<div class="muted scd" style="margin-bottom:10px">ViperScan\'s own behavioral engine — it learns each device\'s normal over time, no external tools. '+
      'Tracking <b>'+r.tracked+'</b> devices over <b>'+r.observations+'</b> observations. The longer it runs, the smarter it gets.</div>';
    const an=r.anomalies||[];
    h+='<div class="sec"><h4>'+IC("alert")+' Immune system — deviations from normal ('+an.length+')</h4>';
    h+= an.length? an.map(a=>'<div class="finding '+(a.sev==="high"?"high":a.sev==="medium"?"medium":"low")+'"><div class="ft"><span class="sev '+(a.sev==="high"?"high":a.sev==="medium"?"medium":"low")+'">'+esc(a.sev)+'</span><span class="ti">'+esc(a.name||a.ip)+' — '+esc((a.kind||"").replace(/_/g," "))+'</span></div><div class="de">'+esc(a.detail)+'</div></div>').join('')
      : '<div class="muted">✓ Nothing abnormal — every tracked device is behaving within its learned baseline.</div>';
    h+='</div>';
    h+='<div class="sec"><h4>'+IC("sparkle")+' Device DNA — identity from behavior</h4>'+
      (r.devices||[]).map(d=>{const dn=d.dna||{},p=d.profile||{};
        return '<div class="dnarow"><div class="dnahead"><b>'+esc(d.name||d.ip||"?")+'</b> '+(d.online?'<span class="dot-on"></span>':'<span class="dot-off"></span>')+
          '<span class="dnaid">'+esc(dn.identity||"unknown")+' <span class="muted">'+(dn.confidence||0)+'%</span></span></div>'+
          '<div class="muted dnameta">link: <b>'+esc(p.link||"?")+'</b> · presence: <b>'+esc(p.presence||"?")+'</b>'+
          (p.rtt_mean!=null?' · ~'+p.rtt_mean+'ms (cv '+p.rtt_cv+')':'')+' · '+(p.samples||0)+' samples'+
          (p.ports_ever&&p.ports_ever.length?' · ports '+p.ports_ever.slice(0,8).join(","):"")+'</div>'+
          (dn.traits&&dn.traits.length?'<div class="dnatraits">'+dn.traits.map(t=>'<span class="trait">'+esc(t)+'</span>').join('')+'</div>':'')+
          '</div>';
      }).join('')+'</div>';
    body.innerHTML=h;
  });
}
function loadSelfcheck(body){
  body.innerHTML='<div class="muted"><span class="spin"></span>running live checks against your actual network — pinging, TLS handshake, SNMP, OUI db… (~10s)</div>';
  api("/api/selfcheck").then(r=>{
    if(!r){body.innerHTML='<div class="muted">self-check failed to run</div>';return;}
    const rows=(r.checks||[]).map(c=>'<div class="scrow"><span class="scmark '+(c.ok?"ok":"info")+'">'+(c.ok?"PASS":"INFO")+'</span>'+
      '<div class="scbody"><div class="scn">'+esc(c.name)+'</div><div class="muted scd">'+esc(c.detail)+'</div>'+
      (c.evidence?'<div class="scev">'+esc(c.evidence)+'</div>':'')+'</div></div>').join('');
    const tools=r.tools||null;
    let tsec='';
    if(tools){
      const ti=(tools.installed||[]).map(t=>'<span class="toolpill on">'+esc(t)+'</span>').join('');
      const tm=(tools.missing||[]).map(t=>'<span class="toolpill off">'+esc(t)+'</span>').join('');
      tsec='<div class="sec"><h4>Intel &amp; bypass tools detected on this machine</h4>'+
        '<div class="muted scd">Installed tools are auto-run in the Deep audit to extract more from each device. Greyed ones are optional — install them for deeper coverage.</div>'+
        '<div class="toolwrap">'+ti+tm+'</div></div>';
    }
    body.innerHTML='<div class="sec"><h4>Everything below is live data — nothing is simulated or spoofed</h4>'+
      '<div class="muted scd" style="margin-bottom:10px">'+r.passed+'/'+r.total+' subsystems returned real data at '+esc(r.ts||"")+'.</div>'+
      rows+'</div>'+tsec;
  });
}
function closePanel(){ document.getElementById("panel").classList.remove("on"); }
function loadScope(body){
  api("/api/scope").then(s=>{
    const list=s.authorized||[];
    body.innerHTML='<div class="sec"><h4>Networks you’re authorised to actively test</h4>'+
      (list.length?list.map(c=>'<div class="panelrow"><span class="u">'+esc(c)+'</span><button class="btn" onclick="scopeRemove(\''+escJs(c)+'\')">Remove</button></div>').join(''):
        '<div class="muted">No networks authorised yet — Deep audit &amp; password tests are blocked until you add one.</div>')+
      '</div><div class="sec">'+
      (CURRENT_CIDR?'<button class="btn primary" onclick="scopeAdd(\''+escJs(CURRENT_CIDR)+'\')">✓ Authorise current network ('+esc(CURRENT_CIDR)+')</button>':'')+
      '<div style="margin-top:10px"><input id="scopeinput" placeholder="e.g. 10.0.0.0/24" spellcheck="false"> <button class="btn" onclick="scopeAddInput()">Add CIDR</button></div>'+
      '<div class="deepnote">Only add networks you own or have written authorisation to test. The quiet audit runs everywhere; nmap, open-stream and password tests run only inside these ranges.</div></div>';
  });
}
function scopeAdd(c){ api("/api/scope?add="+encodeURIComponent(c)).then(()=>openPanel("scope")); }
function scopeAddInput(){ const v=document.getElementById("scopeinput").value.trim(); if(v)scopeAdd(v); }
function scopeRemove(c){ api("/api/scope?remove="+encodeURIComponent(c)).then(()=>openPanel("scope")); }
function loadAlerts(body){
  api("/api/events").then(s=>{
    const ev=s.events||[];
    body.innerHTML='<div class="sec"><h4>Recent network changes</h4>'+
      (ev.length?ev.map(e=>'<div class="evrow ev-'+esc(e.type)+'"><span class="evt">'+esc((e.type||"").replace(/_/g," "))+'</span><b>'+esc(e.ip)+'</b> '+esc(e.detail)+'<div class="evts">'+esc(e.ts)+'</div></div>').join(''):
        '<div class="muted">No changes recorded yet. Alerts appear when a device joins or leaves, opens a new port, or becomes reachable from the internet.</div>')+'</div>';
  });
}
function loadActivity(body){
  api("/api/engagement").then(s=>{
    const log=s.log||[];
    body.innerHTML='<div class="sec"><h4>Engagement log — every active action you ran</h4>'+
      (log.length?log.map(e=>'<div class="evrow"><span class="evt">'+esc((e.kind||"").replace(/_/g," "))+'</span><b>'+esc(e.target)+'</b> '+esc(e.detail)+'<div class="evts">'+esc(e.ts)+'</div></div>').join(''):
        '<div class="muted">No active actions logged yet. Deep audits, password tests, scope changes and reports are recorded here.</div>')+'</div>';
  });
}
function cvssClass(s){return s>=9?'c':s>=7?'h':s>=4?'m':'l';}
const RC={green:"var(--green)",blue:"var(--blue)",amber:"var(--amber)",red:"var(--red)"};
function renderRisk(risk){
  const sec=document.getElementById("sec-risk"); if(!sec||!risk)return;
  const col=RC[risk.color]||"var(--dim)";
  sec.innerHTML='<h4>Risk</h4><div class="risk">'+
    '<div class="ring" style="--p:'+risk.score+';--rc:'+col+'"><i>'+risk.score+'</i></div>'+
    '<div><div class="lbl" style="color:'+col+'">'+risk.label+'</div><div class="sub">'+risk.score+'/100 risk score</div></div></div>';
}
function renderBypass(b){
  let h='<div class="bypassbox">';
  const acts=[];
  if(b.view_id)acts.push('<a class="openbtn" href="/api/bypass/view?id='+encodeURIComponent(b.view_id)+'" target="_blank" rel="noopener">▶ Open the bypassed page ↗</a>');
  if(b.url)acts.push('<a class="openbtn" href="'+esc(b.url)+'" target="_blank" rel="noopener">Open URL ↗</a>');
  if(acts.length)h+='<div class="bypassacts">'+acts.join('')+'</div>';
  if(b.snippet)h+='<div class="muted" style="margin-top:6px">page preview: '+esc(b.snippet)+'…</div>';
  if(b.curl)h+='<div class="muted" style="margin-top:7px">reproduce'+(b.technique?(' ('+esc(b.technique)+')'):'')+':</div>'+
    '<div class="curlrow"><code class="loccmd curlcode">'+esc(b.curl)+'</code>'+
    '<button class="btn copybtn" onclick="copyText(this)">copy</button></div>';
  h+='</div>';
  return h;
}
function copyText(btn){
  const code=btn.parentElement.querySelector("code"); if(!code)return;
  const t=code.textContent, done=()=>{const o=btn.textContent;btn.textContent="copied ✓";setTimeout(()=>btn.textContent=o,1200);};
  if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(t).then(done,()=>fallbackCopy(t,done));
  else fallbackCopy(t,done);
}
function fallbackCopy(t,done){
  const ta=document.createElement("textarea");ta.value=t;ta.style.position="fixed";ta.style.opacity="0";
  document.body.appendChild(ta);ta.select();try{document.execCommand("copy");if(done)done();}catch(e){}
  document.body.removeChild(ta);
}
function renderFindings(r){
  const sec=document.getElementById("sec-findings"); if(!sec)return;
  const fs=r.findings||[];
  let html='';
  const intel=r.intel||[];
  if(intel.length){
    html+='<div style="margin-bottom:14px"><h4 style="margin-bottom:9px">'+IC('search')+' Device intelligence</h4>'+
      '<div class="kv">'+intel.map(it=>'<div class="k">'+esc(it.label)+'</div><div class="v" style="word-break:break-word">'+esc(it.value)+'</div>').join('')+'</div></div>';
  }
  html+='<h4>Findings ('+fs.length+')</h4>';
  if(!fs.length){ html+='<div class="muted">No issues found in '+(r.deep?'the deep audit':'the quiet checks')+'.'+
    (r.deep?'':' Run a deep audit for nmap, open-stream &amp; factory-password checks.')+'</div>'; }
  else html+=fs.map(f=>'<div class="finding '+f.severity+'"><div class="ft"><span class="sev '+f.severity+'">'+f.severity+
    '</span><span class="ti">'+esc(f.title)+'</span></div>'+
    (f.detail?'<div class="de">'+esc(f.detail)+'</div>':'')+
    (f.cves&&f.cves.length?'<div class="cves">'+f.cves.map(c=>'<div class="cverow">'+
      '<a href="https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(c.id)+'" target="_blank" rel="noopener">'+esc(c.id)+'</a>'+
      '<span class="cvss '+cvssClass(c.cvss)+'">CVSS '+c.cvss+'</span>'+
      '<span class="cdesc">'+esc(c.desc)+'</span></div>').join('')+'</div>':'')+
    (f.bypass?renderBypass(f.bypass):'')+
    (f.recommendation?'<div class="rec">→ '+esc(f.recommendation)+'</div>':'')+'</div>').join("");
  if(r.nmap&&(r.nmap.nmap_os||r.nmap.nmap_services))
    html+='<div class="muted" style="margin-top:8px">nmap: '+esc(r.nmap.nmap_os||"")+' '+esc(r.nmap.nmap_services||"")+'</div>';
  const tx=r.tools||null;
  if(tx&&(tx.intel||[]).length){
    html+='<div style="margin-top:14px"><h4 style="margin-bottom:9px">'+IC('search')+' Extra intel'+
      (tx.ran&&tx.ran.length?' <span class="muted" style="font-weight:400">('+esc(tx.ran.join(", "))+')</span>':'')+'</h4>'+
      tx.intel.map(t=>'<div class="hrow"><b>'+esc(t.title)+'</b> <span class="toolpill on" style="font-size:10px">'+esc(t.tool)+'</span>'+
        '<div class="hd" style="word-break:break-word">'+esc(t.detail)+'</div></div>').join('')+'</div>';
  }
  if(r.hardening&&r.hardening.length)
    html+='<div style="margin-top:14px"><h4 style="margin-bottom:9px">'+IC('shield')+' How to bulletproof this device</h4>'+
      r.hardening.map(h=>'<div class="hrow"><b>'+esc(h.title)+'</b><div class="hd">'+esc(h.detail)+'</div></div>').join('')+'</div>';
  sec.innerHTML=html;
}
function renderPanels(p,ip){
  const sec=document.getElementById("sec-panels"); if(!sec)return;
  const panels=(p&&p.panels)||[], best=p&&p.best_url;
  if(!panels.length){ sec.innerHTML='<h4>Web / admin panels</h4><div class="muted">No reachable web panel on this device.</div>'; return; }
  sec.innerHTML='<h4>Web / admin panels</h4>'+
    panels.map(pa=>'<div class="panelrow"><span class="u">'+esc(pa.url)+'</span>'+
      (pa.url===best?'<span class="badge-best">best</span>':'')+
      '<span class="st">'+pa.status+(pa.title?(" · "+esc(pa.title)):(pa.server?(" · "+esc(pa.server)):""))+'</span>'+
      '<a class="openbtn" href="'+esc(pa.url)+'" target="_blank" rel="noopener">Open ↗</a></div>').join("");
}
function renderDeep(r){
  const sec=document.getElementById("sec-deep"); if(!sec)return;
  let html='<h4>Deep probe</h4>';
  if(r.default_creds){ const c=r.default_creds;
    html+='<div class="warn">⚠ <b>Factory login still works</b> — <b>'+esc(c.user)+' / '+esc(c.password)+'</b> opened <span style="font-family:ui-monospace,monospace">'+esc(c.url)+'</span>.<br>Change this password now.</div>';
  } else if(r.creds_tested){ html+='<div class="muted">✓ Tried '+r.creds_tested+' known factory logins — none worked.</div>';
  } else { html+='<div class="muted">No HTTP Basic-auth panel to test (device likely uses a form login, which isn\'t auto-tested).</div>'; }
  const n=r.nmap||{};
  if(n.nmap_os||n.nmap_services){ html+='<div class="kv" style="margin-top:11px">';
    if(n.nmap_os)html+='<div class="k">OS fingerprint</div><div class="v">'+esc(n.nmap_os)+(n.nmap_os_conf==="guess"?' <span class="muted">(nmap guess — unreliable for phones/IoT)</span>':'')+'</div>';
    if(n.nmap_services)html+='<div class="k">Services</div><div class="v">'+esc(n.nmap_services)+'</div>'; html+='</div>'; }
  if(r.catchall)html+='<div class="muted" style="margin-top:9px">Server answers 200 on any path (single-page app) — path enumeration skipped.</div>';
  else if((r.paths||[]).length)html+='<div style="margin-top:9px"><div class="muted">Notable paths:</div>'+r.paths.map(p=>'<div class="muted">• '+esc(p.path)+' ('+p.status+(p.title?(" "+esc(p.title)):"")+')</div>').join("")+'</div>';
  sec.innerHTML=html;
}

document.querySelectorAll(".chip").forEach(c=>c.onclick=()=>{
  document.querySelectorAll(".chip").forEach(x=>x.classList.remove("on"));
  c.classList.add("on"); FILTER=c.dataset.f; draw();
});
document.querySelectorAll("#modeseg button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#modeseg button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on");
  const m=b.dataset.mode;
  document.getElementById("modehint").textContent=MODE_HINT[m]||"";
  flash("rescanning in "+m+" mode…");
  api("/api/set?mode="+m+"&scan=1");
});
document.getElementById("scanbtn").onclick=()=>{
  const net=document.getElementById("netinput").value.trim();
  flash("scanning "+(net||"current LAN")+"…");
  api("/api/set?net="+encodeURIComponent(net)+"&scan=1");
};
document.getElementById("rescan").onclick=()=>{flash("rescanning…");api("/api/scan");};
document.getElementById("interval").onchange=e=>api("/api/set?interval="+e.target.value);

function flash(msg){const st=document.getElementById("status");st.textContent=msg;}

// ---- top-bar Monitor Mode toggle (arms the Wi-Fi sniffer adapter) ----
let SNIFFER={on:false,iface:null};
function setSnif(t){const s=document.getElementById("sniflabel");if(s)s.innerHTML=t;}
function applySniffer(s){
  SNIFFER.on=!!s.on; SNIFFER.iface=s.iface||null;
  const b=document.getElementById("snifferbtn"); if(b)b.classList.toggle("on",SNIFFER.on);
  setSnif(SNIFFER.on?("Monitor ON"+(SNIFFER.iface?(" · "+esc(SNIFFER.iface)):"")):"Monitor&nbsp;Mode");
}
function refreshSniffer(){ api("/api/sniffer").then(s=>{ if(s)applySniffer(s); }); }
function snifferError(r){
  const e=r.error||"", reason=r.reason||"";
  const msg = reason ? ("Monitor mode failed — "+reason)
    : e==="needs_root"?"Monitor mode needs the dashboard run with sudo."
    : e==="needs_iw"?"Install iw:  sudo apt install iw"
    : e==="no_adapter"?"No monitor-capable Wi-Fi adapter found — plug in your A8000."
    : e==="monitor_failed"?("Couldn't put "+(r.iface||"the adapter")+" into monitor mode.")
    : ("Monitor mode error: "+(e||"unknown"));
  flash(msg);
  const b=document.getElementById("snifferbtn");
  if(r.fix){ if(b)b.title="Manual fix — "+r.fix; console.warn("ViperScan monitor-mode manual fix:\n"+r.fix); }
}
function toggleSniffer(){
  const b=document.getElementById("snifferbtn"); if(b)b.disabled=true;
  const turningOn=!SNIFFER.on;
  setSnif(turningOn?"arming…":"disarming…");
  api(turningOn?"/api/sniffer/on":"/api/sniffer/off").then(r=>{
    if(b)b.disabled=false;
    if(r&&r.ok===false){ snifferError(r); }
    else flash(turningOn?("✓ Monitor mode ON"+(r&&r.iface?(" — "+r.iface):"")+" · the Find button is ready."):"Monitor mode off — adapter back to normal Wi-Fi.");
    refreshSniffer();
  });
}
function matches(d){
  if(FILTER==="all")return true;
  if(FILTER==="alert")return d.is_alert;
  if(FILTER==="camera")return d.category==="camera"||(d.flags||[]).includes("CAMERA?");
  if(FILTER==="voice")return d.category==="voice";
  if(FILTER==="unknown")return (d.category==="unknown"||(d.flags||[]).includes("UNKNOWN"))&&!d.user_label;
  if(FILTER==="new")return (d.flags||[]).includes("NEW");
  return true;
}
function flagClass(f){return f.replace("?","q").replace(/[^A-Za-z]/g,"");}
function esc(s){return (s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
// escJs: safe for a value placed INSIDE a single-quoted JS string literal in an
// onclick= handler. esc() does NOT escape ' or \, so any attacker-influenced field
// (WebRTC IPs, cid, fingerprint, src) routed through an onclick needs THIS instead.
function escJs(s){return (s||"").replace(/[\\'"<>\r\n]/g,c=>({"\\":"\\\\","'":"\\'",'"':"\\\"","<":"\\x3c",">":"\\x3e","\r":"","\n":""}[c]));}
function idLine(d){
  const s=d.services||{};
  for(const k of ["snmp","nmap_os","nmap_services","ssdp_model"]){
    if(s[k])return esc((k==="snmp"?"SNMP: ":k==="nmap_os"?"OS: ":k==="nmap_services"?"services: ":"model: ")+s[k]);
  }
  return "";
}
function card(d){
  const cls=["card"]; if(d.is_alert)cls.push("alert"); if(d.category==="camera")cls.push("cam");
  const flags=(d.flags||[]).map(f=>`<span class="flag ${flagClass(f)}">${f}</span>`).join("");
  const ports=Object.entries(d.open_ports||{}).slice(0,8).map(([p,l])=>`${p}`).join(" · ");
  const reasons=(d.flag_reasons||[]).map(r=>`<li>${esc(r)}</li>`).join("");
  const id=idLine(d);
  const mark=d.is_self?' <span class="tag">(this device)</span>':d.is_gateway?' <span class="tag">(gateway)</span>':'';
  const trustmark=d.trust==="trusted"?' <span class="tmark t-ok">trusted</span>':d.trust==="untrusted"?' <span class="tmark t-bad">untrusted</span>':'';
  const tags=(d.tags&&d.tags.length)?`<div class="tags2">${d.tags.map(t=>`<span class="tag2">${esc(t)}</span>`).join('')}</div>`:'';
  return `<div class="${cls.join(' ')}" onclick="cardClick(event,'${escJs(d.ip)}')" oncontextmenu="cardMenu(event,'${escJs(d.ip)}')">
    <div class="top"><div class="ico ico-${d.category||'unknown'}">${catIcon(d)}</div>
      <div style="flex:1;min-width:0">
        <div class="name">${esc(d.display_name||d.device_type)}${mark}${trustmark}</div>
        <div class="ip">${d.ip}</div>
      </div></div>
    ${d.mac?`<div class="mac">${d.mac}</div>`:""}
    ${d.vendor?`<div class="vendor">${esc(d.vendor)}</div>`:""}
    ${tags}
    ${flags?`<div class="flags">${flags}</div>`:""}
    ${ports?`<div class="ports">ports: ${ports}</div>`:""}
    ${id?`<div class="idline">${id}</div>`:""}
    ${reasons?`<details><summary>why flagged</summary><ul>${reasons}</ul></details>`:""}
  </div>`;
}
function draw(){
  if(VIEW==="map")return;          // the map render loop handles map view
  const g=document.getElementById("grid");
  const list=DEV.filter(matches).sort((a,b)=>(b.is_alert-a.is_alert)||(ip2n(a.ip)-ip2n(b.ip)));
  g.innerHTML=list.map(card).join("");
  document.getElementById("empty").style.display=list.length?"none":"block";
}

// ---------------- network map visualizer (pure canvas) ----------------
let VIEW="grid", MAP_RAF=null, MAP_HOVER=null, MAP_NODES=[];
const CATCOLOR={camera:"#ff5d6c",voice:"#b98bff",media:"#5aa6ff",printer:"#43e0a0",network:"#34e27a",computer:"#9aa7bd",mobile:"#5aa6ff",iot:"#ffc14d",unknown:"#8595ad"};
function setView(v){
  VIEW=v;
  document.getElementById("vt-grid").classList.toggle("on",v==="grid");
  document.getElementById("vt-map").classList.toggle("on",v==="map");
  const grid=document.getElementById("grid"),empty=document.getElementById("empty"),wrap=document.getElementById("netmap-wrap");
  if(v==="map"){ grid.style.display="none";empty.style.display="none";wrap.style.display="block"; sizeCanvas(); startMap(); }
  else { wrap.style.display="none";grid.style.display=""; stopMap(); draw(); }
}
function sizeCanvas(){
  const cv=document.getElementById("netmap"); if(!cv)return;
  const dpr=window.devicePixelRatio||1, rect=cv.getBoundingClientRect();
  cv.__w=Math.max(320,rect.width); cv.__h=640;
  cv.width=cv.__w*dpr; cv.height=cv.__h*dpr;
  cv.getContext("2d").setTransform(dpr,0,0,dpr,0,0);
}
function startMap(){ stopMap(); const loop=()=>{ if(VIEW!=="map")return; drawMap(); MAP_RAF=requestAnimationFrame(loop); }; loop(); }
function stopMap(){ if(MAP_RAF){cancelAnimationFrame(MAP_RAF);MAP_RAF=null;} }
function drawMap(){
  const cv=document.getElementById("netmap"); if(!cv)return;
  const ctx=cv.getContext("2d"), w=cv.__w||cv.width, h=cv.__h||cv.height, cx=w/2, cy=h/2, maxR=Math.min(w,h)/2-30;
  ctx.clearRect(0,0,w,h);
  const list=DEV.filter(matches), others=list.filter(d=>!d.is_gateway);
  ctx.strokeStyle="rgba(255,255,255,0.05)"; ctx.lineWidth=1;
  for(let r=80;r<maxR;r+=Math.max(60,(maxR-80)/4)){ ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.stroke(); }
  const t=performance.now()/1000, sweep=(t*0.7)%(Math.PI*2);
  for(let k=0;k<48;k++){ const a=sweep-k*0.025; ctx.strokeStyle="rgba(52,226,122,"+(0.10*(1-k/48))+")"; ctx.lineWidth=1.5;
    ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(cx+Math.cos(a)*maxR,cy+Math.sin(a)*maxR);ctx.stroke(); }
  MAP_NODES=[]; const per=14;
  others.forEach((d,i)=>{ const ring=Math.floor(i/per), cnt=Math.min(per,others.length-ring*per), idx=i-ring*per,
    radius=Math.min(95+ring*Math.max(70,(maxR-95)/3),maxR), ang=(idx/Math.max(1,cnt))*Math.PI*2-Math.PI/2+ring*0.4;
    d.__x=cx+Math.cos(ang)*radius; d.__y=cy+Math.sin(ang)*radius; MAP_NODES.push(d); });
  others.forEach(d=>{ ctx.strokeStyle=d.is_alert?"rgba(255,93,108,0.28)":"rgba(255,255,255,0.07)"; ctx.lineWidth=d.is_alert?1.5:1;
    ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(d.__x,d.__y);ctx.stroke(); });
  others.forEach(d=>drawNode(ctx,d,t));
  ctx.beginPath();ctx.arc(cx,cy,18,0,Math.PI*2); ctx.fillStyle="rgba(52,226,122,.18)"; ctx.fill();
  ctx.lineWidth=2; ctx.strokeStyle="#34e27a"; ctx.stroke();
  ctx.beginPath();ctx.arc(cx,cy,5,0,Math.PI*2);ctx.fillStyle="#34e27a";ctx.fill();
  ctx.font="11px ui-sans-serif"; ctx.fillStyle="#8595ad"; ctx.fillText("gateway",cx,cy+31);
  const tip=document.getElementById("maptip"), hv=MAP_NODES.find(d=>d.ip===MAP_HOVER);
  if(hv&&tip){ tip.style.display="block"; tip.style.left=hv.__x+"px"; tip.style.top=hv.__y+"px"; tip.textContent=(hv.display_name||hv.device_type)+" · "+hv.ip; }
  else if(tip){ tip.style.display="none"; }
}
function drawNode(ctx,d,t){
  const col=CATCOLOR[d.category]||"#8595ad", r=(d.is_alert?11:9)+(d.ip===MAP_HOVER?2:0);
  if(d.is_alert){ const p=0.5+0.5*Math.sin(t*3); ctx.beginPath();ctx.arc(d.__x,d.__y,r+5*p,0,Math.PI*2); ctx.fillStyle="rgba(255,93,108,"+(0.10*p)+")"; ctx.fill(); }
  ctx.beginPath();ctx.arc(d.__x,d.__y,r,0,Math.PI*2); ctx.fillStyle=col+"33"; ctx.fill();
  ctx.lineWidth=d.is_alert?2.5:1.5; ctx.strokeStyle=d.is_alert?"#ff5d6c":col; ctx.stroke();
  ctx.beginPath();ctx.arc(d.__x,d.__y,3,0,Math.PI*2); ctx.fillStyle=col; ctx.fill();
}
(function(){
  const cv=()=>document.getElementById("netmap");
  document.addEventListener("mousemove",e=>{ if(VIEW!=="map")return; const c=cv(); if(!c)return;
    const rect=c.getBoundingClientRect(), x=e.clientX-rect.left, y=e.clientY-rect.top; let hit=null;
    for(const d of MAP_NODES){ const dx=d.__x-x,dy=d.__y-y; if(dx*dx+dy*dy<220){hit=d.ip;break;} } MAP_HOVER=hit; });
  document.addEventListener("click",e=>{ if(VIEW!=="map")return; const c=cv(); if(!c||e.target!==c)return;
    const rect=c.getBoundingClientRect(), x=e.clientX-rect.left, y=e.clientY-rect.top;
    for(const d of MAP_NODES){ const dx=d.__x-x,dy=d.__y-y; if(dx*dx+dy*dy<220){ openDevice(d.ip); break; } } });
  window.addEventListener("resize",()=>{ if(VIEW==="map")sizeCanvas(); });
})();
function ip2n(ip){return (ip||"").split(".").reduce((a,o)=>a*256+(+o),0);}
function syncControls(cfg){
  if(!cfg)return;
  document.querySelectorAll("#modeseg button").forEach(b=>b.classList.toggle("on",b.dataset.mode===cfg.mode));
  document.getElementById("modehint").textContent=MODE_HINT[cfg.mode]||"";
  const sel=document.getElementById("interval");
  if(document.activeElement!==sel && cfg.interval){
    const v=String(Math.round(cfg.interval));
    if(!Array.from(sel.options).some(o=>o.value===v)){   // a --watch/persisted value
      const o=document.createElement("option");          // that isn't a preset: add it
      o.value=v; o.textContent="every "+v+"s"; sel.appendChild(o);
    }
    sel.value=v;
  }
  const ni=document.getElementById("netinput");
  if(document.activeElement!==ni)ni.placeholder=cfg.net||"auto (current LAN)";
  const ka=document.getElementById("kabtn");
  if(ka){ const on=cfg.keepalive!==false; ka.classList.toggle("on",on);
    const l=document.getElementById("kalabel"); if(l)l.innerHTML=on?"Keep-alive&nbsp;ON":"Keep-alive&nbsp;off"; }
}
function toggleKeepalive(){
  const on=!document.getElementById("kabtn").classList.contains("on");
  api("/api/set?keepalive="+(on?1:0)).then(()=>flash(on?"Keep-alive on — constantly pinging every device to keep it live.":"Keep-alive off."));
}
let BUILD=null;
async function poll(){
  const s=await api("/api/devices");
  if(!s){document.getElementById("status").textContent="reconnecting…";return;}
  if(s.build){ if(BUILD&&s.build!==BUILD){location.reload();return;} BUILD=s.build; }
  DEV=s.devices||[]; const m=s.meta||{};
  CURRENT_CIDR=m.cidr||"";
  const ev=s.events||[];
  const ac=document.getElementById("alertcount"); if(ac)ac.textContent=ev.length;
  if(LAST_EVENTS!==null && ev.length>LAST_EVENTS && window.Notification && Notification.permission==="granted"){
    const top=ev[0]; new Notification("ViperScan: network change",{body:top?(top.type.replace(/_/g," ")+" — "+top.ip+" "+top.detail):""});
  }
  LAST_EVENTS=ev.length;
  syncControls(s.config);
  document.getElementById("net").textContent=(m.cidr||"—")+(m.iface?(" · "+m.iface):"");
  document.getElementById("c-live").textContent=DEV.length;
  document.getElementById("c-alert").textContent=DEV.filter(d=>d.is_alert).length;
  document.getElementById("c-cam").textContent=DEV.filter(d=>d.category==="camera").length;
  const dot=document.getElementById("dot"),st=document.getElementById("status");
  const rescan=document.getElementById("rescan");
  BUSY=!!s.scanning; rescan.disabled=BUSY;
  if(BUSY){dot.classList.add("busy");st.textContent="scanning ("+(s.config?s.config.mode:"")+")…";}
  else{dot.classList.remove("busy");
    if(m.error)st.textContent="error: "+m.error;
    else st.textContent=m.timestamp?("updated "+m.timestamp.split(" ")[1]):"idle";}
  draw();
}
document.querySelectorAll('[data-icon]').forEach(el=>el.insertAdjacentHTML('afterbegin', IC(el.dataset.icon)));
poll(); setInterval(poll,2000);
refreshSniffer(); setInterval(refreshSniffer,12000);
function refreshIntelBadge(){ api("/api/intel").then(r=>{ const b=document.getElementById("anomcount"); if(b&&r){ b.textContent=(r.anomalies||[]).length; b.style.display=(r.anomalies||[]).length?"":"none"; } }); }
refreshIntelBadge(); setInterval(refreshIntelBadge,30000);

</script>
<div id="ctxmenu"></div>
<div id="helpov" onclick="if(event.target===this)hideHelp()">
  <div class="hbox">
    <h3>⌨ Keyboard shortcuts</h3>
    <div class="hrow"><span>Scan / rescan now</span><kbd>s</kbd></div>
    <div class="hrow"><span>Export inventory (JSON)</span><kbd>e</kbd></div>
    <div class="hrow"><span>Jump to network field</span><kbd>/</kbd></div>
    <div class="hrow"><span>Close modal / menu</span><kbd>Esc</kbd></div>
    <div class="hrow"><span>This help</span><kbd>?</kbd></div>
    <div class="hrow" style="margin-top:8px;color:var(--dim2,#6b7785)"><span>Right-click a device for copy / lookup</span><span></span></div>
  </div>
</div>
</body></html>
"""
