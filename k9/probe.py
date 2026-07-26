"""On-demand deep probe of a single device, triggered when you click it.

This is the "tell me everything and open it up" path. It runs three things:

  1. panels()      — fast: which web/admin URLs actually respond, and the best
                     one to open in a browser tab.
  2. investigate()  — deep: panels() + nmap service/version + common admin-path
                     checks + a *default-credential* check for the device's
                     vendor.

The default-credential check only makes sense on a network you own — it tells
you which of *your* devices are still sitting on factory passwords so you can
fix them. It is intentionally conservative: HTTP Basic-auth only (no form
brute-forcing), a short vendor-targeted list, capped attempts, and it stops at
the first hit. Run it only against your own gear.

Stdlib only, except it reuses the project's existing nmap helper.
"""

from __future__ import annotations

import base64
import re
import socket
import ssl

from . import fingerprint

# Ports we'll treat as candidate web/admin panels, in rough "open this first"
# order. 7547 (TR-069) is intentionally absent — it isn't a browser UI.
_PREF = [80, 443, 8080, 8443, 8000, 81, 8081, 8888, 8008, 5000, 3000, 9000, 9443]
_TLS_PORTS = {443, 8443, 8883, 9443}
_ADMIN_PATHS = [
    "/login", "/admin", "/setup", "/index.htm", "/main.html",
    "/cgi-bin/luci", "/onvif/device_service", "/doc/page/login.asp",
]
# A path that should never exist, used to detect "returns 200 for everything"
# single-page apps so we don't report bogus path hits.
_NX_PATH = "/viperscan_nonexistent_zzq_404_check"

# Small, vendor-targeted default-credential sets. Defenders' shortlist, not an
# exhaustive brute-force dictionary.
_COMMON_CREDS = [
    ("admin", "admin"), ("admin", ""), ("admin", "password"), ("admin", "admin123"),
    ("admin", "1234"), ("admin", "12345"), ("admin", "123456"), ("root", "root"),
    ("root", "admin"), ("root", ""), ("user", "user"), ("guest", "guest"),
    ("support", "support"),
]
_VENDOR_CREDS = {
    "hikvision": [("admin", "12345"), ("admin", "Admin12345")],
    "dahua": [("admin", "admin"), ("888888", "888888"), ("666666", "666666")],
    "axis": [("root", "pass"), ("root", "root"), ("root", "axis")],
    "reolink": [("admin", "")],
    "foscam": [("admin", ""), ("admin", "admin")],
    "amcrest": [("admin", "admin")],
    "lorex": [("admin", "000000")],
    "swann": [("admin", "")],
    "vivotek": [("root", "")],
    "tp-link": [("admin", "admin")],
    "tplink": [("admin", "admin")],
    "netgear": [("admin", "password")],
    "linksys": [("admin", "admin")],
    "d-link": [("admin", ""), ("admin", "admin")],
    "zyxel": [("admin", "1234")],
    "asus": [("admin", "admin")],
    "mikrotik": [("admin", "")],
    "ubiquiti": [("ubnt", "ubnt")],
    "synology": [("admin", "")],
    "qnap": [("admin", "admin")],
    "hp": [("admin", "")],
    "canon": [("ADMIN", "canon")],
    "epson": [("EPSONWEB", "admin")],
}


def _scheme_for(port: int) -> str:
    return "https" if port in _TLS_PORTS else "http"


def http_probe(ip: str, port: int, scheme: str = "http", path: str = "/",
               timeout: float = 2.0, auth: tuple[str, str] | None = None,
               headers: dict | None = None) -> dict | None:
    """One HTTP(S) request. Returns parsed status/headers/title, or None if the
    socket never connected (so we can tell 'no service' from 'service said 401').

    *auth* sends HTTP Basic; *headers* lets callers send anything else (e.g. a
    computed Digest Authorization header)."""
    raw = b""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        if scheme == "https":
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        req = (f"GET {path} HTTP/1.1\r\nHost: {ip}\r\n"
               "User-Agent: ViperScan\r\nAccept: */*\r\nConnection: close\r\n")
        if auth is not None:
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            req += f"Authorization: Basic {token}\r\n"
        for hk, hv in (headers or {}).items():
            req += f"{hk}: {hv}\r\n"
        req += "\r\n"
        sock.sendall(req.encode())
        while len(raw) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
    except Exception:
        return None

    text = raw.decode("latin-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    status = 0
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", head)
    if m:
        status = int(m.group(1))

    def hdr(name: str) -> str:
        mm = re.search(rf"^{name}:\s*(.+)$", head, re.I | re.M)
        return mm.group(1).strip() if mm else ""

    title = ""
    mt = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if mt:
        title = re.sub(r"\s+", " ", mt.group(1)).strip()[:120]

    return {
        "port": port, "scheme": scheme, "url": f"{scheme}://{ip}:{port}/",
        "status": status, "server": hdr("Server")[:120],
        "auth": hdr("WWW-Authenticate")[:120], "location": hdr("Location")[:200],
        "title": title,
    }


def _candidate_ports(open_ports) -> list[int]:
    ports = [int(p) for p in (open_ports or {})]
    web = [p for p in ports if p in _PREF]
    if not web:                       # quiet device — try the usual suspects
        web = [80, 443, 8080]
    # keep _PREF ordering, de-duplicated
    seen, ordered = set(), []
    for p in _PREF + web:
        if p in web and p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


def _rank(panel: dict) -> tuple:
    # A live login/landing page (200/401) beats a redirect (301/302), which
    # beats a 403, which beats an error/4xx. Ties broken by port preference.
    s = panel["status"]
    tier = {200: 0, 401: 0, 302: 1, 301: 1, 403: 2}.get(s, 3 if s else 4)
    try:
        pidx = _PREF.index(panel["port"])
    except ValueError:
        pidx = len(_PREF)
    return (tier, pidx)


def panels(ip: str, open_ports=None, timeout: float = 2.0) -> dict:
    """Fast: probe candidate web ports, return responding panels + best URL."""
    found = []
    for port in _candidate_ports(open_ports):
        r = http_probe(ip, port, _scheme_for(port), "/", timeout)
        if r and r["status"]:
            found.append(r)
    found.sort(key=_rank)
    return {"panels": found, "best_url": found[0]["url"] if found else ""}


def _creds_for(vendor: str) -> list[tuple[str, str]]:
    v = (vendor or "").lower()
    creds: list[tuple[str, str]] = []
    for key, lst in _VENDOR_CREDS.items():
        if key in v:
            creds.extend(lst)
    creds.extend(_COMMON_CREDS)
    out, seen = [], set()
    for c in creds:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out[:10]


def _check_default_creds(ip: str, panel: dict, vendor: str, timeout: float) -> dict | None:
    """If a panel uses HTTP Basic auth, see whether a factory login opens it."""
    if "basic" not in (panel.get("auth") or "").lower():
        return None
    for user, pw in _creds_for(vendor):
        r = http_probe(ip, panel["port"], panel["scheme"], "/", timeout, auth=(user, pw))
        if r and r["status"] in (200, 301, 302):
            return {"url": panel["url"], "user": user,
                    "password": pw or "(blank)", "status": r["status"]}
    return None


def investigate(ip: str, vendor: str = "", open_ports=None, *,
                do_nmap: bool = True, do_creds: bool = True,
                timeout: float = 2.0) -> dict:
    """Deep, on-demand probe used by the dashboard when a device is clicked."""
    result: dict = {"ip": ip, "panels": [], "best_url": "", "paths": [],
                    "nmap": {}, "default_creds": None, "creds_tested": 0,
                    "catchall": False}

    pan = panels(ip, open_ports, timeout)
    result["panels"] = pan["panels"]
    result["best_url"] = pan["best_url"]

    # Probe a handful of common admin paths against the best panel — but first
    # fetch a path that can't exist. If THAT returns 200, the server answers
    # everything with its app shell (a single-page app), so individual path
    # "hits" are meaningless and we suppress them.
    if pan["panels"]:
        top = pan["panels"][0]
        bogus = http_probe(ip, top["port"], top["scheme"], _NX_PATH, timeout)
        catchall = bool(bogus and bogus["status"] == 200)
        result["catchall"] = catchall
        base_title = (bogus or {}).get("title", "")
        for path in _ADMIN_PATHS:
            r = http_probe(ip, top["port"], top["scheme"], path, timeout)
            if not r or not r["status"] or r["status"] == 404:
                continue
            if catchall and r["status"] == 200 and r["title"] == base_title:
                continue  # same shell the catch-all returns — not a real hit
            result["paths"].append({"path": path, "status": r["status"],
                                    "title": r["title"]})

    if do_nmap:
        result["nmap"] = fingerprint.nmap_deep(ip, timeout=25.0)

    # Default-credential check against any Basic-auth panel.
    if do_creds:
        tested = 0
        for panel in pan["panels"]:
            if "basic" in (panel.get("auth") or "").lower():
                tested += len(_creds_for(vendor))
                hit = _check_default_creds(ip, panel, vendor, timeout)
                if hit:
                    result["default_creds"] = hit
                    break
        result["creds_tested"] = tested

    return result
