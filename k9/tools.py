"""External intel & bypass orchestration — squeeze every drop from each device.

During a Deep audit (scope-gated, authorized targets only) ViperScan auto-runs
any best-of-breed pentest tools it finds installed on this machine and folds
their output back into the device's findings plus an "extra intel" section:

    whatweb       web technology fingerprint
    nuclei        templated vulnerability scan
    nmap NSE      default + vuln scripts against the open ports
    snmpwalk      full SNMP system-tree dump
    onesixtyone   SNMP community-string sweep
    sslscan       obsolete TLS protocol / cipher detection
    nbtscan       NetBIOS name enumeration
    smbclient     anonymous SMB share listing
    dig           DNS server interrogation (version.bind, etc.)
    ffuf/gobuster/dirb   content discovery — find hidden / forbidden paths
    nomore403     403/401 access-control bypass (driven from bypass.py)

Every tool is OPTIONAL. If its binary isn't on PATH it is silently skipped and
reported as "missing" in the System Check, so you know what to install for
deeper coverage. Nothing here runs outside an explicit Deep audit on a device
inside your authorized scope. Each tool runs with a hard timeout and its output
is parsed defensively (formats vary by version); the tools run concurrently so
total wall-time is bounded by the slowest single tool, not their sum.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# name -> (binary candidates, short description). nomore403 has no candidates
# here because its detection lives in bypass.py (it may be a local build).
_CATALOG = [
    ("whatweb",     ["whatweb"],            "web tech fingerprint"),
    ("nuclei",      ["nuclei"],             "templated vuln scan"),
    ("nmap",        ["nmap"],               "NSE script scan"),
    ("sslscan",     ["sslscan"],            "TLS weakness scan"),
    ("snmpwalk",    ["snmpwalk"],           "SNMP tree dump"),
    ("onesixtyone", ["onesixtyone"],        "SNMP community sweep"),
    ("nbtscan",     ["nbtscan"],            "NetBIOS enumeration"),
    ("smbclient",   ["smbclient"],          "SMB share listing"),
    ("dig",         ["dig"],                "DNS interrogation"),
    ("ffuf",        ["ffuf"],               "content discovery"),
    ("gobuster",    ["gobuster"],           "content discovery"),
    ("dirb",        ["dirb"],               "content discovery"),
    ("nomore403",   [],                     "403/401 bypass"),
]

# Tiny built-in fallback wordlist for content discovery when no system list is
# installed — high-value endpoints that commonly sit behind a 401/403.
_COMMON_PATHS = [
    "admin", "administrator", "login", "logon", "signin", "api", "api/v1",
    "config", "config.json", "configuration", "settings", "setup", "install",
    "backup", "backups", "db", "database", "dump", "status", "health", "debug",
    "console", "manager", "management", "dashboard", "panel", "cgi-bin",
    "phpmyadmin", "wp-admin", "wp-login.php", ".git", ".git/config", ".env",
    "server-status", "actuator", "actuator/health", "metrics", "info",
    "swagger", "swagger-ui", "graphql", "robots.txt", ".well-known",
    "system", "user", "users", "account", "auth", "oauth", "token", "upload",
    "uploads", "files", "download", "logs", "log", "tmp", "test", "dev",
    "old", "bak", "private", "secret", "secrets", "internal", "monitor",
]


# --------------------------------------------------------------------------- util

def _which(cands) -> str:
    for c in cands:
        p = shutil.which(c)
        if p:
            return p
    return ""


def _run(cmd, timeout):
    """Run a command, return (returncode|None, stdout, stderr); never raises.
    stdin=DEVNULL so no tool can hang waiting on a terminal/stdin (nomore403 did
    exactly that), and the timeout is a hard backstop."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                           timeout=timeout, check=False, errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except (OSError, subprocess.TimeoutExpired):
        return None, "", ""


def _intel(tool, title, detail=""):
    return {"tool": tool, "title": str(title)[:160], "detail": str(detail)[:500]}


def _f(sev, title, detail="", rec=""):
    return {"severity": sev, "title": title, "detail": detail, "recommendation": rec}


def inventory() -> dict:
    """Which intel/bypass tools are installed vs missing (for the System Check)."""
    from . import bypass
    inst, miss = [], []
    for name, cands, _desc in _CATALOG:
        ok = bypass.available() if name == "nomore403" else bool(_which(cands))
        (inst if ok else miss).append(name)
    return {"installed": inst, "missing": miss}


# --------------------------------------------------------------------------- web

def _whatweb(url, timeout=45):
    b = _which(["whatweb"])
    if not b:
        return [], []
    _rc, out, _e = _run([b, "--color=never", "-a", "3", "--log-json=-", url], timeout)
    intel = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        tags = []
        for name, info in (d.get("plugins") or {}).items():
            vals = []
            if isinstance(info, dict):
                for k in ("string", "version"):
                    v = info.get(k)
                    if v:
                        vals.append(",".join(map(str, v)) if isinstance(v, list) else str(v))
            tags.append(name + ("=" + ";".join(vals) if vals else ""))
        if tags:
            intel.append(_intel("whatweb", "Web stack " + url, ", ".join(tags[:30])))
    return intel, []


def _nuclei(url, timeout=110):
    b = _which(["nuclei"])
    if not b:
        return [], []
    _rc, out, _e = _run([b, "-u", url, "-silent", "-jsonl", "-duc", "-nc",
                         "-rl", "40", "-timeout", "5",
                         "-severity", "low,medium,high,critical"], timeout)
    sev_ok = {"critical", "high", "medium", "low", "info"}
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info") or {}
        sev = str(info.get("severity") or "low").lower()
        if sev not in sev_ok:
            sev = "low"
        name = info.get("name") or d.get("template-id") or "nuclei finding"
        at = d.get("matched-at") or d.get("host") or url
        findings.append(_f(sev, "nuclei: " + str(name)[:90],
                           "Template '%s' matched at %s." % (d.get("template-id", "?"), at),
                           "Review the matched nuclei template and patch/mitigate the issue."))
    return [], findings[:20]


def _wordlist():
    """Return (path, is_temp). Prefer a system list, else write a tiny builtin."""
    for p in ("/usr/share/seclists/Discovery/Web-Content/common.txt",
              "/usr/share/wordlists/dirb/common.txt",
              "/usr/share/dirb/wordlists/common.txt",
              "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"):
        if os.path.isfile(p):
            return p, False
    wl = os.path.join("/tmp", "viperscan_wl.txt")
    try:
        with open(wl, "w", encoding="utf-8") as fh:
            fh.write("\n".join(_COMMON_PATHS) + "\n")
        return wl, True
    except OSError:
        return "", False


def _content_discovery(url, timeout=75):
    wl, is_tmp = _wordlist()
    if not wl:
        return [], []
    base = url.rstrip("/")
    found = []   # (status, path)
    ffuf = _which(["ffuf"])
    gob = _which(["gobuster"])
    dirb = _which(["dirb"])
    try:
        if ffuf:
            of = os.path.join("/tmp", "viperscan_ffuf_%x.json" % (abs(hash(url)) % (1 << 28)))
            _run([ffuf, "-u", base + "/FUZZ", "-w", wl, "-t", "40", "-se", "-s",
                  "-mc", "200,204,301,302,307,308,401,403,500", "-of", "json", "-o", of], timeout)
            try:
                with open(of, encoding="utf-8") as fh:
                    data = json.load(fh)
                for r in data.get("results", []):
                    found.append((r.get("status"),
                                  r.get("url") or (r.get("input", {}) or {}).get("FUZZ", "")))
            except (OSError, json.JSONDecodeError, ValueError):
                pass
            finally:
                try:
                    os.remove(of)
                except OSError:
                    pass
        elif gob:
            _rc, out, _e = _run([gob, "dir", "-u", url, "-w", wl, "-q", "-t", "40",
                                 "-s", "200,204,301,302,307,308,401,403", "-b", ""], timeout)
            for line in out.splitlines():
                m = re.match(r"\s*(/\S+)\s+\(Status:\s*(\d+)\)", line)
                if m:
                    found.append((m.group(2), m.group(1)))
        elif dirb:
            _rc, out, _e = _run([dirb, url, wl, "-S", "-r"], timeout)
            for m in re.finditer(r"\+\s*(\S+)\s*\(CODE:(\d+)", out):
                found.append((m.group(2), m.group(1)))
    finally:
        if is_tmp:
            try:
                os.remove(wl)
            except OSError:
                pass
    intel, findings = [], []
    if found:
        uniq = sorted({"%s [%s]" % (p, s) for s, p in found if p})
        intel.append(_intel("content", "Discovered paths " + url, ", ".join(uniq[:30])))
        forb = sorted({p for s, p in found if str(s) in ("401", "403") and p})
        if forb:
            findings.append(_f("low", "Restricted endpoints discovered",
                               "Present but access-controlled: " + ", ".join(forb[:12]),
                               "These exist behind 401/403 — confirm they aren't bypassable "
                               "(ViperScan's 403-bypass step handles the admin panel)."))
    return intel, findings


# --------------------------------------------------------------------------- tls

def _sslscan(ip, port, timeout=40):
    b = _which(["sslscan"])
    if not b:
        return [], []
    _rc, out, _e = _run([b, "--no-colour", "%s:%d" % (ip, port)], timeout)
    weak = []
    for line in out.splitlines():
        m = re.match(r"\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\s+enabled", line, re.I)
        if m:
            weak.append(m.group(1).upper())
    low = out.lower()
    if re.search(r"accepted\b.*\b(rc4|des-cbc|null|export|md5)", low):
        weak.append("weak-cipher")
    findings = []
    if weak:
        findings.append(_f("medium", "Obsolete TLS protocols/ciphers",
                           "sslscan flagged %s on %s:%d." % (", ".join(sorted(set(weak))), ip, port),
                           "Disable SSLv2/3 and TLS 1.0/1.1 plus RC4/DES/EXPORT ciphers; require TLS 1.2+."))
    return [], findings


# -------------------------------------------------------------------------- snmp

def _snmpwalk(ip, timeout=25):
    b = _which(["snmpwalk"])
    if not b:
        return [], []
    _rc, out, _e = _run([b, "-v2c", "-c", "public", "-t", "1", "-r", "0", "-Oqv",
                        ip, "1.3.6.1.2.1.1"], timeout)
    lines = [ln.strip().strip('"') for ln in out.splitlines() if ln.strip()]
    if not lines:
        return [], []
    return [_intel("snmpwalk", "SNMP system tree " + ip, " | ".join(lines[:10]))], []


def _onesixtyone(ip, timeout=18):
    b = _which(["onesixtyone"])
    if not b:
        return [], []
    _rc, out, _e = _run([b, ip], timeout)
    comm = re.findall(r"\[([^\]]+)\]", out)
    if not comm:
        return [], []
    return [], [_f("medium", "SNMP community string exposed",
                   "onesixtyone found community string(s): " + ", ".join(sorted(set(comm))[:6]) + ".",
                   "Change default SNMP community strings and restrict UDP 161 by ACL.")]


# --------------------------------------------------------------------------- smb

def _smb(ip, timeout=22):
    intel, findings = [], []
    nb = _which(["nbtscan"])
    if nb:
        _rc, out, _e = _run([nb, ip], timeout)
        names = [ln.strip() for ln in out.splitlines() if ip in ln]
        if names:
            intel.append(_intel("nbtscan", "NetBIOS " + ip, names[0]))
    sc = _which(["smbclient"])
    if sc:
        _rc, out, _e = _run([sc, "-L", "//" + ip, "-N", "-g"], timeout)
        shares = [ln.split("|")[1] for ln in out.splitlines()
                  if ln.startswith("Disk|") and "|" in ln]
        if shares:
            intel.append(_intel("smbclient", "SMB shares " + ip, ", ".join(shares[:20])))
            findings.append(_f("high", "Anonymous SMB share listing",
                               "smbclient listed shares with no credentials: " + ", ".join(shares[:10]) + ".",
                               "Require authentication for SMB; disable null sessions and guest access."))
    return intel, findings


# --------------------------------------------------------------------------- dns

def _dig(ip, timeout=8):
    b = _which(["dig"])
    if not b:
        return [], []
    _rc, out, _e = _run([b, "@" + ip, "version.bind", "chaos", "txt", "+short",
                        "+time=2", "+tries=1"], timeout)
    ver = out.strip().strip('"')
    if ver and "timed out" not in ver.lower() and "connection" not in ver.lower():
        return [_intel("dig", "DNS server " + ip, "version.bind: " + ver)], []
    return [], []


# ---------------------------------------------------------------------- nmap NSE

def _nmap_nse(ip, ports, timeout=130):
    b = _which(["nmap"])
    if not b or not ports:
        return [], []
    pl = ",".join(str(p) for p in sorted(set(int(x) for x in ports))[:40])
    _rc, out, _e = _run([b, "-Pn", "-sV", "--script", "default,vuln",
                        "--script-timeout", "30s", "--host-timeout", str(int(timeout)) + "s",
                        "-p", pl, ip], timeout + 15)
    intel, findings = [], []
    seen = set()
    for m in re.finditer(r"\|[_ ]*([^\n]*VULNERABLE[^\n]*)", out):
        title = re.sub(r"\s+", " ", m.group(1)).strip(" :|")[:120]
        if title and title.lower() not in seen:
            seen.add(title.lower())
            findings.append(_f("high", "nmap NSE: " + title,
                               "An nmap vuln script reported a potential vulnerability on " + ip + ".",
                               "Confirm against the device's exact model/firmware and patch."))
    for key in ("http-server-header", "http-title", "smb-os-discovery", "ssl-cert"):
        m = re.search(r"\|[_ ]*" + re.escape(key) + r":\s*(.+)", out)
        if m:
            intel.append(_intel("nmap", key, re.sub(r"\s+", " ", m.group(1)).strip()[:200]))
    return intel, findings[:10]


# -------------------------------------------------------------------- dispatcher

def run_for_device(ip, open_ports, panels, services=None) -> dict:
    """Run every applicable installed tool against one authorized device.

    Returns {"intel": [...], "findings": [...], "ran": [...], "missing": [...]}.
    Caller must already have confirmed scope + deep-audit consent.
    """
    ports = set()
    for p in (open_ports or {}):
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            pass
    panels = panels or []
    web_urls = [p.get("url") for p in panels if p.get("url")]
    svc_blob = " ".join(str(v).lower() for v in (services or {}).values())
    has_snmp = (161 in ports) or ("snmp" in svc_blob)

    tasks = []  # (name, thunk)
    if web_urls:
        u = web_urls[0]
        if _which(["whatweb"]):
            tasks.append(("whatweb", lambda u=u: _whatweb(u)))
        if _which(["nuclei"]):
            tasks.append(("nuclei", lambda u=u: _nuclei(u)))
        if _which(["ffuf"]) or _which(["gobuster"]) or _which(["dirb"]):
            tasks.append(("content", lambda u=u: _content_discovery(u)))
    tls_p = next((p for p in (443, 8443, 9443) if p in ports), None)
    if tls_p and _which(["sslscan"]):
        tasks.append(("sslscan", lambda p=tls_p: _sslscan(ip, p)))
    if has_snmp:
        if _which(["snmpwalk"]):
            tasks.append(("snmpwalk", lambda: _snmpwalk(ip)))
        if _which(["onesixtyone"]):
            tasks.append(("onesixtyone", lambda: _onesixtyone(ip)))
    if ports & {139, 445} and (_which(["nbtscan"]) or _which(["smbclient"])):
        tasks.append(("smb", lambda: _smb(ip)))
    if 53 in ports and _which(["dig"]):
        tasks.append(("dig", lambda: _dig(ip)))
    if ports and _which(["nmap"]):
        tasks.append(("nmap-nse", lambda p=tuple(ports): _nmap_nse(ip, p)))

    intel, findings, ran = [], [], []
    if tasks:
        with ThreadPoolExecutor(max_workers=min(6, len(tasks))) as ex:
            futs = {ex.submit(t[1]): t[0] for t in tasks}
            for fu in as_completed(futs):
                name = futs[fu]
                try:
                    i, f = fu.result()
                except Exception:
                    i, f = [], []
                if i or f:
                    ran.append(name)
                intel += i
                findings += f
    inv = inventory()
    return {"intel": intel[:60], "findings": findings,
            "ran": sorted(ran), "missing": inv["missing"], "installed": inv["installed"]}
