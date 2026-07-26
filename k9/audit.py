"""Per-device security audit — the deep "what's wrong with this thing" engine.

Two tiers, by network footprint:

  QUIET  (runs automatically when you click a device)
    - panel discovery (reuses probe.panels)
    - cleartext-HTTP admin detection
    - TLS certificate inspection (self-signed / expired) via the openssl CLI
    - known-CVE hinting from a curated, offline device→CVE map
    - turning ViperScan's own flags into findings
    - internet-exposure (from the cached UPnP port-forward map, if any)

  DEEP   (only when you press "Deep audit" — these get logged by targets)
    - nmap service/version (and OS, as root)
    - RTSP open-stream check (camera video viewable with no password)
    - anonymous FTP
    - default-credential check over HTTP Basic *and* Digest

Every check emits a Finding {severity, title, detail, recommendation}. A risk
score rolls them up. Run the active tier only against gear you own — see the
note in probe.py.
"""

from __future__ import annotations

import calendar
import hashlib
import re
import socket
import ssl
import time

from . import bypass, probe, tools

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_WEIGHT = {"critical": 45, "high": 28, "medium": 14, "low": 5, "info": 0}


def _finding(sev, title, detail="", rec=""):
    return {"severity": sev, "title": title, "detail": detail, "recommendation": rec}


# --------------------------------------------------------------------------- CVEs

# Curated, offline device-class → real-CVE map. These are notable, widely-cited
# CVEs for the device CLASS — a "go verify your model/firmware" list, NOT a
# claim that this specific unit is vulnerable right now.
_CVE_DB = [
    {"match": ["hikvision"], "klass": "Hikvision IP camera / NVR", "cves": [
        {"id": "CVE-2021-36260", "cvss": 9.8, "desc": "Unauthenticated command injection (full remote code execution) via the web interface."},
        {"id": "CVE-2017-7921", "cvss": 10.0, "desc": "Improper authentication — bypass login and read credentials/config."},
    ]},
    {"match": ["dahua"], "klass": "Dahua camera / DVR", "cves": [
        {"id": "CVE-2021-33044", "cvss": 9.8, "desc": "Identity-authentication bypass via a crafted login request."},
        {"id": "CVE-2021-33045", "cvss": 9.8, "desc": "Second authentication-bypass path on many firmware builds."},
    ]},
    {"match": ["axis"], "klass": "Axis network camera", "cves": [
        {"id": "CVE-2018-10660", "cvss": 9.8, "desc": "Shell command injection in the VAPIX interface (root RCE in a chain)."},
        {"id": "CVE-2018-10661", "cvss": 9.8, "desc": "Authorization bypass reaching protected endpoints without auth."},
    ]},
    {"match": ["reolink"], "klass": "Reolink camera", "cves": [
        {"id": "CVE-2021-40150", "cvss": 7.5, "desc": "Unauthenticated access to device resources/streams."},
        {"id": "CVE-2021-40149", "cvss": 5.3, "desc": "Unauthenticated retrieval of device information."},
    ]},
    {"match": ["foscam"], "klass": "Foscam camera", "cves": [
        {"id": "CVE-2018-19064", "cvss": 8.8, "desc": "Stack buffer overflow reachable over the network (potential RCE)."},
        {"id": "CVE-2018-19066", "cvss": 7.5, "desc": "Unauthenticated information disclosure."},
    ]},
    {"match": ["d-link", "dlink"], "klass": "D-Link router", "cves": [
        {"id": "CVE-2019-16920", "cvss": 9.8, "desc": "Unauthenticated remote code execution on multiple (often end-of-life) models."},
    ]},
    {"match": ["netgear"], "klass": "Netgear router", "cves": [
        {"id": "CVE-2016-6277", "cvss": 9.8, "desc": "Unauthenticated RCE via a crafted web request (R-series)."},
        {"id": "CVE-2017-5521", "cvss": 8.1, "desc": "Admin-password disclosure / recovery bypass."},
    ]},
    {"match": ["tp-link", "tplink", "deco", "archer"], "klass": "TP-Link router / mesh", "cves": [
        {"id": "CVE-2023-1389", "cvss": 8.8, "desc": "Unauthenticated command injection (Archer AX21; weaponised by the Mirai botnet)."},
        {"id": "CVE-2022-30075", "cvss": 8.8, "desc": "Authenticated RCE via backup/restore (Archer C-series). Confirm your exact model."},
    ]},
    {"match": ["mikrotik"], "klass": "MikroTik RouterOS", "cves": [
        {"id": "CVE-2018-14847", "cvss": 9.1, "desc": "Winbox path traversal leaks admin credentials on un-upgraded RouterOS."},
    ]},
    {"match": ["ubiquiti", "unifi"], "klass": "Ubiquiti / UniFi", "cves": [
        {"id": "CVE-2021-44228", "cvss": 10.0, "desc": "Log4Shell — the UniFi Network app bundled a vulnerable Log4j; patch the controller."},
    ]},
    {"match": ["realtek"], "klass": "Realtek-SDK IoT device", "cves": [
        {"id": "CVE-2021-35394", "cvss": 9.8, "desc": "Unauthenticated RCE in the Realtek SDK 'UDPServer' baked into many cheap IoT devices."},
    ]},
    {"match": ["goahead"], "klass": "GoAhead embedded webserver", "cves": [
        {"id": "CVE-2017-17562", "cvss": 9.8, "desc": "Unauthenticated RCE via CGI environment poisoning (common on IP cameras)."},
    ]},
    {"match": ["wyze"], "klass": "Wyze camera", "cves": [
        {"id": "CVE-2019-9564", "cvss": 7.5, "desc": "Authentication bypass allowing device control without valid credentials."},
        {"id": "CVE-2019-12266", "cvss": 7.5, "desc": "Stack buffer overflow reachable from the LAN (potential code execution)."},
    ]},
    {"match": ["zyxel"], "klass": "Zyxel router / firewall", "cves": [
        {"id": "CVE-2020-29583", "cvss": 9.8, "desc": "Hardcoded admin-level credential (undocumented backdoor account) in the firmware."},
    ]},
    {"match": ["asustek", "asus"], "klass": "ASUS router (AsusWRT)", "cves": [
        {"id": "CVE-2018-14713", "cvss": 8.8, "desc": "Remote code execution in the AsusWRT web interface."},
        {"id": "CVE-2018-14710", "cvss": 5.3, "desc": "Information disclosure exposing the admin password in some paths."},
    ]},
    {"match": ["qnap"], "klass": "QNAP NAS", "cves": [
        {"id": "CVE-2021-28799", "cvss": 9.8, "desc": "Hardcoded credentials in HBS backup (exploited by the Qlocker ransomware)."},
    ]},
    {"match": ["synology"], "klass": "Synology NAS", "cves": [
        {"id": "CVE-2022-27624", "cvss": 9.8, "desc": "Out-of-bounds write in DSM enabling code execution — keep DSM patched."},
    ]},
    {"match": ["lorex", "swann"], "klass": "Lorex / Swann DVR (Dahua-based)", "cves": [
        {"id": "CVE-2021-33044", "cvss": 9.8, "desc": "Dahua-OEM identity-authentication bypass affecting many rebranded DVRs."},
    ]},
]


def cve_hints(vendor: str, services: dict) -> list:
    hay = (vendor or "").lower() + " " + " ".join(str(v).lower() for v in (services or {}).values())
    out, seen = [], set()
    for entry in _CVE_DB:
        if entry["klass"] in seen or not any(n in hay for n in entry["match"]):
            continue
        seen.add(entry["klass"])
        ids = ", ".join(c["id"] for c in entry["cves"])
        f = _finding(
            "high",
            f"Known CVEs for this device class — {entry['klass']}",
            f"Publicly documented vulnerabilities for {entry['klass']} ({ids}). "
            "These are potential — not confirmed on this unit; verify your exact model and firmware.",
            "Update to the latest vendor firmware; replace or network-isolate the device if it's end-of-life.",
        )
        f["cves"] = entry["cves"]
        f["device_class"] = entry["klass"]
        out.append(f)
    return out


# --------------------------------------------------------------------------- TLS

def _read_tlv(data, off):
    if off + 2 > len(data):
        raise ValueError("truncated TLV")
    tag = data[off]; length = data[off + 1]; p = off + 2
    if length & 0x80:
        nb = length & 0x7F
        if p + nb > len(data):
            raise ValueError("truncated TLV length")
        length = int.from_bytes(data[p:p + nb], "big"); p += nb
    return tag, data[p:p + length], data[off:p + length], p + length


def _parse_cert(der: bytes) -> dict:
    """Minimal X.509 DER walk for the few fields we need (no pyca dependency).
    tbsCertificate's SEQUENCEs come in order: sigAlg, issuer, validity, subject."""
    info: dict = {}
    try:
        _t, cert_val, _r, _n = _read_tlv(der, 0)       # Certificate
        _t, tbs_val, _r, _n = _read_tlv(cert_val, 0)   # tbsCertificate
        off, seqs = 0, []
        while off < len(tbs_val):
            tag, val, raw, off = _read_tlv(tbs_val, off)
            if tag == 0x30:
                seqs.append((val, raw))
        if len(seqs) >= 4:
            issuer_raw, validity_val, subject_raw = seqs[1][1], seqs[2][0], seqs[3][1]
            info["self_signed"] = issuer_raw == subject_raw
            toff, times = 0, []
            while toff < len(validity_val):
                t, v, r, toff = _read_tlv(validity_val, toff)
                times.append((t, v))
            if len(times) >= 2:
                info["not_after"] = times[1][1].decode("latin-1", "replace")
                info["not_after_tag"] = times[1][0]
    except (IndexError, ValueError):
        return {}
    return info


def _cert_expired(not_after: str, tag: int):
    s = not_after.strip().rstrip("Z")
    try:
        if tag == 0x18 or len(s) >= 14:        # GeneralizedTime YYYYMMDDHHMMSS
            t = time.strptime(s[:14], "%Y%m%d%H%M%S")
        else:                                   # UTCTime YYMMDDHHMMSS
            # RFC 5280: 2-digit year 00–49 => 20xx, 50–99 => 19xx
            # (Python's %y uses a different 1969 pivot, so map it ourselves).
            yy = int(s[:2])
            year = 2000 + yy if yy <= 49 else 1900 + yy
            t = time.strptime(f"{year}{s[2:12]}", "%Y%m%d%H%M%S")
        return calendar.timegm(t) < time.time(), time.strftime("%Y-%m-%d", t)
    except (ValueError, IndexError):
        return False, not_after


def tls_audit(ip: str, port: int, timeout: float = 4.0) -> dict:
    """Negotiated protocol + cipher + certificate facts, all via stdlib ssl."""
    info: dict = {}
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ss:
                info["version"] = ss.version() or ""
                ci = ss.cipher()
                info["cipher"] = ci[0] if ci else ""
                der = ss.getpeercert(binary_form=True)
        if der:
            cert = _parse_cert(der)
            info.update(cert)
            if cert.get("not_after"):
                info["expired"], info["expires"] = _cert_expired(cert["not_after"], cert.get("not_after_tag", 0x17))
    except Exception:
        return {}
    return info


def _has_hsts(ip: str, port: int, timeout: float = 2.0):
    sock = None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        sock = ssl._create_unverified_context().wrap_socket(raw, server_hostname=ip)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        data = sock.recv(4096).decode("latin-1", "replace")
        return "strict-transport-security" in data.lower()
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def tls_findings(ip: str, panels: list) -> list:
    out = []
    for p in panels:
        if p["scheme"] != "https":
            continue
        t = tls_audit(ip, p["port"])
        if not t:
            continue
        ver = t.get("version", "")
        if ver and (ver.startswith("SSLv") or ver in ("TLSv1", "TLSv1.0", "TLSv1.1")):
            out.append(_finding("high", f"Obsolete TLS ({ver}) on :{p['port']}",
                f"The device negotiated {ver}, which is deprecated and has known weaknesses.",
                "Disable SSLv3 / TLS 1.0 / 1.1 and require TLS 1.2 or newer."))
        cipher = t.get("cipher", "")
        if any(w in cipher.upper() for w in ("RC4", "3DES", "DES-", "NULL", "EXPORT", "MD5")):
            out.append(_finding("medium", f"Weak TLS cipher on :{p['port']}",
                f"Negotiated a weak cipher ({cipher}).",
                "Restrict the device to modern AEAD ciphers (AES-GCM / ChaCha20)."))
        if t.get("expired"):
            out.append(_finding("medium", f"Expired TLS certificate on :{p['port']}",
                f"The certificate expired {t.get('expires','?')}.",
                "Renew or replace the device certificate."))
        elif t.get("self_signed"):
            out.append(_finding("low", f"Self-signed TLS certificate on :{p['port']}",
                "The certificate is issued by the device itself, so the connection can't be independently verified.",
                "Expected on most local devices — just know the connection isn't verifiable."))
        if _has_hsts(ip, p["port"]) is False:
            out.append(_finding("info", f"No HSTS on :{p['port']}",
                "The HTTPS panel doesn't send Strict-Transport-Security, so a downgrade to plain HTTP isn't actively prevented.",
                "Enable HSTS if the device supports it (often not configurable on embedded gear)."))
        break  # one https panel is enough
    return out


# --------------------------------------------------------------------------- HTTP posture

def http_posture(panels: list) -> list:
    out = []
    has_http_login = any(p["scheme"] == "http" and ("basic" in (p.get("auth") or "").lower())
                         for p in panels)
    if has_http_login:
        out.append(_finding("medium", "Admin login served over plain HTTP",
                            "Credentials to this panel are sent unencrypted and can be sniffed on the network.",
                            "Use the device's HTTPS port if it has one, or restrict access to a trusted VLAN."))
    return out


# --------------------------------------------------------------------------- IoT brokers

def iot_broker_findings(ip: str, device: dict, open_ports) -> list:
    out = []
    ports = set(int(p) for p in (open_ports or {}))
    if {1883, 8883} & ports:
        mq = probe.fingerprint.mqtt_open(ip)
        if mq and mq.get("open"):
            out.append(_finding(
                "high", "Open MQTT broker (no authentication)",
                f"The MQTT broker on port {mq['port']} accepted a connection with no credentials — "
                "anyone on the network can read or inject IoT messages.",
                "Require a username/password (and TLS) on the broker and restrict it to trusted hosts."))
    cat = device.get("category")
    if cat in ("iot", "unknown", "voice", "media", "camera") or 5683 in ports:
        if probe.fingerprint.coap_open(ip):
            out.append(_finding(
                "medium", "Open CoAP endpoint",
                "A CoAP service answered on UDP 5683 without authentication; many IoT CoAP stacks expose controllable resources.",
                "Restrict CoAP access (use DTLS/PSK) or isolate the device on its own network."))
    return out


# --------------------------------------------------------------------------- RTSP (cameras)

_RTSP_PATHS = [
    "/", "/live", "/live.sdp", "/h264", "/stream1", "/11", "/0/onvif/profile1/media.smp",
    "/cam/realmonitor?channel=1&subtype=0",          # Dahua
    "/Streaming/Channels/101",                        # Hikvision
    "/onvif1", "/video1", "/ch0_0.h264", "/live/ch0",
]


def rtsp_open_stream(ip: str, ports=(554, 8554), timeout: float = 2.0) -> list:
    """Probe RTSP DESCRIBE without credentials. A 200 means the video stream is
    viewable with no password — a serious exposure for a camera."""
    out = []
    for port in ports:
        for path in _RTSP_PATHS:
            url = f"rtsp://{ip}:{port}{path}"
            s = None
            try:
                s = socket.create_connection((ip, port), timeout=timeout)
                s.settimeout(timeout)
                s.sendall(f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n".encode())
                resp = s.recv(1024).decode("latin-1", "replace")
            except OSError:
                break  # port not open at all → skip the rest of the paths
            finally:
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            code = 0
            m = re.match(r"RTSP/1\.0\s+(\d+)", resp)
            if m:
                code = int(m.group(1))
            if code == 200:
                out.append(_finding("critical", "Camera stream is open with NO password",
                                    f"RTSP DESCRIBE on {url} returned 200 without authentication — anyone on the network can watch the live video.",
                                    f"Enable authentication on the camera immediately. Verify it yourself with: ffplay {url}"))
                return out  # one confirmed open stream is enough
            if code in (401, 403):
                return out  # auth required → good, stop probing this device
    return out


# --------------------------------------------------------------------------- FTP

def ftp_anonymous(ip: str, timeout: float = 2.0) -> list:
    s = None
    try:
        s = socket.create_connection((ip, 21), timeout=timeout)
        s.settimeout(timeout)
        if not s.recv(256).startswith(b"220"):
            return []
        s.sendall(b"USER anonymous\r\n"); s.recv(256)
        s.sendall(b"PASS viperscan@example.com\r\n")
        resp = s.recv(256).decode("latin-1", "replace")
        if resp.startswith("230"):
            return [_finding("high", "Anonymous FTP is enabled",
                             "The FTP server accepted an anonymous login.",
                             "Disable anonymous FTP unless it's deliberately a public drop-box.")]
    except OSError:
        return []
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
    return []


# --------------------------------------------------------------------------- default creds (Basic + Digest)

def _hparm(challenge: str, name: str) -> str:
    m = re.search(rf'{name}="?([^",]+)"?', challenge, re.I)
    return m.group(1) if m else ""


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def digest_header(user, pw, realm, nonce, qop, opaque, uri="/", method="GET",
                  nc="00000001", cnonce="viperscan"):
    """Build an RFC 2617 Digest Authorization header value."""
    ha1, ha2 = _md5(f"{user}:{realm}:{pw}"), _md5(f"{method}:{uri}")
    if qop:
        resp = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        hdr = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
               f'qop={qop}, nc={nc}, cnonce="{cnonce}", response="{resp}"')
    else:
        resp = _md5(f"{ha1}:{nonce}:{ha2}")
        hdr = f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}"'
    if opaque:
        hdr += f', opaque="{opaque}"'
    return hdr


# A SMALL, fixed set of the most notorious weak passwords. This is a
# weak-password *audit*, not a wordlist cracker — it's deliberately tiny and the
# whole credential test is hard-capped and stops the moment a device locks out.
_WEAK_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "12345", "1234", "111111",
    "000000", "password1", "admin123", "letmein", "welcome", "qwerty", "abc123",
    "iloveyou", "monkey", "dragon", "master", "superman", "sunshine", "login",
    "passw0rd", "changeme", "default", "guest", "test", "1234567890",
]
_CREDS_HARD_CAP = 60  # never send more than this many login attempts per device


def _try_basic_list(ip, panel, creds_list, timeout):
    for user, pw in creds_list:
        r = probe.http_probe(ip, panel["port"], panel["scheme"], "/", timeout, auth=(user, pw))
        if r and r["status"] in (200, 301, 302):
            return {"url": panel["url"], "user": user, "password": pw or "(blank)",
                    "scheme": "basic", "status": r["status"]}
    return None


def _try_digest_list(ip, panel, creds_list, timeout):
    chal = panel.get("auth") or ""
    realm, nonce, qop = _hparm(chal, "realm"), _hparm(chal, "nonce"), _hparm(chal, "qop")
    opaque = _hparm(chal, "opaque")
    for user, pw in creds_list:
        hdr = digest_header(user, pw, realm, nonce, qop, opaque)
        r = probe.http_probe(ip, panel["port"], panel["scheme"], "/", timeout,
                             headers={"Authorization": hdr})
        if r and r["status"] in (200, 301, 302):
            return {"url": panel["url"], "user": user, "password": pw or "(blank)",
                    "scheme": "digest", "status": r["status"]}
    return None


def _cred_list(vendor, include_weak):
    creds = list(probe._creds_for(vendor))
    if include_weak:
        seen = set(creds)
        for user in ("admin", "root"):
            for pw in _WEAK_PASSWORDS:
                c = (user, pw)
                if c not in seen:
                    seen.add(c)
                    creds.append(c)
    return creds[:_CREDS_HARD_CAP]


def default_creds(ip: str, panels: list, vendor: str, timeout: float = 2.0,
                  include_weak: bool = False):
    """Try factory (and optionally common-weak) logins over Basic and Digest.
    Bounded by _CREDS_HARD_CAP. Returns (hit_or_None, attempts_made)."""
    creds = _cred_list(vendor, include_weak)
    tested = 0
    for panel in panels:
        auth = (panel.get("auth") or "").lower()
        if "basic" in auth:
            tested += len(creds)
            hit = _try_basic_list(ip, panel, creds, timeout)
            if hit:
                return hit, tested
        elif "digest" in auth:
            tested += len(creds)
            hit = _try_digest_list(ip, panel, creds, timeout)
            if hit:
                return hit, tested
    return None, tested


def lockout_probe(ip: str, panels: list, timeout: float = 2.0, attempts: int = 5):
    """Does the device resist brute-force? Send a few deliberately-wrong logins
    and see whether it starts blocking/throttling. A device that just keeps
    answering 401 has NO lockout — that's the real weakness. Returns a finding
    (or None). Only assessed on HTTP Basic panels."""
    panel = next((p for p in panels if "basic" in (p.get("auth") or "").lower()), None)
    if not panel:
        return None
    statuses = []
    for i in range(attempts):
        r = probe.http_probe(ip, panel["port"], panel["scheme"], "/", timeout,
                             auth=("admin", f"ViperScanWrongPw{i}"))
        if r is None or r["status"] in (403, 429, 503):
            return None  # it started blocking → lockout/throttle exists (good)
        statuses.append(r["status"])
    if statuses and all(s == 401 for s in statuses):
        return _finding(
            "medium", "No login lockout / rate-limiting",
            f"The login on {panel['url']} accepted {len(statuses)} wrong passwords in a row "
            "without locking out or slowing down — it can be brute-forced offline-fast.",
            "Enable account lockout / rate-limiting if the device supports it; otherwise isolate "
            "it on a separate VLAN and use a long unique password as the compensating control.")
    return None


# --------------------------------------------------------------------- hardening

def hardening(device: dict, findings: list) -> list:
    """A concrete 'how to bulletproof this device' checklist."""
    recs, seen = [], set()

    def add(title, detail):
        if title not in seen:
            seen.add(title)
            recs.append({"title": title, "detail": detail})

    cat = device.get("category")
    ports = set(int(p) for p in (device.get("open_ports") or {}))
    hay = " ".join(f["title"].lower() for f in findings)

    # ---- device-type-specific guidance (the "expert, not boilerplate" part) ----
    if cat == "camera":
        add("Require authentication on the video stream", "Turn off anonymous RTSP/ONVIF; set a strong password so the feed can't be watched without logging in.")
        add("Disable UPnP on the camera", "Stop the camera from auto-opening a port to the internet through your router.")
    elif cat == "printer":
        add("Lock down print services", "Require authentication for IPP/web admin and disable unused protocols (raw 9100, FTP, Telnet) you don't print over.")
        add("Disable remote/cloud printing if unused", "Turn off WAN/cloud print features unless you actually use them.")
    elif cat == "network":
        add("Disable WPS and remote/WAN administration", "WPS is brute-forceable; remote admin exposes the router login to the internet. Turn both off.")
        add("Turn off UPnP on the router", "UPnP lets any device silently open internet-facing ports — disable it and add forwards manually if needed.")
        add("Use WPA3 (or WPA2-AES) Wi-Fi", "Avoid WEP/WPA/TKIP; use WPA3 where supported.")
    elif cat == "computer" and (445 in ports or 5000 in ports):
        add("Harden file sharing", "Disable SMBv1, require authentication on shares, and enable account lockout.")
    elif cat == "voice":
        add("Review microphone & privacy settings", "Mute the mic when not in use and review what the assistant records/stores in its app.")

    if "password" in hay or "default" in hay:
        add("Set a long, unique password", "Replace the default/weak password with a 16+ character unique passphrase you don't reuse anywhere.")
    if "no login lockout" in hay:
        add("Enable lockout / rate-limiting", "Turn on account lockout if the device supports it; if not, network isolation + a strong password are your compensating controls.")
    if "internet" in hay:
        add("Remove the internet exposure", "Delete the router port-forward / UPnP mapping unless you deliberately published this service.")
    if "telnet" in hay:
        add("Disable Telnet", "Turn Telnet off; use SSH if you need remote shell access.")
    if "plain http" in hay or "cleartext" in hay:
        add("Use HTTPS for the admin panel", "Access the admin interface over HTTPS so the password isn't sent in cleartext on the network.")
    if "cve" in hay or "known cves" in hay:
        add("Update the firmware", "Check the vendor's security advisories and apply the latest firmware; replace it if it's end-of-life and unpatched.")
    if cat in ("camera", "iot", "voice", "media"):
        add("Isolate on an IoT / guest network", "Put cameras and smart-home gear on a separate VLAN or guest Wi-Fi so a compromise can't reach your computers and phones.")
    # universal good hygiene
    add("Enable 2FA on the cloud account", "If it has a companion app/cloud account, turn on two-factor authentication and use a unique password there too.")
    add("Keep firmware current", "Enable auto-update where available; otherwise check for updates periodically.")
    return recs


# --------------------------------------------------------------------------- flags → findings

_FLAG_FINDINGS = {
    "INSECURE": ("high", "Telnet (cleartext) is open", "Telnet sends everything — including passwords — in the clear and is a top IoT-botnet entry point.", "Disable Telnet; use SSH if remote access is needed."),
    "REMOTE": ("medium", "Remote-control service exposed", "RDP/VNC/ADB is reachable on the LAN.", "Restrict to trusted hosts and require strong auth."),
    "HIDDEN": ("info", "Host ignores ping but answers ARP", "Quiet device — not necessarily a problem, but worth identifying.", "Use Deep audit to fingerprint it."),
    "UNKNOWN": ("low", "Device could not be identified", "ViperScan couldn't determine what this is.", "Use Deep audit (nmap) or check the router's DHCP lease table."),
    "ISP-MGMT": ("low", "Carrier remote-management port open", "TR-069 lets your ISP manage the device; it has been abused in attacks.", "Usually can't be changed on ISP gear; be aware of it."),
}


def flag_findings(device: dict) -> list:
    out = []
    for f in device.get("flags", []):
        spec = _FLAG_FINDINGS.get(f)
        if spec:
            out.append(_finding(spec[0], spec[1], spec[2], spec[3]))
    return out


# --------------------------------------------------------------------------- scoring

def risk_score(findings: list, device: dict) -> dict:
    score = sum(_SEV_WEIGHT.get(f["severity"], 0) for f in findings)
    # Camera with any high+ finding is inherently sensitive — nudge it up.
    if device.get("category") == "camera" and any(SEV_ORDER[f["severity"]] >= 3 for f in findings):
        score += 10
    score = min(100, score)
    if score == 0:
        label, color = "clean", "green"
    elif score < 25:
        label, color = "low", "blue"
    elif score < 55:
        label, color = "elevated", "amber"
    else:
        label, color = "critical", "red"
    return {"score": score, "label": label, "color": color}


# --------------------------------------------------------------------------- orchestrate

def _intel_summary(ip, device, result, pan):
    """An 'everything we know about this device' dump. Always returned — even
    with zero findings — so a deep audit is never empty/unhelpful. Assembled from
    discovery + fingerprint + nmap + HTTP panels (no extra probing)."""
    dev = device or {}
    out = []

    def add(label, val):
        if val not in (None, "", [], {}):
            out.append({"label": label, "value": str(val)[:320]})

    add("IP address", ip)
    add("MAC address", dev.get("mac"))
    add("Manufacturer", dev.get("vendor") or (result.get("nmap") or {}).get("nmap_vendor"))
    dtype = dev.get("device_type")
    add("Device type", dtype if dtype not in (None, "", "Unknown") else dev.get("category"))
    add("Hostname", dev.get("hostname"))
    add("Discovered via", dev.get("via"))
    rtt = dev.get("rtt_ms")
    add("Ping round-trip", (str(rtt) + " ms") if rtt is not None else "")
    op = dev.get("open_ports") or {}
    if isinstance(op, dict) and op:
        items = []
        for p in sorted(op, key=lambda x: int(x) if str(x).isdigit() else 99999):
            lbl = op[p]
            items.append("%s%s" % (p, " (" + str(lbl) + ")" if lbl else ""))
        add("Open TCP ports (%d)" % len(op), ", ".join(items))
    svc = dev.get("services") or {}
    if isinstance(svc, dict):
        for k, v in svc.items():
            add("Discovery · " + str(k), v)
    nm = result.get("nmap") or {}
    os_str = nm.get("nmap_os")
    if os_str:
        acc = nm.get("nmap_os_acc")
        vlow = (dev.get("vendor") or "").lower()
        cat = (dev.get("category") or "").lower()
        phoneish = (cat in ("phone", "mobile", "computer", "laptop")
                    or any(v in vlow for v in ("apple", "samsung", "google", "xiaomi",
                           "oneplus", "huawei", "motorola", "oppo", "vivo", "lg electronics", "nokia")))
        wrongish = re.search(r"xbox|playstation|nintendo|console|printer|webcam|router|switch|game", os_str, re.I)
        if phoneish and wrongish:
            os_str += (" — ⚠ almost certainly wrong. nmap OS detection is unreliable for phones/"
                       "computers (they keep ports closed); trust the Manufacturer above ("
                       + (dev.get("vendor") or "MAC vendor") + ").")
        elif nm.get("nmap_os_conf") == "guess":
            os_str += " — low-confidence nmap guess" + ((" (%s%%)" % acc) if acc else "") + ", may be wrong"
        add("OS fingerprint (nmap)", os_str)
    add("Service versions (nmap)", nm.get("nmap_services"))
    for pa in (pan.get("panels") or [])[:6]:
        bits = []
        if pa.get("server"):
            bits.append("server: " + str(pa["server"]))
        if pa.get("title"):
            bits.append('title: "%s"' % pa["title"])
        add("HTTP %s [%s]" % (pa.get("url", ""), pa.get("status", "?")), " · ".join(bits) or "reachable")
    if dev.get("flag_reasons"):
        add("Flagged because", "; ".join(str(x) for x in dev["flag_reasons"]))
    return out


def audit(ip: str, device: dict, *, deep: bool = False, creds: bool = False,
          weak: bool = False, exposure: list | None = None, timeout: float = 2.0) -> dict:
    """Run an audit.

    Tiers are independent and explicitly requested:
      quiet  (always)  — passive-leaning identification + posture
      deep   (deep=True)  — nmap, open-stream & anonymous-FTP checks (loud, but
                            does NOT guess passwords)
      creds  (creds=True) — actively tries factory/default logins. Separate and
                            consent-gated in the UI, because it sends real login
                            attempts the device will log.
    """
    device = device or {}
    vendor = device.get("vendor", "")
    open_ports = device.get("open_ports")

    pan = probe.panels(ip, open_ports, timeout)
    findings: list = []

    # ---- quiet tier ----
    findings += flag_findings(device)
    findings += cve_hints(vendor, device.get("services", {}))
    findings += http_posture(pan["panels"])
    findings += tls_findings(ip, pan["panels"])
    findings += iot_broker_findings(ip, device, open_ports)

    # internet-exposure (computed once per network, passed in)
    for m in (exposure or []):
        if m.get("internal_ip") == ip:
            findings.append(_finding(
                "critical", f"Exposed to the INTERNET on port {m.get('ext_port')}",
                f"Your router forwards WAN port {m.get('ext_port')}/{m.get('proto','?')} to this device's "
                f"port {m.get('internal_port')} ({m.get('desc','')}). It is reachable from outside your network.",
                "Remove this port-forward / UPnP mapping unless you deliberately published this service."))

    result = {"ip": ip, "panels": pan["panels"], "best_url": pan["best_url"],
              "findings": findings, "nmap": {}, "default_creds": None,
              "creds_tested": 0, "deep": deep, "creds_run": creds}

    # ---- deep tier: identification / exposure (no password guessing) ----
    if deep:
        result["nmap"] = probe.fingerprint.nmap_deep(ip, timeout=40.0)
        if device.get("category") == "camera" or {554, 8554} & set(int(p) for p in (open_ports or {})):
            findings += rtsp_open_stream(ip)
        if 21 in set(int(p) for p in (open_ports or {})):
            findings += ftp_anonymous(ip)
        snmp_comm = probe.fingerprint.snmp_writable(ip)
        if snmp_comm:
            findings.append(_finding(
                "critical", "SNMP is writable",
                f"The device accepted an SNMP SET using community '{snmp_comm}' — an attacker can "
                "reconfigure it over SNMP (UDP 161).",
                "Disable SNMP write access, change the default community strings, or block UDP 161."))
        # 403/401 access-control bypass — automatically attempt EVERY forbidden
        # panel, and always report the outcome (success → critical; held → why).
        forbidden = [p for p in pan["panels"] if p.get("status") in (401, 403)]
        if forbidden:
            if bypass.available():
                runs = []
                per_to = 90.0 if len(forbidden) == 1 else 45.0   # bound total time on many panels
                for fp in forbidden[:5]:                 # cap so a wall of panels can't run forever
                    br = bypass.run(fp["url"], timeout=per_to)
                    br["panel"] = fp["url"]
                    runs.append(br)
                    if br.get("bypassed"):
                        results = br.get("results", [])
                        for idx, b in enumerate(results[:8]):
                            rb = bypass.replay(b) if idx < 3 else b   # fetch the page for the top few
                            extra = ""
                            if rb.get("replayed"):
                                extra = (f" Fetched the page ({rb.get('fetched_length', 0)} bytes,"
                                         f" {rb.get('content_type', 'text/html')}).")
                            f = _finding(
                                "critical", "403/401 access control bypassed",
                                f"nomore403 reached {b.get('url') or fp['url']} (HTTP {b['status']}) via "
                                f"'{b['technique']}' — the Forbidden response can be circumvented." + extra,
                                "The admin interface is reachable despite the 403; fix the access control "
                                "(don't rely on path/header/verb filtering).")
                            f["bypass"] = {"url": b.get("url") or fp["url"], "status": b.get("status"),
                                           "technique": b.get("technique"), "curl": b.get("curl", ""),
                                           "view_id": rb.get("view_id", ""), "snippet": rb.get("snippet", "")}
                            findings.append(f)
                    else:
                        # couldn't get in — say WHY (this is good news for the owner)
                        findings.append(_finding(
                            "info", f"403 held at {fp['url']}",
                            br.get("reason", "The access control resisted all bypass techniques."),
                            "No action needed — the Forbidden page resisted bypass. (Still verify the "
                            "panel needs no auth-bypass hardening on the upstream proxy.)"))
                result["bypass"] = runs[0] if len(runs) == 1 else {"runs": runs}
                result["bypass_runs"] = runs
            else:
                findings.append(_finding(
                    "low", f"{len(forbidden)} forbidden panel(s) found — bypass tool missing",
                    "ViperScan found 401/403 panel(s) here but nomore403 isn't installed, so it "
                    "couldn't auto-test whether the Forbidden response can be circumvented.",
                    "Install nomore403 so deep audits automatically attempt 403/401 bypasses."))
        # external intel + bypass tools — squeeze every drop from this device
        try:
            tx = tools.run_for_device(ip, open_ports, pan["panels"], device.get("services"))
        except Exception:
            tx = None
        if tx:
            result["tools"] = {"ran": tx.get("ran", []), "intel": tx.get("intel", []),
                               "missing": tx.get("missing", [])}
            findings += tx.get("findings", [])

    # ---- credential tier: actively tries logins (opt-in, scope-gated) ----
    if creds:
        lo = lockout_probe(ip, pan["panels"], timeout)   # does it resist brute-force?
        if lo:
            findings.append(lo)
        hit, tested = default_creds(ip, pan["panels"], vendor, timeout, include_weak=weak)
        result["creds_tested"] = tested
        if hit:
            result["default_creds"] = hit
            kind = "Weak" if hit["password"] in _WEAK_PASSWORDS else "Default/factory"
            findings.append(_finding(
                "critical", f"{kind} password accepted",
                f"{hit['user']} / {hit['password']} ({hit.get('scheme','basic')}) opened {hit['url']}.",
                "Change this device's password to a long, unique passphrase immediately."))

    findings.sort(key=lambda f: -SEV_ORDER[f["severity"]])
    result["findings"] = findings
    result["risk"] = risk_score(findings, device)
    result["hardening"] = hardening(device, findings)
    result["intel_summary"] = _intel_summary(ip, device, result, pan)
    return result
