"""Active fingerprinting: open ports, service banners, and name discovery.

We gather four independent kinds of evidence about each host:

  1. Open TCP ports from a curated, security-relevant port list (cameras,
     DVRs, admin panels, telnet, SMB, printers, IoT brokers...).
  2. Application banners — HTTP `Server:`/`<title>`, RTSP `Server:` (cameras
     love to print their model here), and SSH/Telnet greetings.
  3. Reverse DNS (PTR) — cheap hostnames on home networks.
  4. Multicast / broadcast name discovery: SSDP (UPnP), mDNS (Bonjour) and
     NetBIOS, which is where TVs, Chromecasts, printers and cameras announce
     their friendly names and model strings.

All stdlib sockets. Nothing here needs privileges.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# port -> (label, weight-toward-category). The label is shown to the user; the
# classifier reads the raw port numbers, so labels are purely informational.
PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    81: "HTTP-alt",
    88: "Kerberos/AirPlay",
    110: "POP3",
    111: "RPC",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    515: "Printer-LPD",
    548: "AFP (Apple)",
    554: "RTSP (camera)",
    631: "IPP (printer)",
    873: "rsync",
    1883: "MQTT (IoT)",
    1900: "SSDP/UPnP",
    2020: "ONVIF (camera)",
    2323: "Telnet-alt (IoT)",
    3000: "HTTP-app",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP/HTTP",
    5060: "SIP (VoIP)",
    5353: "mDNS",
    5357: "WSD",
    5432: "PostgreSQL",
    5555: "ADB/DVR",
    5900: "VNC",
    7547: "TR-069 (ISP mgmt)",
    8000: "HTTP-alt (camera)",
    8008: "HTTP (Chromecast)",
    8009: "Cast",
    8080: "HTTP-proxy",
    8081: "HTTP-alt",
    8443: "HTTPS-alt",
    8554: "RTSP-alt (camera)",
    8883: "MQTT-TLS",
    8888: "HTTP-alt",
    9000: "HTTP-app",
    9100: "Printer-RAW",
    9999: "DVR/IoT",
    10001: "Ubiquiti/IoT",
    32400: "Plex",
    37777: "Dahua DVR (camera)",
    34567: "Xiongmai DVR (camera)",
    49152: "UPnP-dyn",
    62078: "iPhone-sync",
}

# Default sweep set — high-value services across IoT, NAS, cameras, admin
# panels, remote-access and printers. Kept lean enough to stay fast but much
# broader than a bare top-20; --deep still uses the full PORTS map.
QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 139, 143, 443, 445, 515, 548, 554,
    587, 631, 993, 1080, 1883, 1900, 2000, 2020, 2323, 3000, 3128, 3306,
    3389, 5000, 5060, 5357, 5555, 5900, 7547, 8000, 8008, 8080, 8081, 8088,
    8181, 8443, 8554, 8888, 9000, 9100, 9999, 10000, 32400, 34567, 37777,
    49152, 49153, 62078,
]

HTTP_PORTS = {80, 81, 443, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 3000}
TLS_PORTS = {443, 8443, 8883}


# ----------------------------------------------------------------------------- ports

def scan_ports(ip: str, ports, timeout: float = 0.6, workers: int = 96) -> dict[int, str]:
    """Threaded TCP connect scan. Returns {port: label} for open ports."""
    open_ports: dict[int, str] = {}

    def probe(port: int):
        # Adaptive: a refused connection is definitively closed (no retry); a
        # timeout might be a rate-limiting/slow device, so retry once with a
        # longer deadline before giving up.
        for attempt in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout * (1 + 0.6 * attempt))
            try:
                rc = s.connect_ex((ip, port))
                if rc == 0:
                    return port
                if rc in (111, 113):   # ECONNREFUSED / EHOSTUNREACH → closed
                    return None
            except OSError:
                pass
            finally:
                s.close()
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(probe, p) for p in ports]
        for fut in as_completed(futs):
            p = fut.result()
            if p is not None:
                open_ports[p] = PORTS.get(p, "open")
    return dict(sorted(open_ports.items()))


# ----------------------------------------------------------------------------- banners

def grab_http(ip: str, port: int, timeout: float = 1.2) -> dict[str, str]:
    """Return {'server':..., 'title':...} from an HTTP(S) endpoint, best effort."""
    info: dict[str, str] = {}
    use_tls = port in TLS_PORTS
    raw = b""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        if use_tls:
            import ssl
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        req = (
            f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
            "User-Agent: ViperScan\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        ).encode()
        sock.sendall(req)
        while len(raw) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    except Exception:
        return info
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    text = raw.decode("latin-1", "replace")
    m = re.search(r"^Server:\s*(.+)$", text, re.I | re.M)
    if m:
        info["server"] = m.group(1).strip()[:120]
    m = re.search(r"^WWW-Authenticate:\s*(.+)$", text, re.I | re.M)
    if m:
        info["auth_realm"] = m.group(1).strip()[:120]
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        if title:
            info["title"] = title[:120]
    return info


def grab_rtsp(ip: str, port: int = 554, timeout: float = 1.2) -> str:
    """RTSP OPTIONS — cameras frequently leak vendor/model in the Server header."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(
            f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n"
            "User-Agent: ViperScan\r\n\r\n".encode()
        )
        data = sock.recv(2048).decode("latin-1", "replace")
        m = re.search(r"^Server:\s*(.+)$", data, re.I | re.M)
        return m.group(1).strip()[:120] if m else "RTSP/server"
    except Exception:
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """Generic first-line banner grab for chatty services (SSH/Telnet/FTP)."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        data = sock.recv(256)
        return data.decode("latin-1", "replace").splitlines()[0].strip()[:120] if data else ""
    except Exception:
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def banners_for(ip: str, open_ports: dict[int, str]) -> dict[str, str]:
    """Collect whatever banners the open ports afford us."""
    out: dict[str, str] = {}
    for port in open_ports:
        if port in HTTP_PORTS:
            http = grab_http(ip, port)
            for k, v in http.items():
                out.setdefault(f"http:{port}:{k}", v)
        elif port in (554, 8554):
            b = grab_rtsp(ip, port)
            if b:
                out[f"rtsp:{port}"] = b
        elif port in (22, 23, 21, 25):
            b = grab_banner(ip, port)
            if b:
                out[f"banner:{port}"] = b
    return out


# ----------------------------------------------------------------------------- names

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


def netbios_name(ip: str, timeout: float = 1.0) -> str:
    """NetBIOS node-status query (UDP 137) -> Windows/SMB friendly name."""
    # Wildcard "*" name, padded — standard NBSTAT request.
    query = struct.pack(">H", 0x1337) + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    query += b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
    query += b"\x00\x21\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(2048)
    except (OSError, socket.timeout):
        return ""
    finally:
        s.close()
    try:
        num = data[56]
        names = []
        off = 57
        for _ in range(num):
            name = data[off:off + 15].decode("latin-1", "replace").strip()
            suffix = data[off + 15]      # NetBIOS name type/suffix
            flags = data[off + 16]       # name flags
            off += 18
            # suffix 0x00 unique + group bit clear == workstation name
            if name and not name.startswith("\x00"):
                names.append((name, suffix))
        # Prefer the unique workstation/server name.
        for name, _suf in names:
            cleaned = name.strip("\x00 ")
            if cleaned and cleaned != "__MSBROWSE__":
                return cleaned
    except (IndexError, ValueError):
        return ""
    return ""


# ---- SNMP (the single best way to identify a quiet device) -----------------
# A great many "hidden" printers, routers, switches, cameras and IoT boxes
# ignore ICMP and run no TCP services, yet still answer an SNMP GET on UDP/161
# with a sysDescr string that names the exact make/model/firmware. We hand-roll
# a minimal SNMP GET (no pysnmp dependency) for sysDescr.0 and sysName.0.

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    if out[0] & 0x80:
        out.insert(0, 0)
    return _tlv(0x02, bytes(out))


def _ber_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    body = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        if p < 0x80:
            body.append(p)
        else:
            stack = []
            while p:
                stack.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(stack) - 1):
                stack[i] |= 0x80
            body.extend(stack)
    return _tlv(0x06, bytes(body))


def _snmp_get(oid: str, community: str, version: int) -> bytes:
    varbind = _tlv(0x30, _ber_oid(oid) + _tlv(0x05, b""))   # OID + NULL value
    pdu = _tlv(
        0xA0,                                               # GetRequest-PDU
        _ber_int(0x5363) + _ber_int(0) + _ber_int(0) + _tlv(0x30, varbind),
    )
    return _tlv(0x30, _ber_int(version) + _tlv(0x04, community.encode()) + pdu)


def _snmp_extract(data: bytes, oid: str) -> str:
    """Pull the value that follows *oid* in an SNMP response (crude TLV seek)."""
    needle = _ber_oid(oid)
    idx = data.find(needle)
    if idx == -1:
        return ""
    pos = idx + len(needle)
    if pos + 2 > len(data):
        return ""
    tag = data[pos]
    length = data[pos + 1]
    p = pos + 2
    if length & 0x80:
        nb = length & 0x7F
        if p + nb > len(data):       # truncated length field → reject
            return ""
        length = int.from_bytes(data[p:p + nb], "big")
        p += nb
    val = data[p:p + length]
    if tag == 0x04:  # OCTET STRING (sysDescr / sysName)
        return val.decode("latin-1", "replace").strip()
    return ""


def snmp_identify(ip: str, communities=("public", "private"), timeout: float = 0.9) -> dict[str, str]:
    """Return {'snmp': sysDescr, 'snmp_name': sysName} if the host answers SNMP."""
    sys_descr = "1.3.6.1.2.1.1.1.0"
    sys_name = "1.3.6.1.2.1.1.5.0"
    for community in communities:
        for version in (1, 0):  # v2c first, then v1 for older gear
            out: dict[str, str] = {}
            for oid, key in ((sys_descr, "snmp"), (sys_name, "snmp_name")):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                try:
                    s.sendto(_snmp_get(oid, community, version), (ip, 161))
                    data, _ = s.recvfrom(2048)
                    val = _snmp_extract(data, oid)
                    if val:
                        out[key] = re.sub(r"\s+", " ", val)[:160]
                except OSError:
                    pass
                finally:
                    s.close()
            if out:
                return out
    return {}


# ---- SNMP SET (is the device reconfigurable over SNMP?) ---------------------

def _snmp_set_octet(oid: str, value: str, community: str, version: int = 1) -> bytes:
    varbind = _tlv(0x30, _ber_oid(oid) + _tlv(0x04, value.encode("latin-1", "replace")))
    pdu = _tlv(0xA3, _ber_int(0x5364) + _ber_int(0) + _ber_int(0) + _tlv(0x30, varbind))
    return _tlv(0x30, _ber_int(version) + _tlv(0x04, community.encode()) + pdu)


def _snmp_error_status(data: bytes):
    """Parse error-status from an SNMP response PDU (0 == accepted)."""
    def rd(d, o):
        tag = d[o]; length = d[o + 1]; p = o + 2
        if length & 0x80:
            nb = length & 0x7F
            length = int.from_bytes(d[p:p + nb], "big"); p += nb
        return tag, d[p:p + length], p + length
    try:
        _t, seqval, _n = rd(data, 0)
        o = 0
        _t, _v, o = rd(seqval, o)       # version
        _t, _v, o = rd(seqval, o)       # community
        _t, pdu, o = rd(seqval, o)      # PDU
        po = 0
        _t, _reqid, po = rd(pdu, po)    # request-id
        _t, errstat, po = rd(pdu, po)   # error-status
        return int.from_bytes(errstat, "big")
    except (IndexError, ValueError):
        return None


def snmp_writable(ip: str, communities=("private", "public"), timeout: float = 1.2) -> str:
    """Non-destructively test whether SNMP is WRITABLE: read sysContact, then
    SET it back to the exact same value. error-status 0 means the device would
    let an attacker reconfigure it over SNMP. Returns the working community."""
    oid = "1.3.6.1.2.1.1.4.0"  # sysContact.0
    for community in communities:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(_snmp_get(oid, community, 1), (ip, 161))
            cur = _snmp_extract(s.recvfrom(2048)[0], oid)
        except OSError:
            s.close(); continue
        finally:
            s.close()
        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.settimeout(timeout)
        try:
            s2.sendto(_snmp_set_octet(oid, cur, community, 1), (ip, 161))
            if _snmp_error_status(s2.recvfrom(2048)[0]) == 0:
                return community
        except OSError:
            pass
        finally:
            s2.close()
    return ""


# ---- MQTT / CoAP IoT brokers ------------------------------------------------

def mqtt_open(ip: str, ports=(1883, 8883), timeout: float = 2.0) -> dict:
    """Send an MQTT CONNECT and read the CONNACK. Return-code 0 = the broker
    accepted us with NO authentication (anyone can pub/sub)."""
    payload = b"\x00\x09viperscan"               # client-id
    varhdr = b"\x00\x04MQTT\x04\x02\x00\x3c"     # protocol MQTT v3.1.1, clean session
    body = varhdr + payload
    pkt = b"\x10" + bytes([len(body)]) + body
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) != 0:
                continue
            if port == 8883:
                import ssl
                sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname=ip)
            sock.sendall(pkt)
            resp = sock.recv(8)
            if len(resp) >= 4 and resp[0] == 0x20:   # CONNACK
                return {"port": port, "rc": resp[3], "open": resp[3] == 0}
        except OSError:
            continue
        finally:
            sock.close()
    return {}


def coap_open(ip: str, port: int = 5683, timeout: float = 2.0) -> bool:
    """CoAP GET /.well-known/core over UDP. Any valid reply = a CoAP endpoint."""
    msg = b"\x40\x01\x12\x34" + b"\xbb" + b".well-known" + b"\x04" + b"core"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (ip, port))
        data, _ = s.recvfrom(1500)
        return len(data) >= 4 and (data[0] >> 6) == 1   # CoAP version 1
    except OSError:
        return False
    finally:
        s.close()


# ---- UDP service scan (protocol-specific probes) ----------------------------

def _udp_probe(ip: str, port: int, payload: bytes, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (ip, port))
        s.recvfrom(2048)
        return True
    except OSError:
        return False
    finally:
        s.close()


def udp_scan(ip: str, timeout: float = 0.8, workers: int = 10) -> dict:
    """Protocol-specific UDP probes (run in parallel) — TCP scans miss these."""
    probes = [
        (53, "DNS (udp)", b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"),
        (123, "NTP (udp)", b"\x1b" + b"\x00" * 47),
        (69, "TFTP (udp)", b"\x00\x01viperscan\x00octet\x00"),
        (161, "SNMP (udp)", _snmp_get("1.3.6.1.2.1.1.1.0", "public", 1)),
        (5683, "CoAP (udp)", b"\x40\x01\x12\x34\xbb.well-known\x04core"),
    ]
    found: dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_udp_probe, ip, port, payload, timeout): (port, label)
                for port, label, payload in probes}
        for fut in as_completed(futs):
            port, label = futs[fut]
            try:
                if fut.result():
                    found[port] = label
            except Exception:
                pass
    return dict(sorted(found.items()))


# ---- nmap deep dive (optional, used by --unhide when nmap is installed) -----

def nmap_deep(ip: str, timeout: float = 40.0) -> dict[str, str]:
    """Fold in nmap's service/version and (root-only) OS detection.

    `-Pn` tells nmap to skip its own ping and treat the host as up — exactly
    what we want for a host that's hiding from ICMP.
    """
    if shutil.which("nmap") is None:
        return {}
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    # --top-ports keeps the scan bounded on dark hosts; -O (OS detection) only
    # works as root, so we add it conditionally.
    cmd = ["nmap", "-Pn", "-sV", "-T4", "--version-light", "--top-ports", "1000",
           "--max-retries", "1", "--host-timeout", f"{int(timeout)}s"]
    if is_root:
        cmd += ["-O", "--osscan-guess"]
    cmd.append(ip)
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 10, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    info: dict[str, str] = {}
    # High-confidence exact match first; otherwise capture a GUESS + its accuracy
    # so the UI can label it honestly (nmap loves to "confidently" call a phone an
    # Xbox 360 because phones keep ports closed — the MAC vendor is the real ID).
    m = re.search(r"OS details: (.+)", out)
    if m:
        info["nmap_os"] = m.group(1).strip()[:140]
        info["nmap_os_conf"] = "match"
    else:
        m = re.search(r"(?:Aggressive OS guesses|Running \(JUST GUESSING\)|OS guesses?): (.+)", out)
        if m:
            line = m.group(1).strip()
            top = re.match(r"(.+?)\s*\((\d+)%\)", line)
            if top:
                info["nmap_os"] = top.group(1).strip()[:140]
                info["nmap_os_acc"] = top.group(2)
            else:
                info["nmap_os"] = line.split(",")[0].strip()[:140]
            info["nmap_os_conf"] = "guess"
    clean, seen = [], set()
    for p in re.findall(r"^\d+/tcp\s+open\s+\S+\s+(.+?)\s*$", out, re.M):
        p = p.strip()
        low = p.lower()
        if not p or "service detection" in low or "please report" in low or "nmap.org" in low:
            continue
        if p not in seen:
            seen.add(p)
            clean.append(p)
    if clean:
        info["nmap_services"] = "; ".join(clean[:6])[:200]
    m = re.search(r"MAC Address: \S+ \((.+)\)", out)
    if m and m.group(1).strip().lower() != "unknown":
        info["nmap_vendor"] = m.group(1).strip()[:80]
    return info


# ---- SSDP (UPnP) ----

_SSDP_ADDR = ("239.255.255.250", 1900)
_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def ssdp_discover(timeout: float = 3.0) -> dict[str, dict[str, str]]:
    """Broadcast an SSDP M-SEARCH and collect responders.

    Returns {ip: {'server':..., 'st':..., 'location':...}}. We then fetch each
    LOCATION's device description to pull friendlyName / manufacturer / model.
    """
    results: dict[str, dict[str, str]] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    try:
        s.sendto(_SSDP_MSEARCH, _SSDP_ADDR)
        import time
        # We can't call time.monotonic budgets here cheaply; just loop on timeout.
        while True:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            ip = addr[0]
            text = data.decode("latin-1", "replace")
            entry = results.setdefault(ip, {})
            for field in ("server", "location", "st", "usn"):
                m = re.search(rf"^{field}:\s*(.+)$", text, re.I | re.M)
                if m and field not in entry:
                    entry[field] = m.group(1).strip()
    except OSError:
        pass
    finally:
        s.close()

    # Enrich with the device-description XML (friendlyName/manufacturer/model).
    for ip, entry in results.items():
        loc = entry.get("location")
        if loc:
            desc = _fetch_ssdp_description(loc)
            entry.update(desc)
    return results


def _fetch_ssdp_description(location: str, timeout: float = 1.5) -> dict[str, str]:
    out: dict[str, str] = {}
    m = re.match(r"https?://([\d.]+):?(\d+)?(/.*)?", location)
    if not m:
        return out
    host = m.group(1)
    port = int(m.group(2) or 80)
    path = m.group(3) or "/"
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        raw = b""
        while len(raw) < 32768:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
    except Exception:
        return out
    xml = raw.decode("latin-1", "replace")
    for tag, key in (
        ("friendlyName", "ssdp_name"),
        ("manufacturer", "ssdp_manufacturer"),
        ("modelName", "ssdp_model"),
        ("modelDescription", "ssdp_desc"),
        ("deviceType", "ssdp_devicetype"),
    ):
        mm = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.I | re.S)
        if mm:
            val = re.sub(r"\s+", " ", mm.group(1)).strip()
            if val:
                out[key] = val[:120]
    return out


# ---- mDNS (Bonjour) ----

_MDNS_ADDR = ("224.0.0.251", 5353)
_MDNS_QUERY_NAMES = [
    "_services._dns-sd._udp.local",
    "_googlecast._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_axis-video._tcp.local",
    "_rtsp._tcp.local",
    "_homekit._tcp.local",
    "_hap._tcp.local",
    "_amzn-wplay._tcp.local",
    "_workstation._tcp.local",
]


def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _mdns_query_packet() -> bytes:
    header = struct.pack(">HHHHHH", 0, 0, len(_MDNS_QUERY_NAMES), 0, 0, 0)
    body = b""
    for name in _MDNS_QUERY_NAMES:
        body += _encode_qname(name) + struct.pack(">HH", 12, 0x8001)  # PTR, QU+IN
    return header + body


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    end = offset
    guard = 0
    while guard < 128:
        guard += 1
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("latin-1", "replace"))
        offset += 1 + length
    return ".".join(labels), end


def mdns_discover(timeout: float = 3.0) -> dict[str, dict[str, str]]:
    """Send mDNS PTR queries and harvest A/PTR/SRV/TXT answers per responder IP."""
    results: dict[str, dict[str, str]] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    try:
        s.sendto(_mdns_query_packet(), _MDNS_ADDR)
        while True:
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                break
            ip = addr[0]
            entry = results.setdefault(ip, {})
            try:
                _harvest_mdns(data, entry)
            except Exception:
                continue
    except OSError:
        pass
    finally:
        s.close()
    return results


def _harvest_mdns(data: bytes, entry: dict[str, str]) -> None:
    if len(data) < 12:
        return
    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    offset = 12
    for _ in range(qd):  # skip questions
        _name, offset = _parse_name(data, offset)
        offset += 4
    services = entry.setdefault("mdns_services", "")
    svc_set = set(filter(None, services.split(",")))
    names_seen = set(filter(None, entry.get("_names", "").split("|")))
    for _ in range(an + ns + ar):
        if offset + 10 > len(data):
            break
        name, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rtype == 12:  # PTR
            target, _ = _parse_name(data, offset)
            for svc in ("_googlecast", "_airplay", "_raop", "_ipp", "_printer",
                        "_axis-video", "_rtsp", "_homekit", "_hap", "_amzn", "_workstation"):
                if svc in name or svc in target:
                    svc_set.add(svc.lstrip("_"))
            host_label = target.split(".")[0]
            if host_label and not host_label.startswith("_"):
                names_seen.add(host_label)
        elif rtype == 16:  # TXT — often has md=ModelName / fn=FriendlyName
            txt = rdata.decode("latin-1", "replace")
            for key in ("md=", "fn=", "model=", "manufacturer=", "fv="):
                mm = re.search(re.escape(key) + r"([^\x00-\x1f]+)", txt)
                if mm:
                    entry.setdefault("mdns_" + key.rstrip("="), mm.group(1).strip()[:80])
        elif rtype in (1,):  # A record -> friendly host label
            label = name.split(".")[0]
            if label and not label.startswith("_"):
                names_seen.add(label)
        offset += rdlen
    if svc_set:
        entry["mdns_services"] = ",".join(sorted(svc_set))
    if names_seen:
        entry["_names"] = "|".join(sorted(names_seen))
        entry["mdns_name"] = sorted(names_seen, key=len, reverse=True)[0][:80]
