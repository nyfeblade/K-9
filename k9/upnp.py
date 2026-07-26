"""Ask the router (via UPnP IGD) what it has forwarded to the internet.

If the gateway speaks UPnP and a device asked it to open a WAN port (game
consoles, DVRs, torrent clients and plenty of cameras do this automatically),
that device is reachable from the *public internet* — usually without the owner
realising. We enumerate those mappings so the audit can flag the exposed
device. Pure stdlib: SSDP to find the IGD, then SOAP GetGenericPortMappingEntry.

Returns [] when UPnP is disabled (e.g. a hardened UniFi/pfSense), which is the
secure state.
"""

from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

_SSDP_ADDR = ("239.255.255.250", 1900)
_IGD_STS = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
]


def _msearch(st: str) -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\nMX: 2\r\n'
        f"ST: {st}\r\n\r\n"
    ).encode()


def _discover_locations(timeout: float = 2.5) -> list[str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    locs: list[str] = []
    try:
        for st in _IGD_STS:
            s.sendto(_msearch(st), _SSDP_ADDR)
        while True:
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                break
            m = re.search(r"^location:\s*(\S+)", data.decode("latin-1", "replace"), re.I | re.M)
            if m and m.group(1) not in locs:
                locs.append(m.group(1))
    except OSError:
        pass
    finally:
        s.close()
    return locs


def _http_get(url: str, timeout: float = 2.5) -> tuple[str, str]:
    """Return (base_origin, body) for a UPnP description URL."""
    u = urlparse(url)
    host, port, path = u.hostname, (u.port or 80), (u.path or "/")
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode())
        raw = b""
        while len(raw) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
    except OSError:
        return "", ""
    body = raw.decode("latin-1", "replace").partition("\r\n\r\n")[2]
    return f"{u.scheme}://{host}:{port}", body


def _find_wan_service(body: str):
    """Locate a WANIP/WANPPPConnection service: returns (serviceType, controlURL)."""
    for block in re.findall(r"<service>(.*?)</service>", body, re.I | re.S):
        st = re.search(r"<serviceType>(.*?)</serviceType>", block, re.I | re.S)
        cu = re.search(r"<controlURL>(.*?)</controlURL>", block, re.I | re.S)
        if st and cu and ("WANIPConnection" in st.group(1) or "WANPPPConnection" in st.group(1)):
            return st.group(1).strip(), cu.group(1).strip()
    return None, None


def _soap_get_mapping(origin: str, control_url: str, svc_type: str, index: int, timeout: float = 2.5):
    u = urlparse(origin)
    host, port = u.hostname, (u.port or 80)
    path = control_url if control_url.startswith("/") else "/" + control_url
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:GetGenericPortMappingEntry xmlns:u="{svc_type}">'
        f'<NewPortMappingIndex>{index}</NewPortMappingIndex>'
        '</u:GetGenericPortMappingEntry></s:Body></s:Envelope>'
    )
    req = (
        f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f'SOAPAction: "{svc_type}#GetGenericPortMappingEntry"\r\n'
        'Content-Type: text/xml; charset="utf-8"\r\n'
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
    )
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(req.encode())
        raw = b""
        while len(raw) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
    except OSError:
        return None
    text = raw.decode("latin-1", "replace")
    if " 200 " not in text.split("\r\n", 1)[0]:
        return None  # SOAP fault → past the end of the table

    def tag(name):
        m = re.search(rf"<{name}>(.*?)</{name}>", text, re.I | re.S)
        return m.group(1).strip() if m else ""

    return {
        "ext_port": tag("NewExternalPort"),
        "proto": tag("NewProtocol"),
        "internal_ip": tag("NewInternalClient"),
        "internal_port": tag("NewInternalPort"),
        "desc": tag("NewPortMappingDescription"),
        "enabled": tag("NewEnabled"),
    }


def port_mappings(timeout: float = 2.5, max_entries: int = 60) -> list[dict]:
    """Return the router's active WAN→LAN port-forwards, or [] if UPnP is off."""
    for loc in _discover_locations(timeout):
        origin, body = _http_get(loc, timeout)
        if not body:
            continue
        svc_type, control_url = _find_wan_service(body)
        if not (svc_type and control_url):
            continue
        mappings = []
        for i in range(max_entries):
            m = _soap_get_mapping(origin, control_url, svc_type, i, timeout)
            if m is None:
                break
            if m.get("enabled") in ("1", "", "true", "True") and m.get("internal_ip"):
                mappings.append(m)
        return mappings  # first working IGD wins
    return []
