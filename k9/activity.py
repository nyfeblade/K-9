"""What a device is DOING right now — live activity, not just identity.

Honest scope: on a switched / Wi-Fi network a host that isn't the gateway can't
see the private unicast traffic between other devices and the internet (that
needs router-level capture or intrusive ARP-spoofing, which ViperScan doesn't
do). What it CAN observe per device, with light probes and no root:

  * liveness & responsiveness  (ping samples → online, loss, latency, jitter)
  * which services are live right NOW, and whether a camera stream is up
  * real throughput via SNMP interface counters (for SNMP-enabled gear)
  * the device's behavioural role, inferred from what it serves/advertises
"""

from __future__ import annotations

import socket
import time

from . import discovery, fingerprint

_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
_IF_IN = "1.3.6.1.2.1.2.2.1.10."     # ifInOctets.<idx>
_IF_OUT = "1.3.6.1.2.1.2.2.1.16."    # ifOutOctets.<idx>


def _ports_of(device) -> set:
    out = set()
    for p in (device.get("open_ports") or {}):
        try:
            out.add(int(p))
        except (ValueError, TypeError):
            pass
    return out


# ----------------------------------------------------------------- SNMP counters

def _snmp_int(ip, oid, community, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(fingerprint._snmp_get(oid, community, 1), (ip, 161))
        data, _ = s.recvfrom(2048)
    except OSError:
        return None
    finally:
        s.close()
    needle = fingerprint._ber_oid(oid)
    idx = data.find(needle)
    if idx == -1:
        return None
    pos = idx + len(needle)
    if pos + 2 > len(data):
        return None
    tag = data[pos]
    length = data[pos + 1]
    p = pos + 2
    if length & 0x80:
        nb = length & 0x7F
        if p + nb > len(data):
            return None
        length = int.from_bytes(data[p:p + nb], "big")
        p += nb
    if tag in (0x02, 0x41, 0x42, 0x43, 0x46):   # INTEGER/Counter32/Gauge/TimeTicks/Counter64
        return int.from_bytes(data[p:p + length], "big")
    return None


def snmp_activity(ip, communities=("public", "private"), timeout=1.0) -> dict:
    """sysUpTime + interface throughput, sampled twice ~2s apart."""
    community = uptime = None
    for c in communities:
        u = _snmp_int(ip, _SYS_UPTIME, c, timeout)
        if u is not None:
            community, uptime = c, u
            break
    if community is None:
        return {}

    def sample():
        ti = to = 0
        for idx in range(1, 7):
            vi = _snmp_int(ip, f"{_IF_IN}{idx}", community, timeout)
            vo = _snmp_int(ip, f"{_IF_OUT}{idx}", community, timeout)
            if vi:
                ti += vi
            if vo:
                to += vo
        return ti, to

    in1, out1 = sample()
    time.sleep(2.0)
    in2, out2 = sample()
    return {
        "uptime_s": (uptime // 100) if uptime else None,
        "in_bps": max(0, in2 - in1) * 8 / 2.0,    # Counter32 wrap → clamp at 0
        "out_bps": max(0, out2 - out1) * 8 / 2.0,
        "community": community,
    }


# ----------------------------------------------------------------- liveness / services

def liveness(ip, samples=4, timeout=1.0) -> dict:
    times, got = [], 0
    for _ in range(samples):
        alive, rtt = discovery._ping(ip, timeout)
        if alive:
            got += 1
            if rtt is not None:
                times.append(rtt)
    return {
        "online": got > 0,
        "loss_pct": round(100 * (samples - got) / samples),
        "avg_ms": round(sum(times) / len(times), 1) if times else None,
        "jitter_ms": round(max(times) - min(times), 1) if len(times) > 1 else 0.0,
        "samples": samples,
    }


def live_services(ip, open_ports, timeout=0.8) -> list:
    """Which of the known-open ports respond at this instant."""
    up = []
    for p in (open_ports or {}):
        try:
            pn = int(p)
        except (ValueError, TypeError):
            continue
        if not (0 < pn < 65536):
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, pn)) == 0:
                up.append(pn)
        except OSError:
            pass
        finally:
            s.close()
    return sorted(up)


def stream_active(ip, ports=(554, 8554), timeout=1.2) -> bool:
    for port in ports:
        s = None
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(f"DESCRIBE rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
            if s.recv(256).decode("latin-1", "replace").startswith("RTSP/1.0"):
                return True
        except OSError:
            continue
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    return False


def role_summary(device) -> list:
    """What the device acts as, from the services/ports it exposes."""
    roles = []
    svc = " ".join(str(v).lower() for v in (device.get("services") or {}).values())
    ports = _ports_of(device)

    def add(cond, label):
        if cond and label not in roles:
            roles.append(label)

    add("airplay" in svc or "raop" in svc, "AirPlay receiver")
    add("googlecast" in svc, "Chromecast / Cast")
    add(554 in ports or 8554 in ports or "rtsp" in svc, "Live video (RTSP)")
    add(631 in ports or 9100 in ports or 515 in ports, "Network printer")
    add(53 in ports, "DNS resolver")
    add(1883 in ports or 8883 in ports, "MQTT broker")
    add(bool({445, 139} & ports), "File sharing (SMB)")
    add(22 in ports, "SSH server")
    add(bool({80, 443, 8080, 8443, 8000} & ports), "Web / admin server")
    add(123 in ports, "Time (NTP) server")
    add("homekit" in svc or "hap" in svc, "HomeKit accessory")
    add("amzn" in svc or "alexa" in svc, "Alexa / Amazon device")
    return roles


def probe(ip, device, timeout=1.0) -> dict:
    device = device or {}
    open_ports = device.get("open_ports")
    ports = _ports_of(device)
    cam = device.get("category") == "camera" or bool({554, 8554} & ports)
    return {
        "ip": ip,
        "liveness": liveness(ip, timeout=timeout),
        "live_ports": live_services(ip, open_ports),
        "stream_active": stream_active(ip) if cam else None,
        "snmp": snmp_activity(ip, timeout=timeout),
        "roles": role_summary(device),
    }
