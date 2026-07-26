"""Turn raw evidence into a device type + a set of human-meaningful flags.

The classifier is deliberately transparent: every flag carries a plain-English
reason, so the report can explain *why* it thinks the thing in the corner is a
camera. Evidence is combined from vendor (MAC OUI), open ports, service
banners, and SSDP/mDNS/NetBIOS names.

Flags are the point of the whole tool — they answer "what's on this network
that I should look at twice?":

  CAMERA      a network camera / video device
  SURVEILLANCE a DVR/NVR or multi-camera recorder
  MIC         an always-listening voice assistant
  HIDDEN      answers ARP but not ICMP, or uses a randomised MAC
  UNKNOWN     could not be identified at all
  EXPOSED     an open admin/login web panel
  INSECURE    telnet / known-weak service exposed
  IOT         a small embedded/smart-home device
  ROUTER      the gateway / an access point
  NEW         not seen on this network on a previous scan
"""

from __future__ import annotations

import re

from .discovery import Host

# --- keyword tables --------------------------------------------------------

_CAMERA_VENDORS = (
    "axis", "hikvision", "dahua", "reolink", "wyze", "foscam", "amcrest",
    "vivotek", "mobotix", "geovision", "acti", "arlo", "lorex", "swann",
    "uniview", "tp-link tapo", "tapo", "ezviz", "annke", "nest cam",
    "ubiquiti", "unifi", "ring",
)
_CAMERA_WORDS = ("camera", "ipcam", "ip cam", "webcam", "nvr", "dvr", "onvif",
                 "surveillance", "doorbell", "cam ", "rtsp")
_VOICE_VENDORS = ("amazon", "echo", "alexa", "google home", "google nest",
                  "sonos", "homepod")
_VOICE_WORDS = ("echo", "alexa", "google home", "google nest", "homepod",
                "voice", "assistant")
# Note: deliberately excludes "airplay"/"raop" — Macs, iPhones and many
# speakers advertise those, so they're too broad to mean "this is a TV".
_TV_WORDS = ("roku", "chromecast", "shield", "appletv", "apple tv", "firetv",
             "fire tv", "bravia", "samsung tv", "lg tv", "vizio", "smart tv",
             "googlecast", "webos", "tizen", "android.tv")
_PRINTER_WORDS = ("printer", "officejet", "deskjet", "laserjet", "envy",
                  "ecotank", "workforce", "brother", "canon mx", "epson",
                  "ipp", "_printer")
_PHONE_VENDORS = ("apple", "samsung", "xiaomi", "huawei", "oneplus", "oppo",
                  "vivo", "google", "motorola", "lg electronics")
_COMPUTER_VENDORS = ("dell", "lenovo", "hp inc", "hewlett", "asus", "intel",
                     "micro-star", "msi", "gigabyte", "raspberry pi", "vmware",
                     "microsoft", "apple", "framework")
_ROUTER_VENDORS = ("netgear", "tp-link", "asus", "linksys", "d-link", "arris",
                   "technicolor", "ubiquiti", "mikrotik", "fortinet", "zyxel",
                   "cisco", "aruba", "ruckus", "eero", "google fiber")
_NAS_VENDORS = ("synology", "qnap", "western digital", "wd ", "seagate",
                "drobo", "buffalo")
_CONSOLE_WORDS = ("xbox", "playstation", "ps4", "ps5", "nintendo", "switch")


def _hay(host: Host) -> str:
    """One lower-cased haystack of every textual signal we have on a host."""
    parts = [host.vendor, host.hostname, host.device_type]
    parts += list(host.services.values())
    parts += [f"{p}:{lbl}" for p, lbl in host.open_ports.items()]
    return " ".join(str(p) for p in parts if p).lower()


def _add_flag(host: Host, flag: str, reason: str) -> None:
    if flag not in host.flags:
        host.flags.append(flag)
    host.flag_reasons.append(reason)


def classify(host: Host) -> None:
    """Populate host.device_type, host.category, host.flags, host.flag_reasons."""
    hay = _hay(host)
    ports = set(host.open_ports)
    vendor = (host.vendor or "").lower()

    camera_score = 0
    camera_why: list[str] = []

    # ---- camera / surveillance evidence ----
    if any(v in vendor for v in _CAMERA_VENDORS):
        camera_score += 3
        camera_why.append(f"vendor '{host.vendor}'")
    if any(w in hay for w in _CAMERA_WORDS):
        camera_score += 2
        camera_why.append("camera-related service/name string")
    if 554 in ports or 8554 in ports:
        camera_score += 3
        camera_why.append("RTSP video port open (554/8554)")
    if 2020 in ports:
        camera_score += 2
        camera_why.append("ONVIF port open (2020)")
    if 37777 in ports or 34567 in ports:
        camera_score += 3
        camera_why.append("DVR/NVR control port open")
    rtsp_banner = next((v for k, v in host.services.items() if k.startswith("rtsp")), "")
    if rtsp_banner:
        camera_score += 2
        camera_why.append(f"RTSP banner: {rtsp_banner}")

    is_dvr = (37777 in ports or 34567 in ports or 9999 in ports
              or any(w in hay for w in ("nvr", "dvr", "recorder")))

    # ---- voice assistant ----
    is_voice = any(v in vendor for v in _VOICE_VENDORS) or any(w in hay for w in _VOICE_WORDS)
    # Sonos is a speaker (mic-less mostly) but still smart-home; treat as IoT/voice-ish.

    # ---- decide the primary device type ----
    if host.is_gateway or (any(v in vendor for v in _ROUTER_VENDORS) and (7547 in ports or host.is_gateway)):
        host.device_type, host.category = "Router / Gateway", "network"
    elif camera_score >= 3:
        if is_dvr:
            host.device_type, host.category = "Surveillance DVR/NVR", "camera"
        else:
            host.device_type, host.category = "IP Camera", "camera"
    elif is_voice:
        host.device_type, host.category = "Voice Assistant / Speaker", "voice"
    elif any(w in hay for w in _TV_WORDS):
        host.device_type, host.category = "TV / Streaming device", "media"
    elif any(w in hay for w in _PRINTER_WORDS) or 9100 in ports or 631 in ports or 515 in ports:
        host.device_type, host.category = "Printer", "printer"
    elif any(w in hay for w in _CONSOLE_WORDS):
        host.device_type, host.category = "Game console", "media"
    elif any(v in vendor for v in _NAS_VENDORS) or (445 in ports and 5000 in ports):
        host.device_type, host.category = "NAS / Storage", "computer"
    elif any(v in vendor for v in _ROUTER_VENDORS) and any(p in ports for p in (53, 80, 443, 7547)):
        host.device_type, host.category = "Router / AP / Network gear", "network"
    elif any(v in vendor for v in _COMPUTER_VENDORS) or {22, 445, 3389, 5900, 62078} & ports:
        host.device_type, host.category = "Computer", "computer"
    elif "raspberry" in vendor:
        host.device_type, host.category = "Raspberry Pi", "computer"
    elif any(v in vendor for v in _PHONE_VENDORS) and host.randomized_mac:
        host.device_type, host.category = "Phone / Mobile", "mobile"
    elif 1883 in ports or 8883 in ports or 5555 in ports or "esp" in vendor or "tuya" in vendor or "espressif" in vendor:
        host.device_type, host.category = "IoT / Smart-home device", "iot"
    elif host.vendor:
        host.device_type, host.category = f"{host.vendor.split('(')[0].strip()} device", "unknown"
    else:
        host.device_type, host.category = "Unknown device", "unknown"

    # ===================================================================== FLAGS

    if host.category == "camera":
        _add_flag(host, "CAMERA", "Looks like a network camera: " + "; ".join(camera_why))
        if is_dvr:
            _add_flag(host, "SURVEILLANCE", "DVR/NVR control port or recorder name present")
    elif camera_score >= 2:  # suggestive but below the type threshold
        _add_flag(host, "CAMERA?", "Possible camera: " + "; ".join(camera_why))

    if host.category == "voice":
        _add_flag(host, "MIC", f"Always-on voice device ({host.device_type})")

    # Hidden / evasive
    if host.arp_only and not host.icmp_alive:
        _add_flag(host, "HIDDEN", "Answers ARP but ignores ICMP ping (not advertising itself)")
    if host.randomized_mac:
        _add_flag(host, "RANDOM-MAC", "Uses a randomised/locally-administered MAC (privacy or spoofing)")

    # Unknown
    if host.category == "unknown" and not host.vendor:
        _add_flag(host, "UNKNOWN", "Could not identify vendor or device type — worth a manual look")

    # Exposed / insecure services
    if 23 in ports or 2323 in ports:
        _add_flag(host, "INSECURE", "Telnet is open (cleartext, frequently default-credentialed)")
    web_login = any(
        k.startswith("http") and ("auth_realm" in k or "login" in (v or "").lower() or "sign in" in (v or "").lower())
        for k, v in host.services.items()
    )
    admin_ports = {80, 443, 8080, 8443, 8000, 81, 8081, 8888} & ports
    # Routers/APs legitimately expose an admin UI — that's expected, not a
    # finding. EXPOSED is reserved for cameras / IoT / unidentified hosts with
    # a reachable panel, or anything presenting an HTTP auth prompt.
    if web_login or (admin_ports and host.category in ("camera", "iot", "unknown") and not host.is_gateway):
        _add_flag(host, "EXPOSED", f"Has a reachable web/admin panel on port(s) {sorted(admin_ports) or '?'}")
    if 7547 in ports:
        _add_flag(host, "ISP-MGMT", "TR-069 remote-management port open (carrier-controlled)")
    if {3389, 5900, 5555} & ports:
        _add_flag(host, "REMOTE", f"Remote-control service open ({sorted({3389,5900,5555} & ports)})")

    if host.is_gateway:
        _add_flag(host, "ROUTER", "This is the network's gateway/router")


# Priority order for sorting/printing — most interesting flags first.
FLAG_PRIORITY = [
    "CAMERA", "SURVEILLANCE", "CAMERA?", "MIC", "HIDDEN", "UNKNOWN",
    "INSECURE", "EXPOSED", "REMOTE", "ISP-MGMT", "RANDOM-MAC", "NEW", "ROUTER",
]

# Flags that should make a device stand out as "worth looking at".
ALERT_FLAGS = {"CAMERA", "SURVEILLANCE", "CAMERA?", "MIC", "HIDDEN", "UNKNOWN",
               "INSECURE", "EXPOSED", "REMOTE"}


def is_alert(host: Host) -> bool:
    return any(f in ALERT_FLAGS for f in host.flags)


def sort_flags(flags: list[str]) -> list[str]:
    return sorted(flags, key=lambda f: FLAG_PRIORITY.index(f) if f in FLAG_PRIORITY else 99)
