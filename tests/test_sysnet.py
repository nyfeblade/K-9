"""Cross-platform tests for k9.sysnet.

No test framework needed — run it directly:

    python3 tests/test_sysnet.py

The Linux path is exercised for real when run on Linux; the macOS and Windows
paths are checked by feeding canned real-world command output into the parsers,
so they're validated without needing a Mac/Windows host.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from k9 import sysnet  # noqa: E402

_failures = []


def check(name, got, want):
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"         got:  {got!r}\n         want: {want!r}")
        _failures.append(name)


def _set_os(linux, mac, win):
    sysnet.IS_LINUX, sysnet.IS_MAC, sysnet.IS_WINDOWS = linux, mac, win


def _fake_run(mapping):
    return lambda cmd, timeout=5: mapping.get(cmd[0], "")


# --- norm_mac: BSD short octets, Windows dashes -----------------------------
print("norm_mac:")
check("bsd short", sysnet.norm_mac("ac:83:e7:1:2:3"), "ac:83:e7:01:02:03")
check("win dashes", sysnet.norm_mac("A4-83-E7-2B-1C-9F"), "a4:83:e7:2b:1c:9f")
check("already ok", sysnet.norm_mac("01:00:5e:00:00:fb"), "01:00:5e:00:00:fb")
check("not a mac", sysnet.norm_mac("(incomplete)"), "")

# --- ping_command per OS ----------------------------------------------------
print("ping_command:")
_set_os(True, False, False)
check("linux", sysnet.ping_command("10.0.0.1", 1.0), ["ping", "-c", "1", "-W", "1", "-n", "10.0.0.1"])
_set_os(False, True, False)
check("macos", sysnet.ping_command("10.0.0.1", 1.0), ["ping", "-c", "1", "-t", "1", "-W", "1000", "10.0.0.1"])
_set_os(False, False, True)
check("windows", sysnet.ping_command("10.0.0.1", 1.0), ["ping", "-n", "1", "-w", "1000", "10.0.0.1"])

# --- macOS interface / gateway / arp parsing --------------------------------
MAC_IFCONFIG = (
    "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
    "\tinet 127.0.0.1 netmask 0xff000000\n"
    "\tinet6 ::1 prefixlen 128\n"
    "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
    "\tether a4:83:e7:2b:1c:9f\n"
    "\tinet6 fe80::14b6:1f8:aaaa:bbbb%en0 prefixlen 64 secured scopeid 0x9\n"
    "\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n"
    "\tstatus: active\n"
    "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n"
    "\tinet6 fe80::ce81:b1c:bd2c:69e%utun0 prefixlen 64 scopeid 0x11\n"
)
MAC_ROUTE = (
    "   route to: default\ndestination: default\n       mask: default\n"
    "    gateway: 192.168.1.1\n  interface: en0\n"
)
MAC_ARP = (
    "? (192.168.1.1) at ac:83:e7:1:2:3 on en0 ifscope [ethernet]\n"
    "? (192.168.1.42) at a4:83:e7:2b:1c:9f on en0 ifscope permanent [ethernet]\n"
    "? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]\n"
    "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n"
)
print("macOS parsers:")
_set_os(False, True, False)
sysnet._run = _fake_run({"ifconfig": MAC_IFCONFIG, "route": MAC_ROUTE, "arp": MAC_ARP})
ifs = sysnet.interfaces()
check("interfaces count (lo0/utun0 skipped)", len(ifs), 1)
check("iface name", ifs[0].name, "en0")
check("iface ip", ifs[0].ip, "192.168.1.42")
check("iface prefix (0xffffff00->24)", ifs[0].prefixlen, 24)
check("iface mac", ifs[0].mac, "a4:83:e7:2b:1c:9f")
check("gateway", sysnet.default_gateway(), "192.168.1.1")
check("arp (short octets padded, incomplete dropped)", sysnet.arp_table(), {
    "192.168.1.1": "ac:83:e7:01:02:03",
    "192.168.1.42": "a4:83:e7:2b:1c:9f",
    "224.0.0.251": "01:00:5e:00:00:fb",
})

# --- Windows arp parsing ----------------------------------------------------
WIN_ARP = (
    "\nInterface: 192.168.1.42 --- 0x5\n"
    "  Internet Address      Physical Address      Type\n"
    "  192.168.1.1           ac-83-e7-01-02-03     dynamic\n"
    "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
    "  224.0.0.22            01-00-5e-00-00-16     static\n"
)
print("Windows arp parser:")
_set_os(False, False, True)
sysnet._run = _fake_run({"arp": WIN_ARP})
check("arp (dash form)", sysnet.arp_table(), {
    "192.168.1.1": "ac:83:e7:01:02:03",
    "192.168.1.255": "ff:ff:ff:ff:ff:ff",
    "224.0.0.22": "01:00:5e:00:00:16",
})

print()
print("RESULT:", "ALL PASSED" if not _failures else f"{len(_failures)} FAILURE(S): {_failures}")
sys.exit(1 if _failures else 0)
