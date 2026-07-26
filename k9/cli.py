"""ViperScan command-line entry point and scan orchestration."""

from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import __version__, classify, dhcp, discovery, fingerprint, netinfo, oui, report
from .discovery import Host


def _normalize_data_home():
    """Keep the data directory consistent whether ViperScan runs normally or
    under sudo. Under sudo, ~ resolves to /root, which would split your
    annotations/scope/config from your normal-user store. Pin it to the
    invoking user's ~/.viperscan via $SUDO_USER so renames etc. survive."""
    if os.environ.get("VIPERSCAN_HOME"):
        return
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            import pwd
            home = pwd.getpwnam(sudo_user).pw_dir
            if home:
                os.environ["VIPERSCAN_HOME"] = os.path.join(home, ".viperscan")
        except (KeyError, ImportError):
            pass


def _eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


def _progress_bar(done: int, total: int, label: str) -> None:
    if not sys.stderr.isatty():
        return
    width = 28
    filled = int(width * done / max(1, total))
    bar = "█" * filled + "░" * (width - filled)
    _eprint(f"\r  {label:<14} [{bar}] {done}/{total}   ", end="")
    if done >= total:
        _eprint("\r" + " " * 60 + "\r", end="")


def run_scan(args) -> tuple[list[Host], dict]:
    t0 = time.time()
    info = netinfo.gather()
    net, targets = netinfo.resolve_targets(args.net, info)
    cidr = str(net)
    iface = info.primary.name if info.primary else "?"
    self_ip = info.primary.ip if info.primary else ""
    self_mac = info.primary.mac if info.primary else ""

    db = oui.OuiDB()

    if not args.quiet:
        _eprint(f"  ViperScan v{__version__} · scanning {cidr} on {iface} "
                f"({len(targets)} addresses)…")

    # 1) discover hosts
    hosts_map = discovery.sweep(
        targets, cidr,
        timeout=args.timeout, workers=args.workers,
        tcp_fallback=not args.no_tcp_knock,
        progress=None if args.quiet else _progress_bar,
    )
    hosts = list(hosts_map.values())

    # tag self / gateway and fill vendor
    gateway_mac = ""
    arp_now = discovery.read_arp_table()
    for h in hosts:
        if not h.mac:
            h.mac = arp_now.get(h.ip, "")
        h.is_self = (h.ip == self_ip)
        if h.is_self and not h.mac:
            h.mac = self_mac
        h.is_gateway = (h.ip == info.gateway)
        if h.is_gateway:
            gateway_mac = h.mac
        h.vendor = db.lookup(h.mac) if h.mac else ""

    # ensure self shows up even if it didn't answer its own ping
    if self_ip and self_ip not in hosts_map:
        me = Host(ip=self_ip, mac=self_mac, icmp_alive=True, via="self", is_self=True)
        me.vendor = db.lookup(self_mac)
        hosts.append(me)

    # Authoritative names from a local DHCP server's lease file, if present
    # (no-op on a normal client box). Applied as the base hostname.
    dhcp_mac, dhcp_ip = dhcp.leases()
    if dhcp_mac or dhcp_ip:
        for h in hosts:
            if not h.hostname:
                name = dhcp_mac.get((h.mac or "").lower()) or dhcp_ip.get(h.ip)
                if name:
                    h.hostname = name

    # 2) network-wide name discovery (one multicast round, shared by all hosts)
    if not args.no_discovery:
        if not args.quiet:
            _eprint("  discovering service announcements (SSDP / mDNS)…")
        _merge_multicast(hosts)

    # 3) per-host fingerprint (ports + banners + names) in parallel
    if not args.no_ports:
        deep_ports = args.deep or args.unhide
        ports = list(fingerprint.PORTS) if deep_ports else fingerprint.QUICK_PORTS
        if args.unhide and not args.quiet:
            _eprint("  --unhide: deep-identifying quiet hosts (SNMP / NetBIOS / nmap)…")
        _fingerprint_hosts(hosts, ports, args, quiet=args.quiet)

    # 4) classify + flag
    for h in hosts:
        classify.classify(h)

    # 5) cross-scan memory → NEW flags
    if not args.no_memory:
        report.apply_memory(hosts, gateway_mac, cidr, t0)

    meta = {
        "cidr": cidr, "iface": iface, "gateway": info.gateway,
        "self_ip": self_ip, "scanned": len(targets),
        "elapsed": time.time() - t0, "oui_source": db.source,
        "oui_entries": len(db), "deep": args.deep,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t0)),
    }
    return hosts, meta


def _merge_multicast(hosts: list[Host]) -> None:
    by_ip = {h.ip: h for h in hosts}

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_ssdp = pool.submit(fingerprint.ssdp_discover, 3.0)
        f_mdns = pool.submit(fingerprint.mdns_discover, 3.0)
        ssdp = f_ssdp.result()
        mdns = f_mdns.result()

    for ip, entry in ssdp.items():
        h = by_ip.get(ip)
        if not h:
            continue
        for k, v in entry.items():
            if k in ("ssdp_name", "ssdp_manufacturer", "ssdp_model", "ssdp_desc",
                     "ssdp_devicetype", "server"):
                h.services[k if k != "server" else "ssdp_server"] = v
    for ip, entry in mdns.items():
        h = by_ip.get(ip)
        if not h:
            continue
        for k, v in entry.items():
            if k.startswith("mdns") and not k.startswith("_"):
                h.services[k] = v


def _fingerprint_one(h: Host, ports, args) -> None:
    h.open_ports = fingerprint.scan_ports(
        h.ip, ports, timeout=args.port_timeout, workers=args.port_workers
    )
    # Protocol-specific UDP services (DNS/NTP/TFTP/SNMP/CoAP) that a TCP scan
    # can't see — merge them into the port list.
    for p, lbl in fingerprint.udp_scan(h.ip).items():
        h.open_ports.setdefault(p, lbl)
    if h.open_ports:
        for k, v in fingerprint.banners_for(h.ip, h.open_ports).items():
            h.services.setdefault(k, v)
    if not args.no_dns and not h.hostname:
        h.hostname = fingerprint.reverse_dns(h.ip)
    if not h.hostname and (139 in h.open_ports or 445 in h.open_ports):
        nb = fingerprint.netbios_name(h.ip)
        if nb:
            h.services["netbios"] = nb
            h.hostname = h.hostname or nb

    deep = args.deep or args.unhide
    if deep:
        # SNMP frequently names quiet printers / routers / cameras / IoT outright.
        snmp = fingerprint.snmp_identify(h.ip)
        for k, v in snmp.items():
            h.services.setdefault(k, v)
        if not h.hostname and snmp.get("snmp_name"):
            h.hostname = snmp["snmp_name"]
        # NetBIOS for every host, not just those advertising SMB.
        if not h.hostname:
            nb = fingerprint.netbios_name(h.ip)
            if nb:
                h.services.setdefault("netbios", nb)
                h.hostname = nb

    if args.unhide and not args.no_nmap:
        # Last resort for a host that is *still* completely dark: ask nmap.
        named = any(k in h.services for k in ("mdns_name", "ssdp_name", "ssdp_model", "snmp"))
        dark = not h.open_ports and not h.hostname and not named
        hidden = h.arp_only and not h.icmp_alive
        if dark or (hidden and not h.open_ports):
            for k, v in fingerprint.nmap_deep(h.ip).items():
                h.services.setdefault(k, v)
            if not h.vendor and h.services.get("nmap_vendor"):
                h.vendor = h.services["nmap_vendor"]


def _fingerprint_hosts(hosts: list[Host], ports, args, quiet: bool) -> None:
    total = len(hosts)
    done = 0
    if not quiet:
        _progress_bar(0, total, "fingerprint")
    # Outer concurrency across hosts; each host runs its own inner port pool.
    with ThreadPoolExecutor(max_workers=min(24, max(4, total))) as pool:
        futs = {pool.submit(_fingerprint_one, h, ports, args): h for h in hosts}
        for fut in as_completed(futs):
            try:
                fut.result()
            except Exception:
                pass
            done += 1
            if not quiet:
                _progress_bar(done, total, "fingerprint")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="viperscan",
        description="ViperScan — discover and flag every device on the network you're on.",
        epilog="Examples:\n"
               "  viperscan                     launch the dashboard (all modes live in the browser)\n"
               "  viperscan --net 10.0.0.0/24   open the dashboard pre-pointed at a subnet\n"
               "  viperscan --cli               one-shot terminal report instead of the dashboard\n"
               "  viperscan --cli --unhide      terminal report, deep-identifying quiet hosts\n"
               "  viperscan --watch 30          terminal: rescan every 30s, alert on new/changed\n"
               "  viperscan --json out.json     terminal: write machine-readable results\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--net", help="CIDR to scan (default: your current subnet)")
    p.add_argument("--deep", action="store_true", help="scan the full port list (more thorough, slower)")
    p.add_argument("--unhide", action="store_true",
                   help="work harder to identify quiet/HIDDEN hosts: full ports + SNMP + NetBIOS + (if nmap installed) service/OS detection")
    p.add_argument("--no-nmap", action="store_true", help="in --unhide mode, skip the nmap service/OS step")
    p.add_argument("--watch", type=float, metavar="SECS", help="rescan every SECS seconds and report changes")
    p.add_argument("--web", action="store_true", help="force the live web dashboard (this is the default with no other flags)")
    p.add_argument("--cli", action="store_true", help="force a one-shot terminal report instead of the web dashboard")
    p.add_argument("--selfcheck", action="store_true", help="run a system self-check proving every subsystem hits real (not simulated) data")
    p.add_argument("--reload", action="store_true", help="dev mode: auto-restart on source change + auto-refresh the browser + take over a busy port")
    p.add_argument("--port", type=int, default=8731, help="web dashboard port (default 8731)")
    p.add_argument("--bind", metavar="ADDR", help="address the dashboard binds (default 127.0.0.1 — loopback only). The dashboard controls host-level actions; only pass 0.0.0.0 on a trusted network.")
    p.add_argument("--no-open", dest="open", action="store_false", help="in web mode, don't auto-open the browser")
    p.add_argument("--json", metavar="FILE", help="write results as JSON ('-' for stdout)")
    p.add_argument("--alerts-only", action="store_true", help="only print flagged devices")
    p.add_argument("--timeout", type=float, default=1.0, help="per-host ping timeout seconds (default 1.0)")
    p.add_argument("--workers", type=int, default=256, help="parallel ping workers (default 256)")
    p.add_argument("--port-timeout", type=float, default=0.6, help="per-port connect timeout (default 0.6)")
    p.add_argument("--port-workers", type=int, default=128, help="parallel port workers per host (default 128)")
    p.add_argument("--no-ports", action="store_true", help="skip port scanning (discovery + vendor only)")
    p.add_argument("--no-discovery", action="store_true", help="skip SSDP/mDNS service discovery")
    p.add_argument("--no-dns", action="store_true", help="skip reverse-DNS lookups")
    p.add_argument("--no-tcp-knock", action="store_true", help="skip TCP fallback probing during discovery")
    p.add_argument("--no-memory", action="store_true", help="don't record/compare against known devices (no NEW flag)")
    p.add_argument("--no-keepalive", action="store_true", help="(web) don't continuously ping discovered devices to keep them live")
    p.add_argument("--quiet", action="store_true", help="suppress progress output")
    p.add_argument("--locate", metavar="IP/MAC",
                   help="Wi-Fi hot/cold finder: live signal meter to physically track down a device (needs sudo + a monitor-mode adapter)")
    p.add_argument("--iface", help="wireless interface to use for --locate (default: auto)")
    p.add_argument("--channel", type=int, help="lock --locate to a specific Wi-Fi channel (default: auto-hop)")
    p.add_argument("--version", action="version", version=f"ViperScan {__version__}")
    return p


def main(argv=None) -> int:
    _normalize_data_home()   # so sudo and non-sudo share the same data dir
    args = build_parser().parse_args(argv)

    if args.locate:
        from . import wifiloc
        return wifiloc.run_cli(args)

    if args.selfcheck:
        from . import selfcheck
        return selfcheck.run_cli()

    # One command, everything in the browser: the web dashboard is the default.
    # The terminal report is opt-in via --cli, or implied by output-oriented
    # flags (--json / --watch / --alerts-only) that only make sense in a shell.
    cli_mode = args.cli or bool(args.json) or args.alerts_only or args.watch
    if args.web or not cli_mode:
        from . import web
        return web.serve(args)

    if args.watch:
        return _watch_loop(args)

    hosts, meta = run_scan(args)
    _emit(hosts, meta, args)
    return 0


def _emit(hosts, meta, args) -> None:
    if args.json:
        out = report.to_json(hosts, meta)
        if args.json == "-":
            print(out)
        else:
            with open(args.json, "w") as fh:
                fh.write(out)
            _eprint(f"  wrote {len(hosts)} devices → {args.json}")
        if args.json != "-":
            print(report.render(_maybe_filter(hosts, args), meta))
    else:
        print(report.render(_maybe_filter(hosts, args), meta))


def _maybe_filter(hosts, args):
    if args.alerts_only:
        return [h for h in hosts if classify.is_alert(h)]
    return hosts


def _watch_loop(args) -> int:
    seen_flags: dict[str, set] = {}
    try:
        while True:
            hosts, meta = run_scan(args)
            print("\033[2J\033[H", end="")  # clear screen
            print(report.render(_maybe_filter(hosts, args), meta))
            # announce changes vs previous round
            changes = []
            current = {h.mac or h.ip: set(h.flags) for h in hosts}
            for key, flags in current.items():
                prev = seen_flags.get(key)
                if prev is None:
                    changes.append(("appeared", key))
                elif flags - prev:
                    changes.append(("changed", key))
            for key in seen_flags.keys() - current.keys():
                changes.append(("vanished", key))
            seen_flags = current
            if changes:
                print(report.bold("  changes since last scan:"))
                for kind, key in changes[:20]:
                    print(f"    {kind:<10} {key}")
            print(report.grey(f"\n  next scan in {args.watch:.0f}s — Ctrl-C to stop"))
            time.sleep(args.watch)
    except KeyboardInterrupt:
        _eprint("\n  stopped.")
        return 0
