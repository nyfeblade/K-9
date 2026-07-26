# ⬡ K-9

**Know every device on the network you're sitting on — and which ones to look at twice.**

K-9 sweeps the local network, identifies every device's vendor and likely
type, and **flags the ones that matter**: cameras, surveillance DVRs, always-on
voice assistants, hidden hosts that hide from ping, exposed admin panels, and
anything it simply can't identify. Walk into any café, office, Airbnb, or hotel,
run one command, and see what's on the wire with you.

```bash
git clone https://github.com/nyfeblade/K-9
cd K-9 && python3 k9.py        # live dashboard → http://localhost:8731
```

> Throughout this README the command is written **`k9`** for brevity.
> Haven't installed it? That's just `python3 k9.py` — identical. To get a
> real `k9` on your `PATH`: `pipx install .` (or `pip install --user .`).

It's **pure Python, standard library only.** No `pip install`, no scapy, no root
required.

### Platform support

K-9 is **Linux-first** — that's where it's built and tested, and where
every feature works.

| OS | Status |
|---|---|
| **Linux** | ✅ Fully supported — all features |
| **macOS** | ⚠️ Partial — core scan, web dashboard and audit run; vendor ID falls back to the built-in brand map if nmap's OUI DB isn't installed; the **Wi-Fi locator does not work** (it needs Linux `AF_PACKET` + monitor mode) |
| **Windows** | ❌ Not yet — discovery relies on Linux networking tools (`ip`, `iw`) and `/proc`; needs a port. PRs welcome |

The **Wi-Fi RF locator** (`--locate`) is **Linux-only** by design — it uses a raw
`AF_PACKET` monitor-mode socket. Everything else is portable in principle; the
Linux assumptions are just not yet abstracted for macOS/Windows.

---

## What it does

| Stage | How |
|---|---|
| **Discovers hosts** | Threaded ICMP ping sweep primes the kernel ARP cache, then reads it back for IP↔MAC. Catches devices that *ignore* ping but still answer ARP (and flags them as hiding). Optional TCP-knock fallback for the truly stubborn. |
| **Identifies vendors** | Offline MAC→vendor lookup using whatever OUI database is already on the box (nmap's 42k-entry table, Wireshark's `manuf`, or IEEE `oui.txt`), plus a built-in camera/IoT brand map so the security-relevant vendors are *always* recognised. |
| **Fingerprints** | TCP connect-scan of camera/DVR/IoT/admin ports, HTTP `Server`/`<title>` + RTSP banners (cameras leak their model), plus **SSDP, mDNS/Bonjour and NetBIOS** name discovery for friendly names and models. |
| **Flags** | A transparent rule engine tags cameras, DVR/NVRs, mics, hidden hosts, unknown devices, telnet/exposed/remote-control services — each with a plain-English reason. |
| **Remembers** | Records the devices it has seen *per network* (keyed by gateway MAC, so home ≠ café). New MACs get a `NEW` flag — so "what just appeared?" is one scan away. |

### The flags

| Flag | Meaning |
|---|---|
| `CAMERA` / `CAMERA?` | Network camera (RTSP/ONVIF port, camera vendor, or model banner) |
| `SURVEILLANCE` | DVR / NVR / multi-camera recorder |
| `MIC` | Always-listening voice assistant (Echo, Nest, HomePod…) |
| `HIDDEN` | Answers ARP but ignores ICMP — not advertising itself |
| `UNKNOWN` | Couldn't be identified at all — worth a manual look |
| `INSECURE` | Telnet / known-weak service exposed |
| `EXPOSED` | Reachable web/admin login panel |
| `REMOTE` | RDP / VNC / ADB remote-control service open |
| `RANDOM-MAC` | Randomised/locally-administered MAC (privacy — or spoofing) |
| `NEW` | First time seen on this network |
| `ROUTER` | The gateway itself |

---

## Usage

**One command — everything is in the dashboard.** Just run:

```bash
python3 k9.py            # or just `k9` if you ran pipx install .
```

It launches the live web app at **http://localhost:8731** (and opens your
browser). From the page you control every mode without touching the command
line:

- **Scan mode** — `Quick` / `Deep` / `Unhide` (switching re-scans immediately)
- **Network** — type any CIDR (e.g. `10.0.0.0/24`) and hit *Scan*, or leave blank for the current LAN
- **Auto** — rescan interval (15s … hourly)
- **Scan now** — force an immediate rescan
- **Filters** — All / Flagged / Cameras / Mics / Unknown / New

### Click a device to investigate it

Click any card to open an **"about this device"** panel. In the background K-9:

1. **Finds its web/admin panels** — probes every web port over HTTP+HTTPS, ranks
   them, and **auto-opens the best one in a new browser tab** so you can log in
   and look. (A single-page app that answers `200` on every path is detected so
   you don't get false results.)
2. **Runs a deep probe** — nmap service/version (and OS, if launched with
   `sudo`) plus a check of common admin paths.
3. **Checks for factory passwords** — for the device's vendor it tries a short
   list of known default logins over HTTP Basic auth. If one still works, the
   device gets a red **`DEFAULT-CREDS`** flag telling you exactly which
   `user / password` opened it — so you can go change it.

### Per-device security audit

Clicking a device also runs a **security audit** and gives it a **risk score**
(0–100). It comes in two tiers so the loud stuff is opt-in:

**Quiet tier — runs automatically, low footprint:**
- **TLS certificate** inspection (self-signed / expired)
- **Known-CVE hints** from a curated, offline device→CVE map (e.g. flags a
  Hikvision/Dahua camera class with its known auth-bypass CVEs to check firmware)
- **Cleartext-admin** detection (login served over plain HTTP)
- **Internet-exposure** — queries your router over **UPnP** for WAN port-forwards
  and flags any device reachable from the **public internet**
- turns K-9's own flags (telnet, remote-control, etc.) into findings

**Deep tier — “🔍 Deep audit” button (loud, but no password guessing):**
- **nmap** service/version (and OS, as root)
- **RTSP open-stream check** — confirms a camera's video is viewable with **no
  password** and gives you the `ffplay rtsp://…` command to verify
- **anonymous FTP**

**Credential tier — its own “🔑 Test factory passwords” button + consent prompt:**
- **default-credential check** over HTTP **Basic and Digest**, with a vendor-
  targeted factory-password list (stops at the first hit).
- **Weak-password audit** (opt-in checkbox) — also tries the ~30 most common
  weak passwords. **Bounded** (hard cap of 60 attempts) and **lockout-aware**
  (it stops the moment the device starts blocking). It's a password-strength
  *audit*, deliberately **not** an unbounded wordlist cracker — a real
  brute-forcer would lock you out of or brick your own devices.
- **Lockout / rate-limit detection** — sends a few wrong logins to see whether
  the device resists brute-force at all. A device that accepts unlimited guesses
  with no throttle is itself flagged (it's brute-forceable).
- Kept fully separate from the Deep audit because it sends **real login
  attempts** the device logs — nothing guesses a password unless you click this
  button and confirm the "I own / am authorised to test this" dialog.

**🛡 Hardening checklist** — every audit attaches a concrete, per-device "how to
bulletproof this" list (isolate IoT on a VLAN, set a unique password, enable
lockout/2FA, remove internet exposure, disable Telnet, update firmware…). It
shows in the device modal and in the exported security report.

Each finding carries a severity, an explanation, and a fix recommendation; a red
flag (`DEFAULT-CREDS`, `OPEN-CAM`, `INTERNET`, `OPEN-FTP`) is pinned to the
device card.

> ⚠️ The deep tier **actively** tries logins, pulls camera streams, and runs
> nmap — all recorded by the target device, and some of it can trigger lockouts
> or alerts. It's a *defensive* audit for gear **you own** (the same thing a
> router-security check does). The quiet tier is passive-leaning; the deep tier
> is gated behind its own button for exactly this reason. Only use it on
> networks and devices you own or are authorised to test.

## Operator / red-team features

K-9 is built for **authorised** assessment, with the scaffolding to keep
it that way:

- **🛡 Authorisation scope** — you declare which CIDRs you're cleared to test.
  The quiet tier runs anywhere (it's just identification), but **the active
  tiers refuse to run against any IP outside your authorised scope** — the
  dashboard blocks them and offers an "Authorise this network" button. This is
  what keeps a publicly-distributed build white-hat by construction.
- **📄 Network security report** — one click generates a printable, self-
  contained HTML report (`/api/report`) ranking every device by risk score with
  all findings, CVE links and recommendations. Print-to-PDF for a deliverable.
- **🔔 Continuous monitoring + alerts** — each rescan is diffed against the last;
  a new device, a newly-opened port, or a device becoming **internet-exposed**
  raises an alert (with optional browser notifications).
- **🕑 History & timeline** — every device gets a reconstructed timeline (first
  seen, port-open history, online/offline windows: *"first seen 3 days ago,
  offline 8 h overnight, back online now"*) in its modal, and a **History**
  panel surfaces anomalies across the network — *"camera went offline at 2 AM"*,
  *"new admin/remote service opened"*, *"device appeared overnight"*, *"became
  internet-exposed"*. One-click **Export history (JSON)** for a compliance trail.
- **🗒 Engagement log** — every active action (deep audit, password test, scope
  change, report) is timestamped to `~/.k9/engagement.jsonl` as an audit
  trail.

State lives under `~/.k9/`: `scope.json`, `engagement.jsonl`,
`events.jsonl`, `known_devices.json`, `dashboard.json`. Nothing leaves the
operator's machine.

## Device intelligence & depth

- **Rename, tag & trust devices** — click a device to give it a custom name
  ("Michael's Wyze cam"), tag it, add notes, and mark it trusted/untrusted. All
  of it **survives rescans and restarts**, and the dashboard remembers your
  scan mode / network / interval too.
- **DHCP-lease hostnames** — if K-9 runs on the DHCP server (a Pi-hole /
  dnsmasq / router box), it reads the lease file for authoritative names,
  turning `UNKNOWN` devices into named ones.
- **Port timeline** — every device tracks when each port first opened ("open
  since …"), so you can tell a long-standing service from a new one.
- **Native TLS posture** — protocol + cipher + cert + HSTS checks via Python's
  own `ssl` (flags TLS ≤ 1.1, weak ciphers, expired/self-signed certs) — no
  external `openssl` needed.
- **Real UDP scanning** — protocol-specific probes for DNS, NTP, TFTP, SNMP and
  CoAP that a TCP scan can't see, plus adaptive retry for rate-limiting devices.
- **IoT exposure checks** — open MQTT brokers, open CoAP endpoints, and a
  non-destructive **SNMP-write** test (reconfigurable-over-SNMP).
- **JSON export** — ⬇ Export downloads the full device inventory from the
  dashboard (parity with the CLI's `--json`).
- **Activity — "what is it doing now?"** — click a device → 📈 Check activity:
  liveness (online / latency / jitter / loss), which services are live this
  instant, whether a camera's stream is actually up, the **real throughput** of
  SNMP-enabled gear (live ↓/↑ bits-per-second + uptime), and the role it plays
  (AirPlay receiver, RTSP source, DNS resolver, printer, MQTT broker…).

  > Honest limit: on a switched / Wi-Fi network, a host that isn't the gateway
  > cannot see the *private* traffic between other devices and the internet —
  > that's how switches work. K-9 reports what each device advertises and
  > its live state; seeing all traffic would need router-level capture or
  > intrusive ARP-spoofing, which K-9 deliberately does not do.

- **📡 Locate — Wi-Fi hot/cold finder** — pick a device and physically walk it
  down: a live signal-strength meter rises as you get closer (🔥 warmer / ❄
  colder). The real way to find a hidden camera/tracker. Pure-Python 802.11
  capture (radiotap RSSI, no scapy).

  ```bash
  sudo python3 k9.py --locate 192.168.1.50      # live terminal meter
  ```

  **One-click in the dashboard:** run the dashboard with sudo
  (`sudo python3 k9.py --web`), click a device → **🛰 Find this device**.
  It **auto-detects** a monitor-capable adapter (preferring a 2nd adapter so your
  main connection stays up), flips it into monitor mode, **auto-pings the device
  to keep it awake/transmitting**, captures RSSI, and shows the live gauge —
  then **Stop** restores the adapter. No terminal, no manual `iw`/`nmcli`.
  Without sudo it explains how to enable it (and the CLI command still works).

  > **Linux only.** Needs **sudo** + a **monitor-mode-capable** Wi-Fi adapter,
  > and only works for Wi-Fi devices. It reports *relative proximity* (signal
  > trend), not
  > coordinates — a single antenna can't triangulate. A 2nd USB Wi-Fi adapter
  > lets you stay online while the other sniffs. Trust the trend, not the
  > absolute distance (walls and orientation skew RSSI).

### Prefer the terminal?

Everything is still scriptable with `--cli` (or any output flag, which implies it):

```bash
k9 --cli               # one-shot flagged report in the terminal
k9 --cli --deep        # full port list — slower, more thorough
k9 --cli --unhide      # squeeze identity out of quiet/HIDDEN hosts
k9 --cli --alerts-only # only the flagged devices
k9 --watch 30          # rescan every 30s, announce what changed
k9 --json out.json     # machine-readable output
k9 --net 10.0.0.0/24   # (web) open the dashboard pre-pointed at a subnet
```

### "Unhiding" quiet devices

A `HIDDEN` flag just means the device answered **ARP** (so we know it's there,
and we have its MAC + vendor) but ignored our **ICMP ping** — almost always a
firewall/privacy setting, not anything sinister. It isn't invisible, just quiet.

To identify what a quiet device actually *is*, run `--unhide`. On top of the
normal scan it adds, per host:

- a **full port scan** (implies `--deep`),
- an **SNMP** `sysDescr`/`sysName` probe (UDP/161) — this alone often names the
  exact make/model/firmware of printers, routers, switches, cameras and IoT,
- a **NetBIOS** name query for every host (not just ones advertising SMB), and
- for hosts that are *still* completely dark, an **nmap** service/version probe
  (and OS detection too, if you run it with `sudo`).

```bash
k9 --unhide            # deep-identify everything
sudo k9 --unhide       # adds nmap OS detection + a true ARP sweep
k9 --unhide --no-nmap  # skip the (slower) nmap step
```

Note: `--unhide` is slower because of the SNMP/NetBIOS/nmap probes, and a device
with a firewall up and no services running may *still* come back `UNKNOWN` —
at which point its MAC vendor is your best lead. The `HIDDEN` flag itself stays
(it's a true description of the host's ping behaviour); what changes is that the
device usually gets a real name and type instead of `UNKNOWN`.

Run it directly without installing anything:

```bash
python3 k9.py            # from inside the K-9/ folder
# or
./k9-run.sh --web
```

### Install (optional — for a `k9` command on your PATH)

K-9 runs fine uninstalled (above). If you'd rather type `k9` from
anywhere, install it — it's still stdlib-only, the install just drops a launcher
on your `PATH`:

```bash
pipx install .                  # recommended (isolated); from inside K-9/
# or
pip install --user .
k9                       # now works anywhere → same as python3 k9.py
```

### Docker

```bash
docker compose up                      # dashboard → http://localhost:8731
# or
docker build -t k9 .
docker run --rm -it --net host k9          # dashboard
docker run --rm -it --net host k9 --cli    # one-shot terminal report
```

`--net host` is **required** — K-9 discovers devices by ARP/ping on the
host's LAN, which a bridged container can't see. Mount a volume on `/data`
(`-v k9-data:/data`) to persist scope/known-devices/config across runs.

### Prometheus metrics

The dashboard exposes a `/metrics` endpoint in Prometheus text format —
device counts, online/new/flagged totals, open-port count, per-flag and
per-category gauges, and scan timing. Point Prometheus at it and graph your
network in Grafana:

```yaml
scrape_configs:
  - job_name: k9
    static_configs: [{ targets: ["localhost:8731"] }]
```

(`/metrics` is read-only counts only — no per-device detail. It's served on
whatever address you bind; keep the dashboard on loopback unless your scrape
host needs it, then `--bind 0.0.0.0` on a trusted network.)

### Keyboard & mouse

In the dashboard: <kbd>s</kbd> scan now · <kbd>e</kbd> export ·
<kbd>/</kbd> jump to the network field · <kbd>?</kbd> shortcut help ·
<kbd>Esc</kbd> close. **Right-click any device** for copy IP / MAC / vendor and
a one-click OUI lookup.

### Optional: sharper discovery
- Run as **root** with `scapy` installed and K-9 adds a true ARP broadcast
  sweep (catches the last stragglers). Neither is required — the no-root path
  already finds everything that answers ARP.
- `--deep` scans the full ~60-port list instead of the fast default set.

---

## Is this legal / safe?

K-9 only looks at the network **you are already connected to** — the same
thing your laptop's "see devices on this network" feature does, just far more
thorough and security-aware. It's passive-leaning (ping, ARP read, light TCP
connects, standard discovery multicast). **Only scan networks you own or are
authorised to assess.** Port-scanning networks you don't control may violate
their acceptable-use policy or local law.

Everything stays on your machine: the device memory lives in
`~/.k9/known_devices.json` and nothing is sent anywhere.

---

## How it stays zero-dependency

- **Discovery:** system `ping` + `ip neigh` (or `/proc/net/arp`)
- **Vendors:** parses an OUI database already present on the system
- **Fingerprinting:** raw `socket` TCP connects + hand-rolled SSDP/mDNS/NetBIOS
- **Dashboard:** stdlib `http.server` serving one self-contained HTML page

No third-party packages. Python 3.9+.

---

*Part of the Nyfe toolkit.*
