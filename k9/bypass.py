"""403/401 access-control bypass via nomore403 (auto-run when a panel forbids us).

When a device's admin panel answers 403/401, ViperScan can hand the URL to the
user's installed nomore403 binary, which tries dozens of well-known bypass
techniques (header injection, path/case tricks, verb tampering, unicode, etc.)
and reports any that slip past the access control. We parse its JSON-Lines
output defensively (field names vary by version) and surface confirmed bypasses
as findings.

Authorized-testing tool — gated behind ViperScan's authorization scope and only
run as part of an explicit Deep audit, exactly like the credential check.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess


def _user_homes() -> list:
    """Candidate home directories. Crucially handles running under sudo: there
    `os.path.expanduser('~')` is /root, but the binary lives in the invoking
    user's home — so we resolve $SUDO_USER's home (and ViperScan's data home)."""
    homes = []
    su = os.environ.get("SUDO_USER")
    if su and su != "root":
        try:
            import pwd
            homes.append(pwd.getpwnam(su).pw_dir)
        except (KeyError, ImportError):
            pass
    vh = os.environ.get("VIPERSCAN_HOME")        # normally <home>/.viperscan
    if vh:
        homes.append(os.path.dirname(vh.rstrip("/")))
    homes.append(os.path.expanduser("~"))
    homes.append(os.environ.get("HOME", ""))
    out, seen = [], set()
    for h in homes:
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _find_binary() -> str:
    p = shutil.which("nomore403")
    if p:
        return p
    subs = ("nomore403/nomore403", "go/bin/nomore403", "tools/nomore403/nomore403",
            "nomore403", ".local/bin/nomore403", "opt/nomore403/nomore403",
            "Downloads/nomore403/nomore403")
    for h in _user_homes():
        for sub in subs:
            cp = os.path.join(h, sub)
            if os.path.isfile(cp) and os.access(cp, os.X_OK):
                return cp
    for cp in ("/usr/local/bin/nomore403", "/opt/nomore403/nomore403"):
        if os.path.isfile(cp) and os.access(cp, os.X_OK):
            return cp
    return ""


def _payloads_dir(binp: str) -> str:
    """Locate nomore403's `payloads/` directory. Without it, nomore403 silently
    SKIPS its most important techniques (headers, verb-tampering, end/mid-paths)
    and finds far fewer bypasses. nomore403's `-f` wants this dir itself."""
    cand = os.path.join(os.path.dirname(os.path.realpath(binp)), "payloads")
    if os.path.isdir(cand):
        return cand
    for h in _user_homes():
        for sub in ("nomore403/payloads", "tools/nomore403/payloads", "go/src/nomore403/payloads"):
            p = os.path.join(h, sub)
            if os.path.isdir(p):
                return p
    for p in ("/usr/local/share/nomore403/payloads", "/opt/nomore403/payloads"):
        if os.path.isdir(p):
            return p
    return ""


def available() -> bool:
    return bool(_find_binary())


_BLOCK_RE = re.compile(r"^\[\s*!?\s*\d+\s+\w+\]", re.M)
_HEAD_RE = re.compile(r"\[\s*!?\s*\d+\s+\w+\]\s+(.+?)\s+(\d{3})\s*(=>|->)\s*(\d{3})")


def _parse_human(text: str):
    """Parse nomore403's default (human) output — its --jsonl/-o modes are broken
    in current builds and write nothing. We pull confirmed bypasses out of the
    'LIKELY BYPASS' section: each block has a header (technique + 403=>NNN), an
    item:, and a multi-line curl: command (the exact request to reproduce it).
    Returns (successes, attempts)."""
    text = _re_ansi.sub("", text or "")
    attempts = 0
    m = re.search(r"(\d+)\s+techniques", text)         # "no visible results: N techniques"
    if m:
        attempts = int(m.group(1))
    region = text
    if "LIKELY BYPASS" in text:
        region = text.split("LIKELY BYPASS", 1)[1].split("INTERESTING VARIATIONS", 1)[0]
    elif "INTERESTING" in text or "FINDINGS" in text:
        region = ""                                    # no confirmed bypasses
    out, seen = [], set()
    starts = [mm.start() for mm in _BLOCK_RE.finditer(region)]
    for i, st in enumerate(starts):
        blk = region[st: starts[i + 1] if i + 1 < len(starts) else len(region)]
        hm = _HEAD_RE.match(blk)
        if not hm or hm.group(3) != "=>":              # only confirmed bypasses (403=>200)
            continue
        tech, final = hm.group(1).strip(), hm.group(4)
        im = re.search(r"item:\s*(.+)", blk)
        item = im.group(1).strip() if im else ""
        curl = ""
        cm = re.search(r"curl:\s*(.+(?:\n\s+.+)*)", blk)
        if cm:
            curl = re.sub(r"\\\s*\n\s+", " ", cm.group(1))
            curl = re.sub(r"\s+", " ", curl).strip()
        urls = re.findall(r"https?://[^\s'\"]+", curl or item)
        url = urls[-1] if urls else ""
        key = (final, tech[:60], (url or item)[:120])
        if key in seen:
            continue
        seen.add(key)
        out.append({"status": final, "technique": tech[:90], "url": url[:200],
                    "curl": curl[:1500], "item": item[:160], "length": None})
    return out[:25], max(attempts, len(starts))


_re_ansi = re.compile(r"\x1b\[[0-9;]*m")


def run(url: str, timeout: float = 90.0) -> dict:
    """Run nomore403 against a forbidden URL. Always returns a verdict AND a
    human 'reason' explaining the outcome — including WHY a bypass failed."""
    binp = _find_binary()
    if not binp:
        return {"available": False, "bypassed": False, "results": [], "attempts": 0,
                "reason": "nomore403 is not installed — couldn't attempt a bypass. "
                          "Install it (binary on PATH or ~/nomore403/nomore403)."}
    # NB: nomore403's --jsonl/-o write nothing in current builds, so we parse its
    # default human output from stdout instead. -f points it at its payloads dir
    # (else it silently skips header/verb/path techniques and finds far fewer).
    cmd = [binp, "-u", url, "--no-banner",
           "--timeout", "3000", "--retry-count", "1", "-m", "30"]
    payloads = _payloads_dir(binp)
    if payloads:
        cmd += ["-f", payloads]
    cwd = os.path.dirname(payloads) if payloads else (os.path.dirname(binp) or None)
    timed_out = False
    err = ""
    stdout = ""
    out_file = os.path.join("/tmp", "viperscan_nm_%x.out" % (abs(hash(url)) % (1 << 28)))
    try:
        with open(out_file, "w", encoding="utf-8", errors="replace") as ofh:
            # stdin=DEVNULL is REQUIRED — nomore403 hangs forever if stdin isn't a
            # closed/terminal fd. stdout→FILE (not a pipe) is also required: its
            # pterm output is suppressed on a pipe. We read the file back after.
            subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=ofh,
                           stderr=subprocess.STDOUT, timeout=timeout, check=False, cwd=cwd)
    except subprocess.TimeoutExpired:
        timed_out = True                 # partial output is still in the file
    except OSError as exc:
        err = str(exc)
    try:
        with open(out_file, encoding="utf-8", errors="replace") as rfh:
            stdout = rfh.read()
    except OSError:
        pass
    finally:
        try:
            os.remove(out_file)
        except OSError:
            pass
    results, attempts = _parse_human(stdout)
    bypassed = bool(results)
    if bypassed:
        reason = ("%d of %d techniques slipped past the 403 — the Forbidden page IS reachable."
                  % (len(results), attempts or len(results)))
    elif timed_out and attempts == 0:
        reason = ("nomore403 timed out after %ds before any technique completed "
                  "(target slow or unreachable)." % int(timeout))
    elif attempts == 0:
        reason = ("No techniques completed — the target was likely unreachable from here"
                  + ((", or the tool errored: " + err) if err else "."))
    else:
        reason = ("All %d bypass techniques still returned Forbidden — the access control held "
                  "(no header/path/verb/case trick got through)." % attempts
                  + (" [partial: timed out]" if timed_out else ""))
    return {"available": True, "url": url, "results": results, "bypassed": bypassed,
            "attempts": attempts, "timed_out": timed_out, "reason": reason}


# --------------------------------------------------------------------------- replay

# Captured bypassed-page bodies, keyed by a short id, so the dashboard can serve
# them back for one-click viewing. Bounded to the most recent handful.
_VIEWS: dict = {}
_VIEW_ORDER: list = []
_VIEW_CAP = 24


def _view_id(seed: str) -> str:
    return "%08x" % (abs(hash(seed)) & 0xFFFFFFFF)


def _register_view(vid, path, ctype, url):
    _VIEWS[vid] = {"path": path, "ctype": ctype or "text/html", "url": url}
    _VIEW_ORDER.append(vid)
    while len(_VIEW_ORDER) > _VIEW_CAP:
        old = _VIEW_ORDER.pop(0)
        v = _VIEWS.pop(old, None)
        if v:
            try:
                os.remove(v["path"])
            except OSError:
                pass


def replay(item: dict, timeout: float = 15.0) -> dict:
    """Re-issue ONE winning bypass request and capture the now-accessible page,
    so the user can open it. Uses nomore403's own curl line when present (run
    with no shell), else falls back to a GET on the bypass URL. Returns the item
    enriched with fetch status, a text preview, and a view id."""
    item = dict(item)
    url = item.get("url") or ""
    curl_cmd = (item.get("curl") or "").strip()
    if not shutil.which("curl"):
        item["replayed"] = False
        item["replay_error"] = "curl not installed"
        return item
    vid = _view_id((url or curl_cmd) + "|" + item.get("technique", ""))
    body_path = os.path.join("/tmp", "viperscan_bypass_%s.bin" % vid)

    args = None
    if curl_cmd.startswith("curl"):
        try:
            args = shlex.split(curl_cmd)
            args = [a for a in args if a != "-i"]   # drop -i so the saved body is clean HTML, not headers+body
        except ValueError:
            args = None
    if not args:
        method = (item.get("method") or "GET").upper()
        if not url:
            item["replayed"] = False
            return item
        args = ["curl", "-X", method, url, "--path-as-is"]
    # force our own capture flags (curl honours the last occurrence), no shell
    args += ["-k", "-s", "-L", "--max-time", str(int(timeout)),
             "-o", body_path, "-w", "%{http_code}\t%{content_type}"]
    code = ctype = ""
    try:
        cp = subprocess.run(args, capture_output=True, text=True,
                            timeout=timeout + 5, check=False)
        meta = (cp.stdout or "").strip().split("\t")
        code = meta[0] if meta else ""
        if len(meta) > 1 and meta[1].strip():
            ctype = meta[1].split(";")[0].strip()
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    length = 0
    snippet = ""
    try:
        with open(body_path, "rb") as fh:
            data = fh.read()
        length = len(data)
        txt = data[:6000].decode("utf-8", "replace")
        snippet = re.sub(r"<[^>]+>", " ", txt)
        snippet = re.sub(r"\s+", " ", snippet).strip()[:280]
    except OSError:
        pass
    item["replayed"] = bool(length)
    item["fetched_status"] = code
    item["content_type"] = ctype or "text/html"
    item["fetched_length"] = length
    item["snippet"] = snippet
    if length:
        _register_view(vid, body_path, ctype, url)
        item["view_id"] = vid
    else:
        item["view_id"] = ""
    return item


def read_view(view_id: str):
    """Return (content_type, bytes) for a captured bypassed page, or None."""
    v = _VIEWS.get(view_id)
    if not v:
        return None
    try:
        with open(v["path"], "rb") as fh:
            return v["ctype"], fh.read()
    except OSError:
        return None
