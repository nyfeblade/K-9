"""Authorization scope, engagement journal, and monitoring-event log.

The scope is the professional guardrail: a list of CIDRs you've declared you're
authorised to actively test. The *quiet* tier (passive identification) runs
anywhere — it's no more than your OS's "devices on this network" view — but the
*active* tiers (deep audit, factory-password test) refuse to run against an IP
that isn't inside an authorised network. That keeps a worldwide-distributed
build white-hat by construction and gives you an audit trail.

Three small JSON stores under ~/.viperscan/:
  scope.json        — authorised CIDRs
  engagement.jsonl  — every active action you took (what / where / when)
  events.jsonl      — monitoring alerts (new device, new port, new exposure…)
"""

from __future__ import annotations

import ipaddress
import json
import os
import time


def _base() -> str:
    base = os.environ.get("VIPERSCAN_HOME") or os.path.expanduser("~/.viperscan")
    os.makedirs(base, exist_ok=True)
    return base


def _p(name: str) -> str:
    return os.path.join(_base(), name)


def _stamp(now=None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now if now is not None else time.time()))


# --------------------------------------------------------------- scope

def load_scope() -> dict:
    try:
        with open(_p("scope.json")) as fh:
            data = json.load(fh)
            data.setdefault("authorized", [])
            return data
    except (OSError, json.JSONDecodeError):
        return {"authorized": []}


def save_scope(s: dict) -> None:
    try:
        with open(_p("scope.json"), "w") as fh:
            json.dump(s, fh, indent=2)
    except OSError:
        pass


def authorized_list() -> list:
    return load_scope().get("authorized", [])


def add_cidr(cidr: str):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False, "invalid CIDR"
    s = load_scope()
    c = str(net)
    if c not in s["authorized"]:
        s["authorized"].append(c)
        save_scope(s)
        log_engagement("scope_add", c, "network authorised for active testing")
    return True, c


def remove_cidr(cidr: str) -> bool:
    s = load_scope()
    before = len(s.get("authorized", []))
    s["authorized"] = [c for c in s.get("authorized", []) if c != cidr]
    save_scope(s)
    if before != len(s["authorized"]):
        log_engagement("scope_remove", cidr, "network removed from authorised scope")
        return True
    return False


def is_authorized(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in authorized_list():
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def suggested_cidr(ip: str) -> str:
    """The /24 around an IP, offered as the network to authorise."""
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ""


# --------------------------------------------------------------- jsonl logs

def _append(path: str, obj: dict) -> None:
    try:
        with open(path, "a") as fh:
            fh.write(json.dumps(obj) + "\n")
    except OSError:
        pass


def _read(path: str, limit: int) -> list:
    out = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        return []
    return out[-limit:]


def log_engagement(kind: str, target: str = "", detail: str = "", now=None) -> dict:
    ev = {"ts": _stamp(now), "kind": kind, "target": target, "detail": detail}
    _append(_p("engagement.jsonl"), ev)
    return ev


def read_engagement(limit: int = 300) -> list:
    return list(reversed(_read(_p("engagement.jsonl"), limit)))


def log_event(etype: str, ip: str = "", detail: str = "", now=None) -> dict:
    ev = {"ts": _stamp(now), "type": etype, "ip": ip, "detail": detail}
    _append(_p("events.jsonl"), ev)
    return ev


def read_events(limit: int = 200) -> list:
    return list(reversed(_read(_p("events.jsonl"), limit)))


def clear_events(etype: str | None = None) -> int:
    """Drop monitoring events. With etype, only that type is removed (so e.g.
    clearing one alert category leaves the others intact); without it,
    all events are wiped. Returns how many were removed."""
    path = _p("events.jsonl")
    kept, removed = [], 0
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if etype is None or ev.get("type") == etype:
                    removed += 1
                else:
                    kept.append(ev)
    except OSError:
        return 0
    try:
        with open(path, "w") as fh:
            for ev in kept:
                fh.write(json.dumps(ev) + "\n")
    except OSError:
        pass
    return removed
