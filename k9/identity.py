"""User annotations on devices — names, tags, notes, trust — that survive
rescans and restarts.

Annotations live inside the same per-network device store report.py already
maintains (~/.viperscan/known_devices.json), attached to each device record by
its MAC (falling back to IP). apply_memory() preserves these fields when it
refreshes a record, so a device you renamed stays renamed forever.
"""

from __future__ import annotations

from . import report

_ANNOTATION_FIELDS = ("user_label", "note", "trust")
_TRUST_VALUES = ("trusted", "untrusted", "")


def _find_record(store: dict, mac: str, ip: str):
    """Return (netkey, devkey, record) for a device by MAC (preferred) or IP."""
    mac = (mac or "").lower()
    for netkey, net in store.items():
        devices = net.get("devices", {})
        if mac and mac in devices:
            return netkey, mac, devices[mac]
        for dk, rec in devices.items():
            if (mac and rec.get("mac", "").lower() == mac) or (ip and rec.get("ip") == ip):
                return netkey, dk, rec
    return None, None, None


def annotate(ip: str, mac: str = "", *, user_label=None, note=None, trust=None, tags=None) -> dict:
    """Set annotation fields on a device; returns the updated annotation dict."""
    with report.STORE_LOCK:    # serialise against the scan loop's writes
        store = report.load_store()
        _netkey, _dk, rec = _find_record(store, mac, ip)
        if rec is None:
            return {}
        if user_label is not None:
            rec["user_label"] = str(user_label)[:60]
        if note is not None:
            rec["note"] = str(note)[:500]
        if trust is not None and trust in _TRUST_VALUES:
            rec["trust"] = trust
        if tags is not None:
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            rec["tags"] = [str(t)[:30] for t in tags if str(t).strip()][:12]
        report.save_store(store)
        return get(ip, mac)


def get(ip: str, mac: str = "") -> dict:
    store = report.load_store()
    _netkey, _dk, rec = _find_record(store, mac, ip)
    if rec is None:
        return {}
    return {
        "user_label": rec.get("user_label", ""),
        "note": rec.get("note", ""),
        "trust": rec.get("trust", ""),
        "tags": rec.get("tags", []),
    }
