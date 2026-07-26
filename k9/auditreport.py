"""Network-wide security report — a printable, self-contained HTML deliverable.

Runs a quiet audit on every discovered device (in parallel), ranks them by risk
score, and renders one standalone HTML page you can open, hand to a client, or
print to PDF (Ctrl-P). Light theme on purpose — it's a document, not a dashboard.
"""

from __future__ import annotations

import html
from concurrent.futures import ThreadPoolExecutor

from . import __version__, audit

_SEV_COLOR = {"critical": "#c0344a", "high": "#d2691e", "medium": "#b8860b",
              "low": "#2f6fb0", "info": "#6b7280"}
_RISK_COLOR = {"critical": "#c0344a", "elevated": "#b8860b", "low": "#2f6fb0",
               "clean": "#1f8a4c"}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _audit_all(devices, exposure):
    def go(d):
        try:
            return d, audit.audit(d.get("ip", ""), d, deep=False, exposure=exposure)
        except Exception:
            return d, {"risk": {"score": 0, "label": "clean", "color": "green"}, "findings": []}
    with ThreadPoolExecutor(max_workers=8) as ex:
        rows = list(ex.map(go, devices))
    rows.sort(key=lambda x: -x[1]["risk"]["score"])
    return rows


def build(devices, meta, exposure, authorized) -> str:
    rows = _audit_all(devices, exposure)
    total = len(rows)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    risk_counts = {"critical": 0, "elevated": 0, "low": 0, "clean": 0}
    for _d, r in rows:
        risk_counts[r["risk"]["label"]] = risk_counts.get(r["risk"]["label"], 0) + 1
        for f in r["findings"]:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    cards = []
    for d, r in rows:
        risk = r["risk"]
        rc = _RISK_COLOR.get(risk["label"], "#6b7280")
        findings_html = ""
        for f in r["findings"]:
            sc = _SEV_COLOR.get(f["severity"], "#6b7280")
            cves = ""
            if f.get("cves"):
                cves = "<div class='cves'>" + "".join(
                    f"<div><a href='https://nvd.nist.gov/vuln/detail/{_esc(c['id'])}'>{_esc(c['id'])}</a> "
                    f"<b>CVSS {_esc(c['cvss'])}</b> — {_esc(c['desc'])}</div>" for c in f["cves"]
                ) + "</div>"
            findings_html += (
                f"<div class='f'><span class='sev' style='background:{sc}'>{_esc(f['severity'])}</span> "
                f"<b>{_esc(f['title'])}</b>"
                f"<div class='fd'>{_esc(f['detail'])}</div>{cves}"
                + (f"<div class='fr'>Recommendation: {_esc(f['recommendation'])}</div>" if f.get("recommendation") else "")
                + "</div>"
            )
        if not r["findings"]:
            findings_html = "<div class='none'>No issues found in the quiet audit.</div>"
        harden_html = ""
        if r.get("hardening"):
            harden_html = "<div class='harden'><b>Hardening:</b><ul>" + "".join(
                f"<li><b>{_esc(h['title'])}</b> — {_esc(h['detail'])}</li>" for h in r["hardening"]
            ) + "</ul></div>"
        ports = ", ".join(f"{p}/{l}" for p, l in (d.get("open_ports") or {}).items()) or "—"
        cards.append(f"""
        <div class="dev">
          <div class="devhead">
            <div class="rs" style="border-color:{rc};color:{rc}">{risk['score']}</div>
            <div class="dh">
              <div class="dn">{_esc(d.get('display_name') or d.get('device_type'))}</div>
              <div class="dm">{_esc(d.get('ip'))} &nbsp;·&nbsp; {_esc(d.get('mac') or '—')} &nbsp;·&nbsp; {_esc(d.get('vendor') or 'unknown vendor')}</div>
            </div>
            <div class="rl" style="color:{rc}">{_esc(risk['label']).upper()}</div>
          </div>
          <div class="ports"><b>Open ports:</b> {_esc(ports)}</div>
          {findings_html}
          {harden_html}
        </div>""")

    scope_txt = ", ".join(_esc(c) for c in authorized) or "none declared"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>ViperScan Security Report — {_esc(meta.get('cidr',''))}</title>
<style>
  body{{font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;color:#1b2330;background:#f4f6fa;margin:0;padding:32px}}
  .wrap{{max-width:900px;margin:0 auto}}
  h1{{font-size:22px;margin:0 0 2px}} .sub{{color:#5b6675;font-size:13px;margin-bottom:20px}}
  .summary{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:22px}}
  .kpi{{background:#fff;border:1px solid #e3e8f0;border-radius:12px;padding:12px 16px;min-width:96px}}
  .kpi b{{display:block;font-size:22px}} .kpi span{{color:#5b6675;font-size:12px}}
  .dev{{background:#fff;border:1px solid #e3e8f0;border-radius:14px;padding:16px;margin-bottom:14px;break-inside:avoid}}
  .devhead{{display:flex;align-items:center;gap:14px}}
  .rs{{width:46px;height:46px;border:3px solid;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:17px}}
  .dh{{flex:1}} .dn{{font-weight:700;font-size:16px}} .dm{{color:#5b6675;font-size:12.5px;font-family:ui-monospace,monospace}}
  .rl{{font-weight:800;font-size:13px;letter-spacing:.5px}}
  .ports{{color:#5b6675;font-size:12.5px;margin:10px 0}}
  .f{{border-left:3px solid #e3e8f0;padding:8px 12px;margin:8px 0;background:#fafbfd;border-radius:0 8px 8px 0}}
  .sev{{color:#fff;font-size:10px;font-weight:800;text-transform:uppercase;padding:2px 7px;border-radius:5px;margin-right:6px}}
  .fd{{color:#3a4452;font-size:13px;margin-top:5px}} .fr{{color:#1f8a4c;font-size:12.5px;margin-top:5px}}
  .cves{{margin-top:6px;font-size:12.5px}} .cves a{{color:#2f6fb0;font-family:ui-monospace,monospace;font-weight:700;text-decoration:none}}
  .none{{color:#1f8a4c;font-size:13px}}
  .harden{{margin-top:10px;background:#f0faf4;border:1px solid #cfeeda;border-radius:8px;padding:10px 14px;font-size:12.5px}}
  .harden ul{{margin:6px 0 0;padding-left:18px}} .harden li{{margin:3px 0;color:#2c3a30}}
  footer{{color:#8a93a3;font-size:11.5px;text-align:center;margin-top:24px}}
  @media print{{body{{background:#fff;padding:0}} .dev,.kpi{{border-color:#ccc}}}}
</style></head><body><div class="wrap">
  <h1>ViperScan Network Security Report</h1>
  <div class="sub">Network <b>{_esc(meta.get('cidr','?'))}</b> · generated {_esc(meta.get('timestamp','')) }
    · {total} devices · authorised scope: {scope_txt} · ViperScan v{__version__}</div>
  <div class="summary">
    <div class="kpi"><b>{total}</b><span>devices</span></div>
    <div class="kpi" style="color:#c0344a"><b>{risk_counts.get('critical',0)}</b><span>critical risk</span></div>
    <div class="kpi" style="color:#b8860b"><b>{risk_counts.get('elevated',0)}</b><span>elevated</span></div>
    <div class="kpi" style="color:#c0344a"><b>{sev_counts.get('critical',0)+sev_counts.get('high',0)}</b><span>high+ findings</span></div>
  </div>
  {''.join(cards)}
  <footer>Generated by ViperScan · quiet (passive-leaning) audit · for authorised assessment only · data stays on the operator's machine</footer>
</div></body></html>"""
