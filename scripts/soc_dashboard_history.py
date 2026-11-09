#!/usr/bin/env python3
"""Local offline index for private static PowerBeam SOC Dashboard reports."""
import argparse
from datetime import date, datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import re
import stat
import sys

from soc_dashboard import DashboardError, save_private_html

MAX_REPORT_BYTES = 131_072
FILENAME = re.compile(r"(?:index|\d{4}-\d{2}-\d{2})\.html\Z")
REPORT_DATE = re.compile(
    r'Informe de eventos:\s*<strong>(\d{4}-\d{2}-\d{2})</strong>'
)
MARKERS = (
    '<title>PowerBeam Security Lab — SOC Dashboard</title>',
    '<meta http-equiv="Content-Security-Policy"',
)


def _date(value):
    try:
        result = date.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise DashboardError("INVALID_REPORT_DATE") from exc
    if result.isoformat() != value:
        raise DashboardError("INVALID_REPORT_DATE")
    return value


METRIC_LABELS = {
    "alerts": "Alertas del día",
    "pending": "Alertas pendientes ahora",
    "ack": "Acuses registrados el día",
}
BAR_LABELS = ("SOC-001", "SOC-002", "other", "informational",
              "low", "medium", "high", "critical")
HEALTH_LABELS = (
    "Motor de detección", "Cola de alertas", "Antigüedad de pendientes",
    "OAuth local", "OAuth remoto", "Notificaciones automáticas",
)


def _count(raw):
    if not isinstance(raw, str) or re.fullmatch(r"(?:0|[1-9][0-9]{0,8})", raw) is None:
        raise DashboardError("INVALID_REPORT_METRIC")
    return int(raw)


def _extract_summary(html):
    """Allowlist-only extraction of aggregate values from the existing dashboard.

    Never copy HTML, arbitrary strings, IPs, alert IDs or source data into the index.
    The index remains a single, self-contained file even when opened via a
    desktop document portal that grants access only to historico.html.
    """
    result = {}
    for key, label in METRIC_LABELS.items():
        pattern = (r'<div class="kicker">' + re.escape(label) +
                   r'</div>\s*<div class="number">([0-9]+)</div>')
        values = re.findall(pattern, html)
        if len(values) != 1:
            raise DashboardError("INVALID_REPORT_METRIC")
        result[key] = _count(values[0])

    bar_matches = re.findall(
        r'<span class="bar-label">([^<]+)</span>\s*'
        r'<div class="track">.*?</div></div>\s*'
        r'<span class="bar-value">([0-9]+)</span>', html, re.S)
    bars = {}
    for label, value in bar_matches:
        if label not in BAR_LABELS or label in bars:
            raise DashboardError("INVALID_REPORT_BARS")
        bars[label] = _count(value)
    if set(bars) != set(BAR_LABELS):
        raise DashboardError("INVALID_REPORT_BARS")
    if (sum(bars[k] for k in BAR_LABELS[:3]) != result["alerts"]
            or sum(bars[k] for k in BAR_LABELS[3:]) != result["alerts"]):
        raise DashboardError("INCONSISTENT_REPORT_METRICS")

    status_matches = re.findall(
        r'<div class="status-row"><span>([^<]+)</span>\s*'
        r'<span class="pill (?:good|warning|bad|unknown)">'
        r'([A-Z][A-Z0-9_]{0,47})</span></div>', html)
    statuses = {}
    for label, value in status_matches:
        if label not in HEALTH_LABELS or label in statuses:
            raise DashboardError("INVALID_REPORT_HEALTH")
        statuses[label] = value
    if set(statuses) != set(HEALTH_LABELS):
        raise DashboardError("INVALID_REPORT_HEALTH")
    return {"alerts": result["alerts"], "pending": result["pending"],
            "ack": result["ack"], "rules": {k: bars[k] for k in BAR_LABELS[:3]},
            "severity": {k: bars[k] for k in BAR_LABELS[3:]},
            "health": statuses}


def _read_report(dir_fd, filename):
    """Read only own, private, regular HTML from the trusted report directory."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(filename, flags, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size < 1 or info.st_size > MAX_REPORT_BYTES):
            raise DashboardError("UNSAFE_REPORT_FILE")
        content = os.read(fd, MAX_REPORT_BYTES + 1)
        if len(content) > MAX_REPORT_BYTES:
            raise DashboardError("UNSAFE_REPORT_FILE")
        html = content.decode("utf-8")
    finally:
        os.close(fd)
    if not all(marker in html for marker in MARKERS):
        raise DashboardError("INVALID_REPORT_HTML")
    match = REPORT_DATE.search(html)
    if match is None:
        raise DashboardError("INVALID_REPORT_HTML")
    event_date = _date(match.group(1))
    if filename != "index.html" and filename != event_date + ".html":
        raise DashboardError("DATE_FILENAME_MISMATCH")
    return event_date, _extract_summary(html)


def discover_reports(directory):
    """Discover private reports without following directories or file symlinks."""
    base = Path(directory).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(base, flags)
    try:
        folder = os.fstat(fd)
        if (not stat.S_ISDIR(folder.st_mode) or folder.st_uid != os.getuid()
                or stat.S_IMODE(folder.st_mode) != 0o700):
            raise DashboardError("PRIVATE_DIRECTORY_REQUIRED")
        found = {}
        names = sorted(name for name in os.listdir(fd) if FILENAME.fullmatch(name))
        for filename in names:
            event_date, summary = _read_report(fd, filename)
            # Keep one result per event date; prefer the explicit dated filename.
            if event_date not in found or filename != "index.html":
                found[event_date] = (filename, summary)
    finally:
        os.close(fd)
    if not found:
        raise DashboardError("NO_REPORTS_FOUND")
    return [(day, filename, summary)
            for day, (filename, summary) in sorted(found.items(), reverse=True)]


def _metric(label, count, *, caption=""):
    return ('<div class="metric"><span class="metric-label">' + escape(label) +
            '</span><strong>' + str(count) + '</strong>' +
            ('<small>' + escape(caption) + '</small>' if caption else '') +
            '</div>')


def _status_tone(value):
    """Present observed health without treating unknown/unverified as healthy."""
    if value == "HEALTHY":
        return "healthy"
    if value == "READY_LOCAL":
        return "ready-local"
    if value in ("WARNING", "DEGRADED"):
        return "warning"
    if value in ("CRITICAL", "FAILED", "ERROR", "UNHEALTHY"):
        return "critical"
    # UNKNOWN / NOT_CHECKED / NOT_AUTOMATED and any future code are neutral.
    return "unverified"


def _card(day, summary):
    """Render only allowlisted metrics, never embed a source HTML document."""
    if not isinstance(summary, dict) or set(summary) != {
            "alerts", "pending", "ack", "rules", "severity", "health"}:
        raise DashboardError("INVALID_SUMMARY")
    for label in ("alerts", "pending", "ack"):
        if type(summary[label]) is not int or not 0 <= summary[label] <= 999_999_999:
            raise DashboardError("INVALID_SUMMARY")
    for key, allowed in (("rules", BAR_LABELS[:3]),
                         ("severity", BAR_LABELS[3:]),
                         ("health", HEALTH_LABELS)):
        if not isinstance(summary[key], dict) or set(summary[key]) != set(allowed):
            raise DashboardError("INVALID_SUMMARY")
    for section in ("rules", "severity"):
        for value in summary[section].values():
            if type(value) is not int or not 0 <= value <= 999_999_999:
                raise DashboardError("INVALID_SUMMARY")
    if (sum(summary["rules"].values()) != summary["alerts"]
            or sum(summary["severity"].values()) != summary["alerts"]):
        raise DashboardError("INVALID_SUMMARY")
    for value in summary["health"].values():
        if not isinstance(value, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", value) is None:
            raise DashboardError("INVALID_SUMMARY")

    by_rule = "".join(
        '<div class="row"><span>' + escape(k) + '</span><strong>' +
        str(summary["rules"][k]) + '</strong></div>'
        for k in BAR_LABELS[:3]
    )
    by_severity = "".join(
        '<div class="row"><span>' + escape(k) + '</span><strong>' +
        str(summary["severity"][k]) + '</strong></div>'
        for k in BAR_LABELS[3:]
    )
    by_health = "".join(
        '<div class="row"><span>' + escape(k) + '</span><strong class="state ' +
        _status_tone(summary["health"][k]) + '">' +
        escape(summary["health"][k]) + '</strong></div>'
        for k in HEALTH_LABELS
    )
    return (
        '<details class="card"><summary><span class="eyebrow">'
        'INFORME DEL DÍA</span><strong class="day">' + escape(day) +
        '</strong><span class="detail">Ver métricas agregadas ▾</span></summary>'
        '<div class="detail-panel">'
        '<div class="metrics">' +
        _metric("Alertas del día", summary["alerts"], caption="Fecha del evento (V1)") +
        _metric("Pendientes al generar", summary["pending"], caption="Instantánea de la cola") +
        _metric("Acuses del día", summary["ack"], caption="Fecha del reconocimiento") +
        '</div><div class="breakdown"><section><h3>Por regla</h3>' + by_rule +
        '</section><section><h3>Por severidad</h3>' + by_severity +
        '</section></div><section><h3>Salud al generar este informe</h3>' +
        by_health + '</section></div></details>'
    )


def render_index(reports, *, generated_at=None):
    """Render a one-file history viewer; no links to inaccessible sibling files."""
    if not isinstance(reports, list) or not reports:
        raise DashboardError("NO_REPORTS_FOUND")
    seen = set()
    cards = []
    for value in reports:
        if not isinstance(value, tuple) or len(value) != 3:
            raise DashboardError("INVALID_ENTRY")
        day, filename, summary = value
        _date(day)
        if (not isinstance(filename, str) or FILENAME.fullmatch(filename) is None
                or (filename != "index.html" and filename != day + ".html")
                or day in seen):
            raise DashboardError("INVALID_ENTRY")
        seen.add(day)
        cards.append(_card(day, summary))
    now = generated_at or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise DashboardError("INVALID_GENERATION_TIME")
    stamp = escape(now.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    tiles = "\n".join(cards)
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>PowerBeam Security Lab — Histórico SOC</title>
<style>
:root{{color-scheme:dark;--bg:#0a101b;--card:#17243a;--border:#2b3d58;--ink:#eaf0fb;--muted:#a4b5cd;--accent:#56dbba}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1080px;margin:0 auto;padding:44px 22px 70px}}
.eyebrow{{display:block;color:var(--accent);font-size:12px;font-weight:750;letter-spacing:.12em}}
h1{{font-size:clamp(28px,4vw,44px);margin:8px 0 12px}}p{{line-height:1.65;color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:16px;margin-top:30px;align-items:start}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:22px;color:var(--ink)}}
.card[open]{{grid-column:1/-1;border-color:var(--accent)}}
.card summary{{cursor:pointer;list-style:none;display:flex;flex-direction:column;gap:14px}}
.card summary::-webkit-details-marker{{display:none}}
.card summary:focus-visible{{outline:2px solid var(--accent);outline-offset:7px}}
.card summary:hover .day{{color:var(--accent)}}
.day{{font-size:30px;letter-spacing:.03em}}.detail{{font-size:14px;color:var(--muted)}}
.detail-panel{{border-top:1px solid var(--border);margin-top:22px;padding-top:20px}}
.metrics{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}}
.metric{{background:#101b2b;border:1px solid var(--border);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:6px}}
.metric-label{{color:var(--muted);font-size:12px}}.metric strong{{font-size:30px}}
.metric small{{font-size:12px;color:var(--muted)}}
.breakdown{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
h3{{font-size:16px;margin:25px 0 10px}}.row{{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:7px 0;border-bottom:1px solid var(--border)}}
.row span{{color:var(--muted)}}
.state{{color:var(--muted);font-size:12px;overflow-wrap:anywhere}}
.state.healthy{{color:#57dfba}}
.state.ready-local{{color:#79abff}}
.state.warning{{color:#f6c26b}}
.state.critical{{color:#ff8192}}
.state.unverified{{color:var(--muted)}}
.callout{{border-left:3px solid var(--accent);margin-top:32px;padding:15px 22px;background:#111c2b;border-radius:0 10px 10px 0}}
small{{color:var(--muted)}}@media(max-width:750px){{.metrics,.breakdown{{grid-template-columns:1fr}}}}
</style>
</head>
<body><main>
<div class="eyebrow">POWERBEAM SECURITY LAB / SOC</div>
<h1>Histórico de informes SOC</h1>
<p>Selecciona una fecha para desplegar las métricas agregadas directamente aquí.
Vista independiente de otros archivos: funciona también a través del portal
de documentos de Firefox, sin servidor, JavaScript ni conexión de red.</p>
<section class="grid" aria-label="Informes disponibles">
{tiles}
</section>
<div class="callout"><strong>Interpretación:</strong>
las detecciones se cuentan por la fecha del evento, pero pendientes y salud son
instantáneas de cuando se generó cada informe. No se reconstruye el estado
histórico de los servicios.</div>
<p><small>Histórico generado: {stamp}. Para incluir nuevos informes, regenera este índice.
Solo contiene contadores y estados permitidos: sin logs brutos, credenciales,
IP ni identificadores de alertas.</small></p>
</main></body></html>
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description="Índice HTML privado de informes SOC existentes")
    parser.add_argument("--dir", required=True, type=Path,
                        help="Directorio privado que contiene index.html y/o YYYY-MM-DD.html")
    args = parser.parse_args(argv)
    try:
        reports = discover_reports(args.dir)
        html = render_index(reports)
        save_private_html(args.dir / "historico.html", html)
    except (DashboardError, ValueError, TypeError, OSError, UnicodeError):
        print("ERROR: HISTORY_UNAVAILABLE_OR_UNSAFE", file=sys.stderr)
        return 2
    print(json.dumps({"status": "CREATED", "file": "historico.html",
                      "reports": len(reports), "inspection": "LOCAL_READ_ONLY",
                      "state_modified": False, "emails_sent": 0,
                      "tokens_modified": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
