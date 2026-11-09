#!/usr/bin/env python3
"""Offline, read-only SOC dashboard from the validated aggregate daily report.

No web server, network requests, external assets, raw logs, alert IDs or OAuth data.
Run as the interactive user, never as powerbeam-monitor or root.
"""
import argparse
from datetime import date, datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

MAX_INPUT = 65_536
RULES = ("SOC-001", "SOC-002", "other")
SEVERITIES = ("informational", "low", "medium", "high", "critical")
HEALTH_KEYS = ("detection", "alert_queue", "backlog", "oauth_local",
               "oauth_remote", "notification_delivery")

CSS = """
:root{color-scheme:dark;--bg:#0a101b;--card:#151f30;--edge:#29354a;
--text:#eaf0fb;--muted:#a4b5cd;--mint:#57dfba;--amber:#f6c26b;
--blue:#79abff;--red:#ff8192}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.5}
main{max-width:1180px;margin:auto;padding:34px 20px 72px}
header{display:flex;justify-content:space-between;align-items:flex-start;
gap:20px;flex-wrap:wrap;border-bottom:1px solid var(--edge);padding-bottom:24px}
.brand{letter-spacing:.13em;text-transform:uppercase;font-weight:750;
font-size:13px;color:var(--mint)}h1{margin:6px 0;font-size:clamp(27px,4vw,42px)}
.subtitle,.muted{color:var(--muted)}.meta{border:1px solid var(--edge);padding:10px 16px;
border-radius:12px;font-size:13px;color:var(--muted)}
h2{font-size:18px;margin:30px 0 14px}.grid{display:grid;grid-template-columns:
repeat(3,minmax(0,1fr));gap:16px}.grid.two{grid-template-columns:
repeat(2,minmax(0,1fr))}.card{background:linear-gradient(170deg,#18243a,var(--card));
border:1px solid var(--edge);border-radius:18px;padding:21px;min-width:0}
.kicker{text-transform:uppercase;letter-spacing:.1em;font-size:12px;color:var(--muted)}
.number{font-size:43px;font-weight:750;line-height:1.25;margin:9px 0 6px}
.note{font-size:12px;color:var(--muted);margin:0}.good{color:var(--mint)}
.warning{color:var(--amber)}.bad{color:var(--red)}.unknown{color:var(--muted)}
.status-row{display:flex;align-items:center;justify-content:space-between;gap:10px;
border-bottom:1px solid var(--edge);padding:12px 0}
.status-row:last-child{border-bottom:0}
.pill{display:inline-block;font-weight:750;font-size:11px;letter-spacing:.025em;
border:1px solid currentColor;padding:4px 9px;border-radius:999px;overflow-wrap:anywhere}
.track{height:11px;background:#293850;border-radius:20px;overflow:hidden;flex:1}
.fill{height:100%;border-radius:20px;background:linear-gradient(90deg,#447ded,#73e4bf)}
.bar-row{display:flex;gap:15px;align-items:center;margin:16px 0}
.bar-label{width:122px;font-size:13px;color:var(--muted)}
.bar-value{font-weight:750;width:40px;text-align:right}
.callout{margin-top:24px;padding:18px 20px;border-left:3px solid var(--blue);
background:#101b2a;border-radius:0 12px 12px 0;color:var(--muted);font-size:13px}
footer{margin-top:30px;color:var(--muted);font-size:12px}
@media(max-width:760px){.grid,.grid.two{grid-template-columns:1fr}
main{padding-top:22px}.bar-label{width:100px}}
"""


class DashboardError(ValueError):
    """Invalid or unsafe dashboard input/output."""


def _count(value):
    if type(value) is not int or not 0 <= value <= 1_000_000_000:
        raise DashboardError("INVALID_COUNTS")
    return value


def _counts(source, names):
    if not isinstance(source, dict) or set(source) != set(names):
        raise DashboardError("INVALID_COUNTS")
    return {name: _count(source[name]) for name in names}


def _status(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", value) is None:
        raise DashboardError("INVALID_STATUS")
    return value


def validate_report(report):
    """Select only approved aggregates. Never pass through arbitrary source data."""
    if not isinstance(report, dict) or report.get("component") != "powerbeam_soc_daily":
        raise DashboardError("INVALID_REPORT")
    if report.get("report_status") != "READY" or report.get("inspection") != "LOCAL_READ_ONLY":
        raise DashboardError("INVALID_REPORT")
    if report.get("timezone") != "Europe/Madrid":
        raise DashboardError("INVALID_TIMEZONE")
    if type(report.get("emails_sent")) is not int or report["emails_sent"] != 0:
        raise DashboardError("INVALID_REPORT")
    if report.get("tokens_modified") is not False:
        raise DashboardError("INVALID_REPORT")
    day = report.get("report_date")
    if not isinstance(day, str):
        raise DashboardError("INVALID_DATE")
    try:
        parsed = date.fromisoformat(day)
    except ValueError as exc:
        raise DashboardError("INVALID_DATE") from exc
    if parsed.isoformat() != day:
        raise DashboardError("INVALID_DATE")

    activity = report.get("activity")
    pending = report.get("pending_now")
    health = report.get("health")
    if not all(isinstance(item, dict) for item in (activity, pending, health)):
        raise DashboardError("INVALID_REPORT")

    total = _count(activity.get("alerts_event_date"))
    ack = _count(activity.get("acknowledged_on_date"))
    by_rule = _counts(activity.get("alerts_by_rule"), RULES)
    by_severity = _counts(activity.get("alerts_by_severity"), SEVERITIES)
    if sum(by_rule.values()) != total or sum(by_severity.values()) != total:
        raise DashboardError("INCONSISTENT_TOTALS")

    pending_total = _count(pending.get("total"))
    pending_severity = _counts(pending.get("by_severity"), SEVERITIES)
    if sum(pending_severity.values()) != pending_total:
        raise DashboardError("INCONSISTENT_PENDING")
    pending_status = _status(pending.get("status"))
    health_selected = {key: _status(health.get(key)) for key in HEALTH_KEYS}

    return {
        "date": day, "daily": total, "ack_on_date": ack,
        "rules": by_rule, "severities": by_severity,
        "pending": pending_total, "pending_severity": pending_severity,
        "pending_status": pending_status, "health": health_selected,
    }


def _tone(value):
    if value in ("HEALTHY", "READY_LOCAL", "ACCEPTED"):
        return "good"
    if value in ("CRITICAL", "ERROR", "FAILED"):
        return "bad"
    if value == "WARNING":
        return "warning"
    return "unknown"


def _bars(counts, names):
    largest = max(1, *(counts[name] for name in names))
    result = []
    for name in names:
        number = counts[name]
        width = round(number * 100 / largest, 2)
        result.append(
            '<div class="bar-row"><span class="bar-label">' + escape(name) +
            '</span><div class="track"><div class="fill" style="width:' +
            str(width) + '%"></div></div><span class="bar-value">' +
            str(number) + '</span></div>'
        )
    return "\n".join(result)


def _statuses(health):
    titles = {
        "detection": "Motor de detección",
        "alert_queue": "Cola de alertas",
        "backlog": "Antigüedad de pendientes",
        "oauth_local": "OAuth local",
        "oauth_remote": "OAuth remoto",
        "notification_delivery": "Notificaciones automáticas",
    }
    return "\n".join(
        '<div class="status-row"><span>' + escape(titles[key]) +
        '</span><span class="pill ' + _tone(health[key]) + '">' +
        escape(health[key]) + '</span></div>'
        for key in HEALTH_KEYS
    )


def render_dashboard(report, *, generated_at=None):
    """Render a self-contained HTML document using aggregates only."""
    data = validate_report(report)
    now = generated_at or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise DashboardError("INVALID_GENERATION_TIME")
    generated = escape(now.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    day = escape(data["date"])
    rules = _bars(data["rules"], RULES)
    severities = _bars(data["severities"], SEVERITIES)
    health = _statuses(data["health"])
    pending_status = escape(data["pending_status"])
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>PowerBeam Security Lab — SOC Dashboard</title>
<style>{CSS}</style>
</head>
<body>
<main>
<header>
<div><div class="brand">POWERBEAM SECURITY LAB / SOC</div>
<h1>Security Operations Dashboard</h1>
<p class="subtitle">Métricas agregadas · Solo lectura · Sin conexión de red</p></div>
<div class="meta">Informe de eventos: <strong>{day}</strong><br>
Generado: {generated}</div>
</header>
<h2>Actividad del {day} · hora del evento (V1)</h2>
<section class="grid" aria-label="Indicadores">
<div class="card"><div class="kicker">Alertas del día</div>
<div class="number">{data["daily"]}</div>
<p class="note">Contadas según la fecha del evento, no la detección.</p></div>
<div class="card"><div class="kicker">Alertas pendientes ahora</div>
<div class="number">{data["pending"]}</div>
<p class="note">Estado al generar el informe · {pending_status}.</p></div>
<div class="card"><div class="kicker">Acuses registrados el día</div>
<div class="number">{data["ack_on_date"]}</div>
<p class="note">Contados por fecha de reconocimiento; pueden corresponder a eventos anteriores.</p></div>
</section>
<h2>Desglose de alertas · fecha de evento</h2>
<section class="grid two">
<div class="card"><div class="kicker">Por regla de detección</div>{rules}</div>
<div class="card"><div class="kicker">Por severidad</div>{severities}</div>
</section>
<h2>Salud técnica y automatización</h2>
<section class="grid two">
<div class="card"><div class="kicker">Estado observado al generar el informe</div>
{health}</div>
<div class="card">
<div class="kicker">Interpretación y alcance</div>
<p>Las detecciones del día se calculan exclusivamente a partir de alertas <strong>V1</strong>.
El monitor V3 no se suma para evitar duplicados.</p>
<p>Los indicadores de cola y salud son <strong>instantáneas actuales</strong>,
no reconstrucciones históricas de {day}.</p>
<p class="muted">Los estados HEALTHY no garantizan ingestión continua de syslog.
READY_LOCAL no verifica Google; NOT_CHECKED y NOT_AUTOMATED no indican éxito de envío.</p>
</div>
</section>
<div class="callout"><strong>Fuente y confidencialidad:</strong>
informe agregado y validado del laboratorio. Esta página no contiene IP de origen,
identificadores de alertas, logs brutos ni tokens. Archivo HTML estático local,
sin JavaScript, recursos externos, servidor web ni actualización automática.
Actualiza la página regenerando el informe.</div>
<footer>PowerBeam Security Lab · Dashboard V1 de solo lectura · {generated}</footer>
</main>
</body>
</html>
"""


def save_private_html(output, content):
    """Atomic, 0600 file replacement inside a user-owned private 0700 directory."""
    path = Path(output).expanduser()
    if not path.name or path.name in (".", ".."):
        raise DashboardError("INVALID_OUTPUT")
    parent = path.parent
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd_dir = os.open(parent, flags)
    except OSError as exc:
        raise DashboardError("PRIVATE_DIRECTORY_REQUIRED") from exc
    try:
        info = os.fstat(fd_dir)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise DashboardError("PRIVATE_DIRECTORY_REQUIRED")
        tmp = None
        try:
            out_fd, tmp = tempfile.mkstemp(prefix=".powerbeam-", suffix=".tmp", dir=parent)
            with os.fdopen(out_fd, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            tmp = None
        finally:
            if tmp is not None:
                os.unlink(tmp)
    finally:
        os.close(fd_dir)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generar dashboard SOC offline desde JSON agregado")
    parser.add_argument("--output", required=True, type=Path,
                        help="HTML local en directorio privado propio (modo 0700)")
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.read(MAX_INPUT + 1)
        if len(raw.encode("utf-8")) > MAX_INPUT:
            raise DashboardError("INPUT_TOO_LARGE")
        report = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(DashboardError("INVALID_JSON")))
        html = render_dashboard(report)
        save_private_html(args.output, html)
    except (DashboardError, ValueError, TypeError, OSError, UnicodeError, json.JSONDecodeError):
        print("ERROR: DASHBOARD_INPUT_OR_OUTPUT_INVALID", file=sys.stderr)
        return 2
    print(json.dumps({"status": "CREATED", "inspection": "LOCAL_READ_ONLY",
                      "file": args.output.name, "state_modified": False,
                      "emails_sent": 0, "tokens_modified": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
