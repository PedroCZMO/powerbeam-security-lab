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
    return event_date


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
            event_date = _read_report(fd, filename)
            # Keep one link per event date; prefer the explicit dated filename.
            if event_date not in found or filename != "index.html":
                found[event_date] = filename
    finally:
        os.close(fd)
    if not found:
        raise DashboardError("NO_REPORTS_FOUND")
    return sorted(found.items(), reverse=True)


def render_index(reports, *, generated_at=None):
    """Render static links; no raw logs, alert IDs, IPs or external resources."""
    if not isinstance(reports, list) or not reports:
        raise DashboardError("NO_REPORTS_FOUND")
    seen = set()
    cards = []
    for value in reports:
        if not isinstance(value, tuple) or len(value) != 2:
            raise DashboardError("INVALID_ENTRY")
        day, filename = value
        _date(day)
        if (not isinstance(filename, str) or FILENAME.fullmatch(filename) is None
                or (filename != "index.html" and filename != day + ".html")
                or day in seen):
            raise DashboardError("INVALID_ENTRY")
        seen.add(day)
        cards.append('<a class="card" href="' + escape(filename, quote=True) +
                     '"><span class="eyebrow">INFORME DEL DÍA</span>' +
                     '<strong>' + escape(day) + '</strong>' +
                     '<span class="detail">Abrir métricas agregadas →</span></a>')
    now = generated_at or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise DashboardError("INVALID_GENERATION_TIME")
    stamp = escape(now.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    links = "\n".join(cards)
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
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:16px;margin-top:30px}}
.card{{display:flex;flex-direction:column;gap:15px;background:var(--card);border:1px solid var(--border);
border-radius:16px;padding:22px;color:var(--ink);text-decoration:none}}
.card:hover,.card:focus{{border-color:var(--accent);outline-offset:4px}}
.card strong{{font-size:30px;letter-spacing:.03em}}.detail{{font-size:14px;color:var(--muted)}}
.callout{{border-left:3px solid var(--accent);margin-top:32px;padding:15px 22px;background:#111c2b;border-radius:0 10px 10px 0}}
small{{color:var(--muted)}}
</style>
</head>
<body><main>
<div class="eyebrow">POWERBEAM SECURITY LAB / SOC</div>
<h1>Histórico de informes SOC</h1>
<p>Accede a los informes locales generados a partir de métricas agregadas V1.
Navegación sin servidor, sin JavaScript y sin conexión a Internet.</p>
<section class="grid" aria-label="Informes disponibles">
{links}
</section>
<div class="callout"><strong>Interpretación:</strong>
cada página muestra actividad por fecha del evento, pero sus indicadores
de pendientes y salud describen el momento en que se generó esa página.
No son reconstrucciones históricas del estado de los servicios.</div>
<p><small>Índice generado: {stamp}. Para incluir nuevos informes, regenera este índice.
No contiene logs brutos, credenciales, IPs ni identificadores de alertas.</small></p>
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
