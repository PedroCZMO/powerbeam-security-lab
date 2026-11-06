#!/usr/bin/env python3
"""Human/JSON daily SOC report from *only aggregate* metrics via stdin.

Run as the regular desktop user to read private local OAuth configuration and
systemd metadata. Raw alerts/queue and secret tokens are NEVER passed to stdin.
No email sending, token renewal, or file modification.
"""

import argparse
from datetime import date, datetime
import json
import sys
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import resilience_report
import oauth_health

MAX_STDIN_BYTES = 64 * 1024
SEVERITIES = ("informational", "low", "medium", "high", "critical")
RULES = ("SOC-001", "SOC-002", "other")
MAX_COUNT = 100_000_000


def _count(value):
    return type(value) is int and 0 <= value <= MAX_COUNT


def clean_daily_metrics(raw):
    """Strictly validate and strip the untrusted JSON at privilege boundary."""
    if not isinstance(raw, dict):
        return None
    if (raw.get("component") != "powerbeam_soc_daily_metrics"
            or raw.get("schema_version") != 1
            or raw.get("inspection") != "LOCAL_READ_ONLY"
            or raw.get("source_scope") != "V1_ONLY"
            or raw.get("alert_count_basis") != "EVENT_TIMESTAMP"
            or raw.get("ack_count_basis") != "ACKNOWLEDGED_AT"
            or raw.get("state_modified") is not False
            or type(raw.get("emails_sent")) is not int
            or raw["emails_sent"] != 0):
        return None
    day = raw.get("report_date")
    tz = raw.get("timezone")
    if not isinstance(day, str) or not isinstance(tz, str) or len(tz) > 80:
        return None
    try:
        if date.fromisoformat(day).isoformat() != day:
            return None
        ZoneInfo(tz)
        dt = datetime.fromisoformat(raw["generated_at"].replace("Z", "+00:00"))
        if dt.tzinfo is None or dt.utcoffset() is None:
            return None
    except (ValueError, TypeError, KeyError, ZoneInfoNotFoundError):
        return None
    counts = raw.get("alerts_by_severity")
    rules = raw.get("alerts_by_rule")
    if not isinstance(counts, dict) or set(counts) != set(SEVERITIES):
        return None
    if not isinstance(rules, dict) or set(rules) != set(RULES):
        return None
    if not all(_count(counts[k]) for k in SEVERITIES):
        return None
    if not all(_count(rules[k]) for k in RULES):
        return None
    total = raw.get("alerts_on_date")
    ack_today = raw.get("acknowledged_on_date")
    if not _count(total) or not _count(ack_today):
        return None
    if sum(counts.values()) != total or sum(rules.values()) != total:
        return None
    backlog = resilience_report.clean_backlog(raw.get("backlog"))
    if backlog is None or ack_today > backlog["acknowledged_total"]:
        return None
    return {
        "report_date": day, "timezone": tz,
        "alerts_on_date": total,
        "alerts_by_severity": {k: counts[k] for k in SEVERITIES},
        "alerts_by_rule": {k: rules[k] for k in RULES},
        "acknowledged_on_date": ack_today,
        "backlog": backlog,
    }


def read_daily_stdin(stream):
    try:
        text = stream.read(MAX_STDIN_BYTES + 1)
        if len(text) > MAX_STDIN_BYTES:
            return None
        return clean_daily_metrics(json.loads(text))
    except (ValueError, TypeError, OSError, UnicodeError):
        return None


def build_report(metrics, *, token=oauth_health.DEFAULT_TOKEN, resilience_reader=None):
    """Merge metrics and current systemd/OAuth state, without mixing identities."""
    if metrics is None:
        return {"component": "powerbeam_soc_daily", "report_status": "UNKNOWN",
                "reason": "INVALID_DAILY_METRICS", "emails_sent": 0,
                "tokens_modified": False}
    if resilience_reader is None:
        infrastructure = resilience_report.collect(
            token, backlog_requested=False)
    else:
        infrastructure = resilience_reader(token)
    health = {
        "detection": infrastructure.get("detection_status", "UNKNOWN"),
        "alert_queue": infrastructure.get("alert_queue_status", "UNKNOWN"),
        "backlog": metrics["backlog"]["operational_status"],
        "oauth_local": infrastructure.get("oauth_local", "UNKNOWN"),
        "oauth_remote": "NOT_CHECKED",
        "notification_delivery": "NOT_AUTOMATED",
    }
    # Technical health and operational queue age are distinct channels.
    return {
        "component": "powerbeam_soc_daily",
        "report_status": "READY",
        "inspection": "LOCAL_READ_ONLY",
        "report_date": metrics["report_date"],
        "timezone": metrics["timezone"],
        "activity": {
            "alerts_event_date": metrics["alerts_on_date"],
            "alerts_by_rule": metrics["alerts_by_rule"],
            "alerts_by_severity": metrics["alerts_by_severity"],
            "acknowledged_on_date": metrics["acknowledged_on_date"],
        },
        "pending_now": {
            "total": metrics["backlog"]["pending_total"],
            "by_severity": metrics["backlog"]["pending_by_severity"],
            "oldest_event_age_minutes": metrics["backlog"]["oldest_event_age_minutes"],
            "status": metrics["backlog"]["operational_status"],
        },
        "health": health,
        "emails_sent": 0,
        "tokens_modified": False,
        "notes": [
            "Actividad diaria por hora del evento de alertas V1 (no por entrada en cola).",
            "Pendientes actuales de cualquier fecha; acuses del día por acknowledged_at.",
            "Estado systemd es una instantánea; no certifica ingestión ni entrega de correo.",
        ],
    }


def as_text(report):
    if report.get("report_status") != "READY":
        return "POWERBEAM SOC DAILY REPORT\nESTADO: UNKNOWN (métricas inválidas o no disponibles)"
    activity = report["activity"]
    pending = report["pending_now"]
    health = report["health"]
    sev = pending["by_severity"]
    return "\n".join((
        "=" * 48,
        "POWERBEAM SECURITY LAB — DAILY SOC REPORT",
        "=" * 48,
        f"Fecha: {report['report_date']} ({report['timezone']})",
        "",
        "SALUD DE SERVICIOS (INSTANTÁNEA)",
        f"Detección SOC:               {health['detection']}",
        f"Cola de alertas:             {health['alert_queue']}",
        f"OAuth local:                 {health['oauth_local']}",
        f"OAuth remoto:                {health['oauth_remote']}",
        f"Correo automático:           {health['notification_delivery']}",
        "",
        "ACTIVIDAD DEL DÍA (POR FECHA DEL EVENTO, SOLO V1)",
        f"Alertas fechadas ese día:    {activity['alerts_event_date']}",
        f"SOC-001:                     {activity['alerts_by_rule']['SOC-001']}",
        f"SOC-002:                     {activity['alerts_by_rule']['SOC-002']}",
        f"Otras reglas:                {activity['alerts_by_rule']['other']}",
        f"Acuses registrados ese día:  {activity['acknowledged_on_date']}",
        "",
        "ALERTAS PENDIENTES AHORA (TODAS LAS FECHAS)",
        f"Pendientes:                  {pending['total']}",
        f"Pendientes HIGH:             {sev['high']}",
        f"Pendientes CRITICAL:         {sev['critical']}",
        f"Estado de revisión:         {pending['status']}",
        f"Edad del evento más antiguo: {pending['oldest_event_age_minutes'] if pending['oldest_event_age_minutes'] is not None else 'N/A'} min",
        "=" * 48,
        "Solo lectura | Sin envíos de correo | Sin modificar tokens",
    ))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Informe diario SOC a partir de métricas agregadas por stdin")
    parser.add_argument("--daily-stdin", action="store_true", required=True)
    parser.add_argument("--token", type=Path, default=oauth_health.DEFAULT_TOKEN)
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)
    metrics = read_daily_stdin(sys.stdin)
    try:
        report = build_report(metrics, token=args.token)
    except Exception:
        report = build_report(None)
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(as_text(report))
    if report["report_status"] != "READY":
        return 2
    if "CRITICAL" in (report["health"]["detection"], report["health"]["alert_queue"],
                      report["health"]["backlog"]):
        return 2
    if any(report["health"][name] in ("WARNING", "UNKNOWN")
           for name in ("detection", "alert_queue", "backlog")):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
