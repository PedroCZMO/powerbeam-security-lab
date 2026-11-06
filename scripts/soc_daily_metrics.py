#!/usr/bin/env python3
"""PowerBeam SOC daily *aggregates* from private V1 alerts and queue state.

Run as powerbeam-monitor. Local read-only, no outbound traffic, no output of
raw alerts, IPs, alert IDs, source filenames, or OAuth credentials.

Date is based on each alert's *event timestamp* in the selected timezone,
not its ingestion time; pending counts are a present-time snapshot across dates.
"""

import argparse
from collections import Counter
from datetime import date, datetime, timezone
import json
from pathlib import Path
import stat
import sys
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import alert_queue
import alert_backlog_health

SCHEMA = 1
SEVERITIES = ("informational", "low", "medium", "high", "critical")
RULES = ("SOC-001", "SOC-002", "other")
DEFAULT_TZ = "Europe/Madrid"


def parse_date(value):
    if not isinstance(value, str):
        raise ValueError("INVALID_REPORT_DATE")
    try:
        result = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("INVALID_REPORT_DATE") from exc
    if result.isoformat() != value:
        raise ValueError("INVALID_REPORT_DATE")
    return result


def read_regular(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("SYMLINK_NOT_ALLOWED")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("NOT_REGULAR_FILE")
    return path


def aggregate(alerts, state, *, report_date, tz, now=None):
    """Pure function: user-facing counts only; never exposes source records."""
    report_date = parse_date(report_date) if isinstance(report_date, str) else report_date
    if type(report_date) is not date:
        raise ValueError("INVALID_REPORT_DATE")
    if not isinstance(tz, ZoneInfo):
        raise ValueError("INVALID_TIMEZONE")
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("INVALID_NOW")
    alert_queue.validate_state(state)
    backlog = alert_backlog_health.evaluate(state, now=now)
    severity = Counter()
    rules = Counter()
    unique = {}
    for alert in alerts:
        norm = alert_queue.normalize_alert(alert, "daily")
        aid = norm["alert_id"]
        if aid in unique:
            if unique[aid] != norm:
                raise ValueError("CONFLICTING_ALERT_ID")
            continue
        unique[aid] = norm
        event_dt = datetime.fromisoformat(norm["timestamp"])
        if event_dt.astimezone(tz).date() != report_date:
            continue
        severity[norm["severity"]] += 1
        rules[norm["rule_id"] if norm["rule_id"] in RULES[:2] else "other"] += 1
    acknowledged_today = 0
    for ack in state.get("acknowledged", []):
        ack_dt = datetime.fromisoformat(ack["acknowledged_at"])
        if ack_dt.astimezone(tz).date() == report_date:
            acknowledged_today += 1
    by_severity = {s: severity[s] for s in SEVERITIES}
    by_rule = {r: rules[r] for r in RULES}
    total = sum(by_severity.values())
    return {
        "component": "powerbeam_soc_daily_metrics",
        "schema_version": SCHEMA,
        "inspection": "LOCAL_READ_ONLY",
        "report_date": report_date.isoformat(),
        "timezone": tz.key,
        "generated_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_scope": "V1_ONLY",
        "alert_count_basis": "EVENT_TIMESTAMP",
        "ack_count_basis": "ACKNOWLEDGED_AT",
        "alerts_on_date": total,
        "alerts_by_severity": by_severity,
        "alerts_by_rule": by_rule,
        "acknowledged_on_date": acknowledged_today,
        "backlog": backlog,
        "state_modified": False,
        "emails_sent": 0,
    }


def inspect(alerts_path, state_path, *, report_date=None, timezone_name=DEFAULT_TZ, now=None):
    try:
        tz = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
        raise ValueError("INVALID_TIMEZONE") from exc
    now = datetime.now(timezone.utc) if now is None else now
    chosen_date = parse_date(report_date) if report_date else now.astimezone(tz).date()
    # The canonical V1 JSONL may have an unfinished tail: alert_queue.read_alerts
    # postpones it until the producer finishes its newline-delimited record.
    alerts = alert_queue.read_alerts(read_regular(alerts_path))
    state = alert_queue.read_state(read_regular(state_path))
    return aggregate(alerts, state, report_date=chosen_date, tz=tz, now=now)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Métricas diarias privadas de alertas V1, solo lectura")
    parser.add_argument("--alerts", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--date", help="YYYY-MM-DD; por defecto, hoy en --tz")
    parser.add_argument("--tz", default=DEFAULT_TZ)
    args = parser.parse_args(argv)
    try:
        result = inspect(args.alerts, args.state, report_date=args.date,
                         timezone_name=args.tz)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        # Fail closed, without echoing paths, IPs, IDs or potentially sensitive JSON.
        print(json.dumps({"component": "powerbeam_soc_daily_metrics",
                          "status": "UNKNOWN", "reason": "METRICS_UNREADABLE_OR_INVALID",
                          "state_modified": False, "emails_sent": 0}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
