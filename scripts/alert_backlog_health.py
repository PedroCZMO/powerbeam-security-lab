#!/usr/bin/env python3
"""PowerBeam Day 12, phase 4: read-only SOC alert backlog health.

Reads the persisted V1 alert queue (not alert sources), counts pending alerts,
reports event-time age and backlog policy. Never acknowledges, writes, or sends.
The event timestamp is NOT the time when an alert entered the queue.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import stat
import sys

import alert_queue

SEVERITIES = ("informational", "low", "medium", "high", "critical")
REASONS = {
    "NONE": "NO_PENDING_ALERTS",
    "RECENT": "PENDING_WITHIN_POLICY",
    "HIGH": "HIGH_PENDING_TOO_OLD",
    "OLD": "PENDING_EVENT_TOO_OLD",
    "CRITICAL": "CRITICAL_SEVERITY_PENDING",
    "EXCEEDED": "MAX_EVENT_AGE_EXCEEDED",
    "FUTURE": "FUTURE_EVENT_TIMESTAMP",
}


def _minutes(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not (0 < value < 1000000):
        raise ValueError(f"Umbral {label} inválido")
    return value


def evaluate(state, *, now=None, high_warning_min=30, any_warning_min=60,
             any_critical_min=240):
    """Validate queue schema and calculate safe aggregate metrics; never mutate state."""
    alert_queue.validate_state(state)
    high_warning_min = _minutes(high_warning_min, "high-warning")
    any_warning_min = _minutes(any_warning_min, "any-warning")
    any_critical_min = _minutes(any_critical_min, "any-critical")
    if any_critical_min <= any_warning_min or any_critical_min <= high_warning_min:
        raise ValueError("Umbral crítico debe superar a los umbrales de aviso")
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Hora de referencia sin zona horaria")
    now = now.astimezone(timezone.utc)
    pending = state["pending"]
    counts = {severity: 0 for severity in SEVERITIES}
    ages = []
    future_count = 0
    for item in pending:
        counts[item["severity"]] += 1
        instant = datetime.fromisoformat(item["timestamp"]).astimezone(timezone.utc)
        age_sec = (now - instant).total_seconds()
        if age_sec < -60:
            future_count += 1
        ages.append((age_sec, instant))
    worst = max(ages, key=lambda item: item[0]) if ages else None
    # Clamp small clock skews to 0 for reporting; larger future skew is flagged.
    age_min = round(max(0.0, worst[0]) / 60, 2) if worst else None
    oldest_at = (worst[1].isoformat().replace("+00:00", "Z") if worst else None)
    status = "HEALTHY"
    reason = REASONS["NONE"] if not pending else REASONS["RECENT"]
    if future_count:
        status, reason = "WARNING", REASONS["FUTURE"]
    if any(age >= any_warning_min * 60 for age, _ in ages):
        status, reason = "WARNING", REASONS["OLD"]
    if any(item["severity"] == "high" and
           (now - datetime.fromisoformat(item["timestamp"]).astimezone(timezone.utc)).total_seconds()
           >= high_warning_min * 60 for item in pending):
        status, reason = "WARNING", REASONS["HIGH"]
    if any(age >= any_critical_min * 60 for age, _ in ages):
        status, reason = "CRITICAL", REASONS["EXCEEDED"]
    if counts["critical"]:
        status, reason = "CRITICAL", REASONS["CRITICAL"]
    return {
        "component": "powerbeam_alert_backlog",
        "inspection": "LOCAL_READ_ONLY",
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "operational_status": status,
        "status_reason": reason,
        "pending_total": len(pending),
        "seen_total": len(state["seen_alert_ids"]),
        "acknowledged_total": len(state.get("acknowledged", [])),
        "pending_by_severity": counts,
        "oldest_event_timestamp": oldest_at,
        "oldest_event_age_minutes": age_min,
        "future_event_timestamp_count": future_count,
        "policy_minutes": {
            "high_warning": high_warning_min,
            "any_warning": any_warning_min,
            "any_critical": any_critical_min,
        },
        "age_basis": "EVENT_TIMESTAMP_NOT_QUEUE_ENTRY",
        "state_modified": False,
        "alerts_acknowledged": 0,
        "emails_sent": 0,
        "note": "Edad desde evento, no tiempo de espera en cola; solo alertas V1." ,
    }


def inspect(path, *, now=None, high_warning_min=30, any_warning_min=60,
            any_critical_min=240):
    """Read one atomic queue snapshot; do not create lock files or directories."""
    path = Path(path)
    # The queue is atomically replaced by its writer. Never follow a final symlink.
    if path.is_symlink():
        raise ValueError("STATE_SYMLINK_NOT_ALLOWED")
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError("STATE_NOT_REGULAR_FILE")
    state = alert_queue.read_state(path)
    return evaluate(state, now=now, high_warning_min=high_warning_min,
                    any_warning_min=any_warning_min, any_critical_min=any_critical_min)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="PowerBeam: antigüedad por hora del evento y severidad de alertas pendientes (sin escritura)")
    parser.add_argument("--state", type=Path, required=True,
                        help="Ruta al state.json de la cola de alertas")
    parser.add_argument("--high-warning-min", type=int, default=30)
    parser.add_argument("--any-warning-min", type=int, default=60)
    parser.add_argument("--any-critical-min", type=int, default=240)
    args = parser.parse_args(argv)
    try:
        result = inspect(args.state, high_warning_min=args.high_warning_min,
                         any_warning_min=args.any_warning_min,
                         any_critical_min=args.any_critical_min)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        # Do not echo OS exception text, file contents, raw alert IDs or secret paths.
        print(json.dumps({"component": "powerbeam_alert_backlog",
                          "operational_status": "UNKNOWN", "status_reason": "STATE_UNREADABLE_OR_INVALID",
                          "state_modified": False, "emails_sent": 0}, indent=2))
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return {"HEALTHY": 0, "WARNING": 1, "CRITICAL": 2}[result["operational_status"]]


if __name__ == "__main__":
    sys.exit(main())
