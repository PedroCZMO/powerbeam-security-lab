#!/usr/bin/env python3
"""PowerBeam resilience overview: local systemd, OAuth and SOC backlog health.

Run as the Ubuntu user who owns the private OAuth token. To integrate the
private alert queue, pipe the read-only *aggregate* output of alert_backlog_health
(run separately as powerbeam-monitor) into --backlog-stdin. This process never
reads private alert state, reads raw events, writes credentials, or sends mail.
Optional online OAuth check uses refresh credentials in memory only.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

import oauth_health

# Fixed list: no user-provided service names or shell interpolation.
UNITS = {
    "soc_v1_timer": ("powerbeam-monitor.timer", "timer", None),
    "soc_v3_timer": ("powerbeam-monitor-v3.timer", "timer", None),
    "health_timer": ("powerbeam-health.timer", "timer", None),
    "soc_v1_last_run": ("powerbeam-monitor.service", "oneshot", 15 * 60),
    "soc_v3_last_run": ("powerbeam-monitor-v3.service", "oneshot", 15 * 60),
    "alert_queue_timer": ("powerbeam-alert-queue.timer", "timer", None),
    "alert_queue_last_run": ("powerbeam-alert-queue.service", "oneshot", 3 * 60),
    "health_last_run": ("powerbeam-health.service", "oneshot", 25 * 60),
}
PROPS = "LoadState,ActiveState,Result,ExecMainStatus,ExecMainExitTimestampMonotonic"
ORDER = {"HEALTHY": 0, "UNKNOWN": 1, "WARNING": 2, "CRITICAL": 3}


def read_unit(unit):
    """Return selected systemd metadata, not an entire unit or environment."""
    try:
        proc = subprocess.run(
            ["systemctl", "show", unit, "--no-pager", "--property=" + PROPS],
            capture_output=True, text=True, check=False, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("SYSTEMCTL_UNAVAILABLE") from None
    if proc.returncode:
        raise RuntimeError("SYSTEMCTL_QUERY_FAILED")
    values = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
    if values.get("LoadState") != "loaded":
        raise RuntimeError("UNIT_NOT_LOADED")
    return values


def check_unit(values, kind, now_us, max_age_sec):
    state = values.get("ActiveState", "")
    if state == "failed" or values.get("Result", "") not in ("", "success"):
        return {"status": "CRITICAL", "reason": "UNIT_FAILED"}
    if kind == "timer":
        return ({"status": "HEALTHY", "reason": "TIMER_ACTIVE"} if state == "active"
                else {"status": "CRITICAL", "reason": "TIMER_INACTIVE"})
    if values.get("ExecMainStatus") not in ("", "0"):
        return {"status": "CRITICAL", "reason": "SERVICE_NONZERO_EXIT"}
    if state not in ("inactive", "active"):
        return {"status": "WARNING", "reason": "SERVICE_UNEXPECTED_STATE"}
    try:
        exit_us = int(values.get("ExecMainExitTimestampMonotonic", "0"))
    except (ValueError, TypeError):
        exit_us = 0
    if exit_us <= 0:
        return {"status": "UNKNOWN", "reason": "NO_RECORDED_EXECUTION"}
    if values.get("Result") != "success" or values.get("ExecMainStatus") != "0":
        return {"status": "UNKNOWN", "reason": "INCOMPLETE_EXECUTION_RESULT"}
    age = (now_us - exit_us) / 1_000_000
    if age < -1:
        return {"status": "WARNING", "reason": "INVALID_MONOTONIC_TIMESTAMP"}
    if age > max_age_sec:
        return {"status": "WARNING", "reason": "LAST_SUCCESS_TOO_OLD"}
    return {"status": "HEALTHY", "reason": "RECENT_SUCCESS"}


def aggregate(statuses):
    return max(statuses, key=lambda x: ORDER.get(x, 1)) if statuses else "UNKNOWN"



# Public aggregate-only contract produced by alert_backlog_health.py.
# Never forward raw alert lists, IP addresses, source paths or token material.
MAX_BACKLOG_REPORT_BYTES = 65536
BACKLOG_SEVERITIES = ("informational", "low", "medium", "high", "critical")
BACKLOG_REASON_STATUS = {
    "NO_PENDING_ALERTS": "HEALTHY",
    "PENDING_WITHIN_POLICY": "HEALTHY",
    "HIGH_PENDING_TOO_OLD": "WARNING",
    "PENDING_EVENT_TOO_OLD": "WARNING",
    "FUTURE_EVENT_TIMESTAMP": "WARNING",
    "CRITICAL_SEVERITY_PENDING": "CRITICAL",
    "MAX_EVENT_AGE_EXCEEDED": "CRITICAL",
}


def _count(value):
    return type(value) is int and 0 <= value <= 100_000_000


def clean_backlog(raw):
    """Validate the independent backlog report and keep only aggregate values.

    No raw source content, alert IDs, IP addresses, or unexpected data survives.
    A bad report is UNKNOWN rather than incorrectly HEALTHY.
    """
    if not isinstance(raw, dict):
        return None
    if (raw.get("component") != "powerbeam_alert_backlog"
            or raw.get("inspection") != "LOCAL_READ_ONLY"
            or raw.get("age_basis") != "EVENT_TIMESTAMP_NOT_QUEUE_ENTRY"
            or raw.get("state_modified") is not False
            or type(raw.get("alerts_acknowledged")) is not int
            or raw["alerts_acknowledged"] != 0
            or type(raw.get("emails_sent")) is not int
            or raw["emails_sent"] != 0):
        return None
    status = raw.get("operational_status")
    reason = raw.get("status_reason")
    if status not in ("HEALTHY", "WARNING", "CRITICAL") or BACKLOG_REASON_STATUS.get(reason) != status:
        return None
    pending = raw.get("pending_total")
    seen = raw.get("seen_total")
    acknowledged = raw.get("acknowledged_total")
    counts = raw.get("pending_by_severity")
    if not all(map(_count, (pending, seen, acknowledged))):
        return None
    if not isinstance(counts, dict) or set(counts) != set(BACKLOG_SEVERITIES):
        return None
    if not all(_count(counts[k]) for k in BACKLOG_SEVERITIES):
        return None
    if sum(counts.values()) != pending or pending + acknowledged > seen:
        return None
    age = raw.get("oldest_event_age_minutes")
    if pending == 0:
        if age is not None or status != "HEALTHY" or reason != "NO_PENDING_ALERTS":
            return None
    elif (type(age) not in (int, float) or age != age or
          age < 0 or age > 10_000_000 or age == float("inf")):
        return None
    return {
        "operational_status": status,
        "status_reason": reason,
        "pending_total": pending,
        "seen_total": seen,
        "acknowledged_total": acknowledged,
        "pending_by_severity": {k: counts[k] for k in BACKLOG_SEVERITIES},
        "oldest_event_age_minutes": age,
        "age_basis": "EVENT_TIMESTAMP_NOT_QUEUE_ENTRY",
    }


def read_backlog_stdin(stream):
    """Bounded stdin parsing: do not persist raw data or log parse errors."""
    try:
        raw = stream.read(MAX_BACKLOG_REPORT_BYTES + 1)
        if len(raw) > MAX_BACKLOG_REPORT_BYTES:
            return None
        return json.loads(raw)
    except (ValueError, TypeError, OSError, UnicodeError):
        return None


def collect(token, *, online=False, reader=read_unit, oauth_reader=None,
            remote_reader=None, now_us=None, backlog_report=None,
            backlog_requested=False):
    now_us = int(time.monotonic() * 1_000_000) if now_us is None else now_us
    checks = {}
    for name, (unit, kind, max_age) in UNITS.items():
        try:
            checks[name] = check_unit(reader(unit), kind, now_us, max_age)
        except RuntimeError as exc:
            code = str(exc)
            if code not in {"SYSTEMCTL_UNAVAILABLE", "SYSTEMCTL_QUERY_FAILED", "UNIT_NOT_LOADED"}:
                code = "UNIT_QUERY_FAILED"
            checks[name] = {"status": "UNKNOWN", "reason": code}
        except Exception:
            checks[name] = {"status": "UNKNOWN", "reason": "UNIT_QUERY_FAILED"}
    detection_keys = ("soc_v1_timer", "soc_v3_timer", "health_timer",
                      "soc_v1_last_run", "soc_v3_last_run", "health_last_run")
    queue_keys = ("alert_queue_timer", "alert_queue_last_run")
    detection = aggregate([checks[k]["status"] for k in detection_keys])
    queue = aggregate([checks[k]["status"] for k in queue_keys])
    local = (oauth_reader or oauth_health.inspect)(token)
    local_status = local.get("local_status", "UNKNOWN")
    if local_status not in ("READY_LOCAL", "WARNING", "CRITICAL"):
        local_status = "UNKNOWN"
    remote = "NOT_CHECKED"
    if online:
        if remote_reader is None:
            import oauth_remote_health
            remote_reader = oauth_remote_health.check
        try:
            result = remote_reader(token)
            remote = result.get("remote_authorization", "NOT_CHECKED")
            if remote not in ("ACCEPTED", "FAILED", "NOT_CHECKED"):
                remote = "NOT_CHECKED"
        except Exception:
            remote = "FAILED"
    backlog = clean_backlog(backlog_report) if backlog_requested else None
    backlog_status = (backlog["operational_status"] if backlog is not None
                      else ("UNKNOWN" if backlog_requested else "NOT_CHECKED"))
    # Keep technical availability distinct from alert review/backlog policy.
    management = (aggregate((queue, backlog_status)) if backlog_requested
                  else "NOT_CHECKED")
    return {
        "component": "powerbeam_resilience",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inspection": "ONLINE_OAUTH_REFRESH_READ_ONLY" if online else "LOCAL_READ_ONLY",
        "detection_status": detection,
        "alert_queue_status": queue,
        "backlog_status": backlog_status,
        "alert_management_status": management,
        "alert_backlog": backlog,
        "notification_delivery": "NOT_AUTOMATED",
        "oauth_local": local_status,
        "oauth_remote": remote,
        "checks": checks,
        "emails_sent": 0,
        "tokens_modified": False,
        "note": "Estado de servicios, OAuth y (si se solicita) backlog V1 por hora del evento; "
                "no certifica ingestión de logs, espera desde entrada en cola ni entrega de correo."
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="PowerBeam: estado de resiliencia sin enviar correos")
    parser.add_argument("--token", type=Path, default=oauth_health.DEFAULT_TOKEN)
    parser.add_argument("--online", choices=["YES"], help="Permite una renovacion OAuth en memoria")
    parser.add_argument("--backlog-stdin", action="store_true",
                        help="Lee SOLO el informe agregado de alert_backlog_health.py desde stdin")
    args = parser.parse_args(argv)
    backlog_report = read_backlog_stdin(sys.stdin) if args.backlog_stdin else None
    report = collect(args.token, online=(args.online == "YES"),
                     backlog_requested=args.backlog_stdin, backlog_report=backlog_report)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    # Nonzero only for broken local components; OAuth in Testing may be UNKNOWN.
    statuses = (report["detection_status"], report["alert_queue_status"])
    if args.backlog_stdin:
        statuses += (report["backlog_status"],)
    if "CRITICAL" in statuses:
        return 2
    if "WARNING" in statuses or "UNKNOWN" in statuses:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
