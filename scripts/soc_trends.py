#!/usr/bin/env python3
"""Read-only SOC V1 activity trend analysis from private Phase 7 archive snapshots.

Only aggregate activity by event date is compared. Health and pending counts are
capture-time observations and must never be presented as historical day states.
The process uses no OAuth credentials, raw alert/queue data, outbound traffic or
archive writes. Missing snapshots are NOT zeros; V1 alert counts are NOT proof
of complete log ingestion or absence of malicious network activity.
"""

import argparse
from datetime import date, datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from zoneinfo import ZoneInfo

import soc_snapshot_archive as archive

MAX_FILE_BYTES = 64 * 1024
MAX_DIRECTORY_ENTRIES = 10_000
MAX_RANGE_DAYS = 31
MAX_COUNT = 100_000_000
RULES = ("SOC-001", "SOC-002", "other")
SEVERITIES = ("informational", "low", "medium", "high", "critical")
LOCAL_TZ = ZoneInfo("Europe/Madrid")
FILE_PATTERN = archive.FILE_PATTERN
DEFAULT_DIR = archive.DEFAULT_DIR


class TrendsError(Exception):
    """Fixed, non-sensitive error code only."""


def _valid_count(value):
    return type(value) is int and 0 <= value <= MAX_COUNT


def _day(text):
    try:
        if type(text) is not str:
            raise ValueError
        parsed = date.fromisoformat(text)
        if parsed.isoformat() != text:
            raise ValueError
        return parsed
    except ValueError as exc:
        raise TrendsError("INVALID_DATE") from exc


def _counts(obj, fields):
    if type(obj) is not dict or set(obj) != set(fields):
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    if not all(_valid_count(obj[key]) for key in fields):
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    return {key: obj[key] for key in fields}


def validate_snapshot(raw, filename):
    """Validate Phase 7 schema and filename, return a strict whitelist."""
    match = FILE_PATTERN.fullmatch(filename)
    if not match or type(raw) is not dict:
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    day_text, stamped, _suffix = match.groups()
    day = _day(day_text)
    if (raw.get("component") != "powerbeam_soc_archive_snapshot"
            or type(raw.get("schema_version")) is not int
            or raw["schema_version"] != 1
            or raw.get("report_date") != day_text
            or raw.get("report_timezone") != "Europe/Madrid"):
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    captured_text = raw.get("captured_at_utc")
    try:
        if type(captured_text) is not str or not captured_text.endswith("Z"):
            raise ValueError
        captured = datetime.fromisoformat(captured_text.replace("Z", "+00:00"))
        if captured.tzinfo is None or captured.utcoffset() != timedelta(0):
            raise ValueError
    except ValueError as exc:
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA") from exc
    if stamped != captured.strftime("%Y%m%dT%H%M%S%fZ"):
        raise TrendsError("FILENAME_TIMESTAMP_MISMATCH")
    captured_day = captured.astimezone(LOCAL_TZ).date()
    context = ("SAME_DAY_PARTIAL_ACTIVITY_WITH_CURRENT_STATE" if day == captured_day
               else "RETROSPECTIVE_ACTIVITY_WITH_CURRENT_STATE")
    if day > captured_day or raw.get("snapshot_context") != context:
        raise TrendsError("INVALID_SNAPSHOT_CONTEXT")
    activity = raw.get("activity_by_event_date_v1")
    pending = raw.get("pending_at_capture")
    health = raw.get("health_at_capture")
    if type(activity) is not dict or type(pending) is not dict or type(health) is not dict:
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    by_rule = _counts(activity.get("by_rule"), RULES)
    by_severity = _counts(activity.get("by_severity"), SEVERITIES)
    total = activity.get("alerts_total")
    ack = activity.get("acknowledged_on_date")
    if not _valid_count(total) or not _valid_count(ack):
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    if sum(by_rule.values()) != total or sum(by_severity.values()) != total:
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    pcounts = _counts(pending.get("by_severity"), SEVERITIES)
    if not _valid_count(pending.get("total")) or sum(pcounts.values()) != pending["total"]:
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    age = pending.get("oldest_event_age_minutes")
    if (age is not None and (type(age) not in (int, float)
                             or not math.isfinite(age) or age < 0 or age > 1e8)):
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    if pending["total"] == 0 and age is not None:
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    if pending.get("status") not in ("HEALTHY", "WARNING", "CRITICAL", "UNKNOWN"):
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    if set(health) != {"detection", "alert_queue", "backlog", "oauth_local",
                       "oauth_remote", "notification_delivery"}:
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    if any(type(value) is not str or value not in archive.HEALTH_VALUES
           for value in health.values()) or health["backlog"] != pending["status"]:
        raise TrendsError("INVALID_SNAPSHOT_SCHEMA")
    return {
        "report_date": day.isoformat(),
        "captured_at_utc": captured.isoformat().replace("+00:00", "Z"),
        "capture_time": captured,
        "snapshot_context": context,
        "alerts_total": total,
        "by_rule": by_rule,
        "by_severity": by_severity,
        "acknowledged_on_date": ack,
    }


def _read_file(directory_fd, filename, owner_uid):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise TrendsError("SNAPSHOT_UNREADABLE") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES):
            raise TrendsError("SNAPSHOT_UNSAFE_OR_TOO_LARGE")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise TrendsError("SNAPSHOT_UNSAFE_OR_TOO_LARGE")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError, TypeError) as exc:
            raise TrendsError("SNAPSHOT_INVALID_JSON") from exc
        return validate_snapshot(data, filename)
    except OSError as exc:
        raise TrendsError("SNAPSHOT_UNREADABLE") from exc
    finally:
        os.close(fd)


def read_archive(archive_dir, start, end):
    """Read relevant secure archive files only; never disclose raw content."""
    try:
        private = archive._validate_private_dir(archive_dir, create=False)
    except archive.ArchiveError as exc:
        raise TrendsError("ARCHIVE_DIRECTORY_UNSAFE") from exc
    if private is None:
        return []
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(private, flags)
    except OSError as exc:
        raise TrendsError("ARCHIVE_DIRECTORY_UNREADABLE") from exc
    try:
        result = []
        with os.scandir(directory_fd) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_DIRECTORY_ENTRIES:
                    raise TrendsError("ARCHIVE_TOO_MANY_FILES")
                match = FILE_PATTERN.fullmatch(entry.name)
                if not match:
                    continue
                # Reject any malformed date in a seemingly valid archive filename.
                try:
                    day = _day(match.group(1))
                except TrendsError as exc:
                    raise TrendsError("INVALID_SNAPSHOT_FILENAME") from exc
                if start <= day <= end:
                    result.append(_read_file(directory_fd, entry.name, os.getuid()))
        return result
    except OSError as exc:
        raise TrendsError("ARCHIVE_READ_FAILED") from exc
    finally:
        os.close(directory_fd)


def compare(records, *, start, end, now=None):
    """Pure comparison of validated snapshots; no file access or side effects."""
    start = _day(start) if isinstance(start, str) else start
    end = _day(end) if isinstance(end, str) else end
    if type(start) is not date or type(end) is not date or end < start:
        raise TrendsError("INVALID_DATE_RANGE")
    total_days = (end - start).days + 1
    if total_days < 2 or total_days > MAX_RANGE_DAYS:
        raise TrendsError("INVALID_DATE_RANGE")
    now = now or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise TrendsError("INVALID_CLOCK")
    if end > now.astimezone(LOCAL_TZ).date():
        raise TrendsError("FUTURE_DATE_RANGE")
    by_day = {start + timedelta(days=n): [] for n in range(total_days)}
    for record in records:
        day = _day(record["report_date"])
        if day not in by_day:
            raise TrendsError("OUT_OF_RANGE_SNAPSHOT")
        if record["capture_time"] > now.astimezone(timezone.utc) + timedelta(minutes=1):
            raise TrendsError("FUTURE_SNAPSHOT_CAPTURE")
        by_day[day].append(record)
    rows = []
    previous = None
    complete = True
    for day, captures in by_day.items():
        day_text = day.isoformat()
        if not captures:
            row = {"date": day_text, "status": "MISSING_SNAPSHOT", "alerts_total": None,
                   "by_rule": None, "by_severity": None, "acknowledged_on_date": None,
                   "captured_at_utc": None, "snapshot_count": 0,
                   "revisions_detected": False}
        else:
            captures.sort(key=lambda item: (item["capture_time"], json.dumps(item["by_rule"], sort_keys=True)))
            latest = captures[-1]
            # Equal timestamps with different counts are ambiguous, do not guess.
            for item in captures[:-1]:
                if item["capture_time"] == latest["capture_time"] and any(
                    item[key] != latest[key] for key in ("alerts_total", "by_rule", "by_severity", "acknowledged_on_date")
                ):
                    raise TrendsError("AMBIGUOUS_SNAPSHOT_REVISION")
            revisions = len({json.dumps({k: item[k] for k in (
                "alerts_total", "by_rule", "by_severity", "acknowledged_on_date")}, sort_keys=True)
                for item in captures}) > 1
            row = {"date": day_text,
                   "status": ("PARTIAL_AT_CAPTURE" if latest["snapshot_context"].startswith("SAME_DAY") else "RECORDED"),
                   "alerts_total": latest["alerts_total"],
                   "by_rule": latest["by_rule"], "by_severity": latest["by_severity"],
                   "acknowledged_on_date": latest["acknowledged_on_date"],
                   "captured_at_utc": latest["captured_at_utc"],
                   "snapshot_count": len(captures),
                   "revisions_detected": revisions}
        if row["status"] != "RECORDED":
            complete = False
        if previous is None:
            delta = None
            trend = "NO_BASELINE"
            delta_percent = None
        elif previous["status"] != "RECORDED" or row["status"] != "RECORDED":
            delta = None
            trend = "NOT_COMPARABLE"
            delta_percent = None
        else:
            delta = row["alerts_total"] - previous["alerts_total"]
            trend = "INCREASE" if delta > 0 else "DECREASE" if delta < 0 else "UNCHANGED"
            delta_percent = round(delta * 100 / previous["alerts_total"], 2) if previous["alerts_total"] else None
        row["change_from_previous_day"] = delta
        row["change_percent"] = delta_percent
        row["trend"] = trend
        rows.append(row)
        previous = row
    recorded = [r for r in rows if r["status"] == "RECORDED"]
    known_sum = sum(r["alerts_total"] for r in recorded)
    peak = max((r["alerts_total"] for r in recorded), default=None)
    peak_days = [r["date"] for r in recorded if r["alerts_total"] == peak]
    return {
        "component": "powerbeam_soc_trends", "schema_version": 1,
        "inspection": "LOCAL_READ_ONLY", "source_scope": "ARCHIVED_V1_ALERT_ACTIVITY_ONLY",
        "timezone": "Europe/Madrid", "start_date": start.isoformat(), "end_date": end.isoformat(),
        "coverage_status": "COMPLETE_SNAPSHOTS" if complete else "INCOMPLETE_SNAPSHOTS",
        "days_requested": total_days, "days_recorded_complete": len(recorded),
        "days_missing": sum(r["status"] == "MISSING_SNAPSHOT" for r in rows),
        "days_partial": sum(r["status"] == "PARTIAL_AT_CAPTURE" for r in rows),
        "known_complete_day_alerts": known_sum,
        "period_total_alerts": known_sum if complete else None,
        "peak_count_recorded": peak, "peak_days_recorded": peak_days,
        "days": rows, "emails_sent": 0, "tokens_modified": False,
        "caveat": ("Archived V1 event counts only, not evidence of complete ingestion or absence of threats. "
                   "No snapshot is not zero. Capture-time health/pending are excluded. "
                   "Later snapshots may revise counts; latest capture per date is used."),
    }


def as_text(report):
    lines = ["=" * 62, "POWERBEAM SECURITY LAB — SOC TRENDS",
             "=" * 62,
             f"Periodo: {report['start_date']} a {report['end_date']} (Europe/Madrid)",
             f"Cobertura de instantáneas: {report['coverage_status']}",
             "", "ACTIVIDAD DE ALERTAS V1 ARCHIVADA (FECHA DEL EVENTO)",
             "Fecha        Estado                  Total  SOC-001  SOC-002  Cambio"]
    for row in report["days"]:
        total = "N/D" if row["alerts_total"] is None else str(row["alerts_total"])
        r1 = "N/D" if row["by_rule"] is None else str(row["by_rule"]["SOC-001"])
        r2 = "N/D" if row["by_rule"] is None else str(row["by_rule"]["SOC-002"])
        change = "N/C" if row["change_from_previous_day"] is None else f"{row['change_from_previous_day']:+d}"
        lines.append(f"{row['date']}   {row['status']:<22} {total:>5}  {r1:>7}  {r2:>7}  {change:>6}")
        if row["revisions_detected"]:
            lines.append("   Aviso: varias instantáneas con recuentos diferentes; se eligió la más reciente.")
    lines += ["", f"Días completos archivados: {report['days_recorded_complete']}/{report['days_requested']}",
              f"Días sin instantánea: {report['days_missing']}",
              f"Días parciales al capturar: {report['days_partial']}",
              f"Suma de días completos disponibles: {report['known_complete_day_alerts']}",
              (f"TOTAL DEL PERIODO: {report['period_total_alerts']}" if report['period_total_alerts'] is not None
               else "TOTAL DEL PERIODO: N/D (faltan días completos)"),
              "", "NOTAS",
              "N/D = no disponible; N/C = no comparable.",
              "Son alertas V1 archivadas, no todos los eventos de red.",
              "Cero alertas no demuestra que no existieran amenazas ni huecos de ingestión.",
              "Estados de salud y pendientes históricos NO se infieren de capturas posteriores.",
              "=" * 62, "Solo lectura | Sin correo | Sin acceso al token OAuth"]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Comparar instantáneas privadas SOC (solo lectura)")
    parser.add_argument("--start", required=True, help="Fecha inicial YYYY-MM-DD")
    parser.add_argument("--end", required=True, help="Fecha final YYYY-MM-DD")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="Carpeta privada de instantáneas")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        start, end = _day(args.start), _day(args.end)
        # Validate bounds before file operations.
        if (end - start).days + 1 < 2 or (end - start).days + 1 > MAX_RANGE_DAYS:
            raise TrendsError("INVALID_DATE_RANGE")
        if end < start:
            raise TrendsError("INVALID_DATE_RANGE")
        if end > datetime.now(LOCAL_TZ).date():
            raise TrendsError("FUTURE_DATE_RANGE")
        report = compare(read_archive(args.dir, start, end), start=start, end=end)
    except (TrendsError, TypeError, ValueError) as exc:
        code = str(exc) if isinstance(exc, TrendsError) else "TRENDS_UNAVAILABLE"
        print(json.dumps({"component": "powerbeam_soc_trends", "status": "UNKNOWN",
                          "reason": code, "emails_sent": 0, "tokens_modified": False}))
        return 2
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(as_text(report))
    return 0 if report["coverage_status"] == "COMPLETE_SNAPSHOTS" else 1


if __name__ == "__main__":
    sys.exit(main())
