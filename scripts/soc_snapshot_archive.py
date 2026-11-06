#!/usr/bin/env python3
"""Store immutable, minimized snapshots of PowerBeam's aggregate daily SOC JSON.

Use as the regular desktop user. Reads report JSON from stdin, never raw alerts,
credentials or OAuth tokens. Archives are snapshots taken NOW, even for historical
activity dates; health and pending counts are never labeled as past-day states.
"""

import argparse
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from zoneinfo import ZoneInfo

MAX_STDIN = 64 * 1024
MAX_COUNT = 100_000_000
SEVERITIES = ("informational", "low", "medium", "high", "critical")
RULES = ("SOC-001", "SOC-002", "other")
HEALTH_VALUES = frozenset({
    "HEALTHY", "WARNING", "CRITICAL", "UNKNOWN", "DEGRADED", "READY_LOCAL",
    "NOT_READY", "NOT_CHECKED", "NOT_AUTOMATED", "DISABLED", "ERROR",
})
FILE_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2})__snapshot-(\d{8}T\d{12}Z)-([0-9a-f]{8})\.json$")
DEFAULT_DIR = Path.home() / ".local/share/powerbeam-security-lab/soc-reports"


class ArchiveError(Exception):
    """Safe error with no user-controlled fields in its message."""


def _count(value):
    return type(value) is int and 0 <= value <= MAX_COUNT


def _counts(raw, keys):
    if not isinstance(raw, dict) or set(raw) != set(keys):
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    if not all(_count(raw[key]) for key in keys):
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    return {key: raw[key] for key in keys}


def minimize_report(report):
    """Whitelist aggregates only; NEVER persist source JSON's extra keys."""
    if not isinstance(report, dict) or any((
        report.get("component") != "powerbeam_soc_daily",
        report.get("report_status") != "READY",
        report.get("inspection") != "LOCAL_READ_ONLY",
        report.get("emails_sent") != 0 or type(report.get("emails_sent")) is not int,
        report.get("tokens_modified") is not False,
        report.get("timezone") != "Europe/Madrid",
    )):
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    raw_date = report.get("report_date")
    if not isinstance(raw_date, str):
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    try:
        if date.fromisoformat(raw_date).isoformat() != raw_date:
            raise ValueError
    except ValueError as exc:
        raise ArchiveError("INVALID_REPORT_SCHEMA") from exc

    activity = report.get("activity")
    pending = report.get("pending_now")
    health = report.get("health")
    if not isinstance(activity, dict) or not isinstance(pending, dict) or not isinstance(health, dict):
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    ar = _counts(activity.get("alerts_by_rule"), RULES)
    sev = _counts(activity.get("alerts_by_severity"), SEVERITIES)
    ps = _counts(pending.get("by_severity"), SEVERITIES)
    if not all(_count(v) for v in (
        activity.get("alerts_event_date"), activity.get("acknowledged_on_date"), pending.get("total")
    )):
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    if sum(ar.values()) != sum(sev.values()) or sum(ar.values()) != activity["alerts_event_date"]:
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    if sum(ps.values()) != pending["total"]:
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    age = pending.get("oldest_event_age_minutes")
    if age is not None and (type(age) not in (int, float) or not 0 <= age <= 1e8):
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    if pending["total"] == 0 and age is not None:
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    status = pending.get("status")
    if status not in ("HEALTHY", "WARNING", "CRITICAL", "UNKNOWN"):
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    health_keys = ("detection", "alert_queue", "backlog", "oauth_local", "oauth_remote", "notification_delivery")
    sanitized_health = {}
    for key in health_keys:
        val = health.get(key)
        if type(val) is not str or val not in HEALTH_VALUES:
            raise ArchiveError("INVALID_REPORT_SCHEMA")
        sanitized_health[key] = val
    if sanitized_health["backlog"] != status:
        raise ArchiveError("INVALID_REPORT_SCHEMA")
    return {
        "report_date": raw_date,
        "report_timezone": "Europe/Madrid",
        "activity_by_event_date_v1": {
            "alerts_total": activity["alerts_event_date"],
            "by_rule": ar,
            "by_severity": sev,
            "acknowledged_on_date": activity["acknowledged_on_date"],
        },
        "pending_at_capture": {
            "total": pending["total"], "by_severity": ps,
            "oldest_event_age_minutes": age, "status": status,
        },
        "health_at_capture": sanitized_health,
    }


def _load_stdin(stream):
    try:
        data = stream.read(MAX_STDIN + 1)
        if len(data) > MAX_STDIN:
            raise ArchiveError("REPORT_TOO_LARGE")
        return minimize_report(json.loads(data))
    except (ValueError, UnicodeError, OSError) as exc:
        raise ArchiveError("INVALID_REPORT_JSON") from exc


def build_snapshot(clean, *, now=None):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ArchiveError("INVALID_CLOCK")
    utc = now.astimezone(timezone.utc)
    local_date = now.astimezone(ZoneInfo("Europe/Madrid")).date()
    target = date.fromisoformat(clean["report_date"])
    if target > local_date:
        raise ArchiveError("FUTURE_REPORT_DATE")
    context = ("SAME_DAY_PARTIAL_ACTIVITY_WITH_CURRENT_STATE" if target == local_date
               else "RETROSPECTIVE_ACTIVITY_WITH_CURRENT_STATE")
    return {
        "component": "powerbeam_soc_archive_snapshot", "schema_version": 1,
        "captured_at_utc": utc.isoformat().replace("+00:00", "Z"),
        "snapshot_context": context,
        "report_date": clean["report_date"],
        "report_timezone": clean["report_timezone"],
        "activity_by_event_date_v1": clean["activity_by_event_date_v1"],
        "pending_at_capture": clean["pending_at_capture"],
        "health_at_capture": clean["health_at_capture"],
        "scope_note": "Activity belongs to report_date; pending and health belong to captured_at_utc. Counts may change if late evidence arrives.",
    }


def _validate_private_dir(path, *, create):
    path = Path(path).expanduser()
    if not path.is_absolute():
        raise ArchiveError("ARCHIVE_DIR_MUST_BE_ABSOLUTE")
    try:
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or (parent.st_mode & 0o077):
            raise ArchiveError("PARENT_DIRECTORY_NOT_PRIVATE")
        try:
            info = path.lstat()
        except FileNotFoundError:
            if not create:
                return None
            path.mkdir(mode=0o700)
            info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or (info.st_mode & 0o077)):
            raise ArchiveError("ARCHIVE_DIRECTORY_NOT_PRIVATE")
        return path
    except (OSError, ValueError) as exc:
        raise ArchiveError("ARCHIVE_DIRECTORY_UNAVAILABLE") from exc


def save_snapshot(snapshot, archive_dir, *, now=None):
    """Atomic, no-overwrite save via private directory and hard-link publication."""
    archive_dir = _validate_private_dir(archive_dir, create=True)
    now = now or datetime.now(timezone.utc)
    utc = now.astimezone(timezone.utc)
    stamp = utc.strftime("%Y%m%dT%H%M%S%fZ")
    base = f"{snapshot['report_date']}__snapshot-{stamp}-{secrets.token_hex(4)}.json"
    tmp = f".partial-{secrets.token_hex(12)}.json"
    payload = (json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(archive_dir, dir_flags)
    except OSError as exc:
        raise ArchiveError("ARCHIVE_DIRECTORY_UNAVAILABLE") from exc
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600, dir_fd=directory_fd)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(tmp, base, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
            os.fsync(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            os.unlink(tmp, dir_fd=directory_fd)
        return base
    except OSError as exc:
        raise ArchiveError("ARCHIVE_WRITE_FAILED") from exc
    finally:
        os.close(directory_fd)


def list_snapshots(archive_dir, limit=20):
    path = _validate_private_dir(archive_dir, create=False)
    if path is None:
        return []
    found = []
    try:
        for item in path.iterdir():
            if item.is_symlink():
                continue
            match = FILE_PATTERN.fullmatch(item.name)
            if match and item.is_file():
                found.append({"filename": item.name, "report_date": match.group(1)})
    except OSError as exc:
        raise ArchiveError("ARCHIVE_READ_FAILED") from exc
    return sorted(found, key=lambda item: item["filename"], reverse=True)[:limit]


def main(argv=None):
    parser = argparse.ArgumentParser(description="PowerBeam: archivo privado de informes SOC agregados")
    parser.add_argument("action", choices=("save", "list"))
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    parser.add_argument("--dry-run", action="store_true", help="Validar sin escribir (solo save)")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args(argv)
    if args.limit < 1 or args.limit > 100:
        parser.error("--limit debe estar entre 1 y 100")
    if args.action == "list" and args.dry_run:
        parser.error("--dry-run solo se permite con save")
    try:
        if args.action == "list":
            items = list_snapshots(args.dir, args.limit)
            result = {"action": "list", "count": len(items), "snapshots": items}
        else:
            clean = _load_stdin(sys.stdin)
            now = datetime.now(timezone.utc)
            snapshot = build_snapshot(clean, now=now)
            name = None if args.dry_run else save_snapshot(snapshot, args.dir, now=now)
            result = {"action": "save", "saved": not args.dry_run,
                      "report_date": snapshot["report_date"],
                      "snapshot_context": snapshot["snapshot_context"],
                      "filename": name, "emails_sent": 0, "tokens_modified": False}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except ArchiveError as exc:
        # Codes are fixed; no user path, alert data, token, or JSON is echoed.
        print(json.dumps({"action": args.action, "status": "ERROR", "code": str(exc)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
