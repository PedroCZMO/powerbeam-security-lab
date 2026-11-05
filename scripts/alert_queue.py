#!/usr/bin/env python3
"""PowerBeam Day 11 / phase 1: durable local notification queue (NO network).

Input: canonical V1 alerts.jsonl. V3 is deliberately excluded to avoid
sending two notifications for the same incident in parallel.

Commands:
  bootstrap: acknowledge historical alerts without queuing them
  scan:      queue only previously unseen alert IDs, idempotently
  status:    print queue statistics
  ack:       explicitly acknowledge one pending alert, with audit record

The queue and seen IDs are committed together as a single atomic JSON state.
"""

import argparse
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile

SCHEMA_VERSION = 1
ALERT_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
RULE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical", "informational"}
ACK_REASONS = {"reviewed", "delivered"}
MAX_ALERT_LINE = 256 * 1024
MAX_STATE_BYTES = 16 * 1024 * 1024


def normalize_alert(obj, line_no):
    """Keep only fields required for future notification delivery."""
    if not isinstance(obj, dict):
        raise ValueError(f"Línea {line_no}: no es objeto JSON")
    aid = obj.get("alert_id")
    rule = obj.get("rule_id")
    severity = obj.get("severity")
    source_ip = obj.get("source_ip")
    timestamp = obj.get("timestamp")
    if not isinstance(aid, str) or not ALERT_ID_RE.fullmatch(aid):
        raise ValueError(f"Línea {line_no}: alert_id inválido")
    if not isinstance(rule, str) or not RULE_RE.fullmatch(rule):
        raise ValueError(f"Línea {line_no}: rule_id inválido")
    if not isinstance(severity, str) or severity not in ALLOWED_SEVERITIES:
        raise ValueError(f"Línea {line_no}: severity inválida")
    if not isinstance(source_ip, str):
        raise ValueError(f"Línea {line_no}: source_ip inválida")
    try:
        source_ip = str(ipaddress.ip_address(source_ip))
    except ValueError as exc:
        raise ValueError(f"Línea {line_no}: source_ip inválida") from exc
    if not isinstance(timestamp, str):
        raise ValueError(f"Línea {line_no}: timestamp inválido")
    try:
        dt = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValueError(f"Línea {line_no}: timestamp inválido") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"Línea {line_no}: timestamp sin zona horaria")
    return {"alert_id": aid, "rule_id": rule, "severity": severity,
            "source_ip": source_ip, "timestamp": timestamp}


def read_alerts(path):
    path = Path(path)
    alerts = []
    # Real monitor writes newline-delimited JSON. A trailing partial line is
    # ignored until the next scan, rather than treated as a corrupt record.
    with path.open("rb") as handle:
        for line_no, raw in enumerate(handle, start=1):
            if len(raw) > MAX_ALERT_LINE:
                raise ValueError(f"Línea {line_no}: longitud excesiva")
            if not raw.endswith(b"\n"):
                break
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"Línea {line_no}: JSONL inválido") from exc
            alerts.append(normalize_alert(obj, line_no))
    return alerts


def validate_state(state):
    if not isinstance(state, dict) or state.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Estado incompatible o corrupto")
    seen = state.get("seen_alert_ids")
    pending = state.get("pending")
    if not isinstance(seen, list) or not isinstance(pending, list):
        raise ValueError("Estado incompleto o corrupto")
    if any(not isinstance(a, str) or not ALERT_ID_RE.fullmatch(a) for a in seen):
        raise ValueError("IDs en estado inválidos")
    if len(seen) != len(set(seen)):
        raise ValueError("IDs repetidos en estado")
    pending_ids = []
    for obj in pending:
        norm = normalize_alert(obj, "estado")
        pending_ids.append(norm["alert_id"])
        if norm != obj:
            raise ValueError("Cola en estado inválida")
    if len(pending_ids) != len(set(pending_ids)) or not set(pending_ids).issubset(set(seen)):
        raise ValueError("Cola inconsistente con IDs vistos")
    acknowledgements = state.get("acknowledged", [])
    if not isinstance(acknowledgements, list):
        raise ValueError("Historial de acuses corrupto")
    ack_ids = []
    for record in acknowledgements:
        if not isinstance(record, dict) or set(record) != {"alert_id", "reason", "acknowledged_at"}:
            raise ValueError("Registro de acuse inválido")
        aid = record["alert_id"]
        if not isinstance(aid, str) or not ALERT_ID_RE.fullmatch(aid):
            raise ValueError("ID de acuse inválido")
        if not isinstance(record["reason"], str) or record["reason"] not in ACK_REASONS:
            raise ValueError("Motivo de acuse inválido")
        stamp = record["acknowledged_at"]
        if not isinstance(stamp, str):
            raise ValueError("Hora de acuse inválida")
        try:
            dt = datetime.fromisoformat(stamp)
        except ValueError as exc:
            raise ValueError("Hora de acuse inválida") from exc
        if dt.tzinfo is None or dt.utcoffset() is None:
            raise ValueError("Hora de acuse sin zona horaria")
        ack_ids.append(aid)
    if len(ack_ids) != len(set(ack_ids)) or not set(ack_ids).issubset(set(seen)):
        raise ValueError("Historial de acuses inconsistente")
    if set(ack_ids).intersection(pending_ids):
        raise ValueError("Alerta simultáneamente pendiente y reconocida")
    return state


def read_state(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError("Estado no inicializado. Ejecuta bootstrap primero")
    if path.stat().st_size > MAX_STATE_BYTES:
        raise ValueError("Estado demasiado grande para esta versión de laboratorio")
    with path.open(encoding="utf-8") as handle:
        return validate_state(json.load(handle))


def atomic_save(path, state):
    path = Path(path)
    encoded = (json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError("Límite de estado superado; no se han guardado cambios")
    temp_name = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=".alertqueue-", dir=str(path.parent))
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        temp_name = None
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if temp_name is not None:
            os.unlink(temp_name)


def run(command, source, state_path, *, alert_id=None, reason=None):
    source = Path(source)
    state_path = Path(state_path)
    if source.resolve() == state_path.resolve():
        raise ValueError("Origen y estado deben ser distintos")
    if command not in ("bootstrap", "scan", "status", "ack"):
        raise ValueError("Comando desconocido")
    if command == "ack":
        if not isinstance(alert_id, str) or not ALERT_ID_RE.fullmatch(alert_id):
            raise ValueError("Para ack se requiere --alert-id válido")
        if not isinstance(reason, str) or reason not in ACK_REASONS:
            raise ValueError("Para ack se requiere --reason reviewed|delivered")
    elif alert_id is not None or reason is not None:
        raise ValueError("--alert-id y --reason solo admitidos con ack")
    # Lock is separate from atomic state file: lock inode remains stable.
    state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = state_path.with_name(state_path.name + ".lock")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        if command == "bootstrap":
            if state_path.exists():
                raise FileExistsError("Estado existente: bootstrap no puede reinicializarlo")
            alerts = read_alerts(source)
            ids = list(dict.fromkeys(a["alert_id"] for a in alerts))
            state = {"schema_version": SCHEMA_VERSION,
                     "seen_alert_ids": ids, "pending": []}
            atomic_save(state_path, state)
            return {"action": "bootstrap", "historical_ignored": len(ids), "pending": 0}
        state = read_state(state_path)
        if command == "status":
            return {"action": "status", "seen": len(state["seen_alert_ids"]),
                    "pending": len(state["pending"]), "pending_alerts": state["pending"],
                    "acknowledged": len(state.get("acknowledged", []))}
        if command == "ack":
            if alert_id not in {item["alert_id"] for item in state["pending"]}:
                raise ValueError("La alerta no está pendiente (desconocida o ya reconocida)")
            state["pending"] = [item for item in state["pending"] if item["alert_id"] != alert_id]
            state.setdefault("acknowledged", []).append({
                "alert_id": alert_id, "reason": reason,
                "acknowledged_at": datetime.now(timezone.utc).isoformat()})
            validate_state(state)
            atomic_save(state_path, state)
            return {"action": "ack", "alert_id": alert_id, "reason": reason,
                    "pending": len(state["pending"]),
                    "acknowledged": len(state["acknowledged"])}
        alerts = read_alerts(source)
        seen = set(state["seen_alert_ids"])
        new = []
        for alert in alerts:
            if alert["alert_id"] not in seen:
                new.append(alert)
                seen.add(alert["alert_id"])
                state["seen_alert_ids"].append(alert["alert_id"])
                state["pending"].append(alert)
        if new:
            atomic_save(state_path, state)
        return {"action": "scan", "new_queued": len(new),
                "pending": len(state["pending"]), "new_alerts": new}
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Cola local de alertas PowerBeam, sin envío externo")
    parser.add_argument("command", choices=["bootstrap", "scan", "status", "ack"])
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--alert-id")
    parser.add_argument("--reason", choices=sorted(ACK_REASONS))
    args = parser.parse_args(argv)
    try:
        result = run(args.command, args.source, args.state,
                     alert_id=args.alert_id, reason=args.reason)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
