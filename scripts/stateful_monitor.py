#!/usr/bin/env python3
"""Día 6 fase 2: laboratorio de correlación incremental con contexto persistente.

NO sustituye el servicio systemd actual. Sólo lee históricos SIN COMPRIMIR.
Invocación desde la raíz del repo:
  python3 scripts/stateful_monitor.py \
    --log-dir alerts/demo-stateful/logs \
    --state alerts/demo-stateful/state.json \
    --output alerts/demo-stateful/alerts.jsonl
"""

import argparse
from collections import Counter, defaultdict, deque
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile

from auth_detector import parse_event
from incremental_reader import snapshot_raw
from security_monitor import append_unique, make_alert

VERSION = 1
WINDOW = timedelta(minutes=5)
FAILURE_KINDS = {"usuario_inexistente", "contrasena_incorrecta"}


def blank_state():
    return {
        "version": VERSION,
        "cursors": {},
        "soc001_failures": {},
        "soc002_failures": {},
        "soc001_last_alert": {},
        "last_event_timestamp": None,
    }


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError("Fecha inválida en el estado")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("Fecha ISO inválida en el estado") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Fecha sin zona horaria en el estado")
    return timestamp


def read_checkpoint(path):
    path = Path(path)
    if not path.exists():
        return blank_state()
    if path.is_symlink():
        raise ValueError("No se admiten enlaces simbólicos para el estado")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("Estado JSON corrupto") from exc
    expected = blank_state()
    if not isinstance(data, dict) or set(data) != set(expected) or data["version"] != VERSION:
        raise ValueError("Estado con esquema o versión inesperados")
    cursors = data["cursors"]
    if not isinstance(cursors, dict):
        raise ValueError("Cursores inválidos")
    import re
    for ident, offset in cursors.items():
        if not isinstance(ident, str) or not re.fullmatch(r"\d+:\d+", ident):
            raise ValueError("Identificador de archivo inválido")
        if type(offset) is not int or offset < 0:
            raise ValueError("Offset inválido")
    for name in ("soc001_failures", "soc002_failures"):
        if not isinstance(data[name], dict):
            raise ValueError(f"Estado inválido para {name}")
        for ip, times in data[name].items():
            if not isinstance(ip, str) or not isinstance(times, list):
                raise ValueError("Historial de fallos inválido")
            for value in times:
                parse_time(value)
    if not isinstance(data["soc001_last_alert"], dict):
        raise ValueError("Historial de alertas inválido")
    for ip, value in data["soc001_last_alert"].items():
        if not isinstance(ip, str):
            raise ValueError("IP inválida")
        parse_time(value)
    if data["last_event_timestamp"] is not None:
        parse_time(data["last_event_timestamp"])
    return data


def save_checkpoint(path, state):
    """Escribe un único checkpoint atómico: cursores + contexto de detección."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".state-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def exclusive_lock(state_path):
    """Impide dos ejecuciones concurrentes sobre el mismo checkpoint."""
    lock_path = Path(str(state_path) + ".lock")
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError as exc:
        raise RuntimeError("Ya hay otra ejecución utilizando este estado") from exc
    finally:
        os.close(fd)


def correlate(lines, state):
    """Correlaciona las reglas entre lotes sin cambiar el estado de entrada."""
    next_state = deepcopy(state)
    events = [event for line in lines if (event := parse_event(line))]
    events.sort(key=lambda event: event[0])
    highwater = (parse_time(state["last_event_timestamp"])
                 if state["last_event_timestamp"] else None)
    if events and highwater is not None and events[0][0] < highwater:
        raise ValueError("Llegaron eventos anteriores al último lote; falta gestión de eventos tardíos")

    recent001 = defaultdict(deque, {
        ip: deque(parse_time(t) for t in times)
        for ip, times in state["soc001_failures"].items()
    })
    recent002 = defaultdict(deque, {
        ip: deque(parse_time(t) for t in times)
        for ip, times in state["soc002_failures"].items()
    })
    last001 = {ip: parse_time(t) for ip, t in state["soc001_last_alert"].items()}
    counts = Counter()
    alerts = []

    for stamp, ip, kind in events:
        counts[kind] += 1
        for queue in (recent001[ip], recent002[ip]):
            while queue and stamp - queue[0] > WINDOW:
                queue.popleft()
        if kind in FAILURE_KINDS:
            recent001[ip].append(stamp)
            recent002[ip].append(stamp)
            last = last001.get(ip)
            if len(recent001[ip]) >= 5 and (last is None or stamp - last > WINDOW):
                alerts.append(make_alert("SOC-001", stamp, ip, len(recent001[ip])))
                last001[ip] = stamp
        elif kind == "autenticacion_correcta":
            if len(recent002[ip]) >= 2:
                alerts.append(make_alert("SOC-002", stamp, ip, len(recent002[ip])))
            recent002[ip].clear()
        highwater = stamp

    # Limitar el tamaño del contexto a los eventos todavía relevantes.
    if highwater is not None:
        for collection in (recent001, recent002):
            for ip, queue in list(collection.items()):
                while queue and highwater - queue[0] > WINDOW:
                    queue.popleft()
                if not queue:
                    del collection[ip]
        last001 = {ip: ts for ip, ts in last001.items() if highwater - ts <= WINDOW}

    next_state["soc001_failures"] = {
        ip: [t.isoformat() for t in q] for ip, q in recent001.items() if q
    }
    next_state["soc002_failures"] = {
        ip: [t.isoformat() for t in q] for ip, q in recent002.items() if q
    }
    next_state["soc001_last_alert"] = {ip: t.isoformat() for ip, t in last001.items()}
    next_state["last_event_timestamp"] = highwater.isoformat() if highwater else None
    alerts.sort(key=lambda alert: (alert["timestamp"], alert["rule_id"], alert["source_ip"]))
    return alerts, counts, next_state


def run_once(log_dir, state_path, output_path):
    log_dir, state_path, output_path = map(Path, (log_dir, state_path, output_path))
    if state_path == output_path:
        raise ValueError("El archivo de estado y el de alertas deben ser distintos")
    with exclusive_lock(state_path):
        if any(p.name.startswith("powerbeam.log") and p.name.endswith(".gz")
               for p in log_dir.iterdir()):
            raise ValueError("Hay archivos .gz: esta fase NO procesa históricos comprimidos")
        previous = read_checkpoint(state_path)
        lines, proposed = snapshot_raw(log_dir, previous["cursors"])
        alerts, counts, next_state = correlate(lines, previous)
        next_state["cursors"] = proposed

        # Orden crucial: escribir y sincronizar alertas ANTES de avanzar cursores.
        # Si hay fallo al guardar el checkpoint, el siguiente intento reanaliza
        # los eventos y append_unique evita repetir sus IDs.
        written = append_unique(alerts, output_path)
        if written:
            fd = os.open(output_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            sync_directory(output_path.parent)
        save_checkpoint(state_path, next_state)
        return {"lines": len(lines), "auth": sum(counts.values()),
                "soc001": sum(a["rule_id"] == "SOC-001" for a in alerts),
                "soc002": sum(a["rule_id"] == "SOC-002" for a in alerts),
                "written": written}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Demo SOC persistente (NO servicio de producción)")
    ap.add_argument("--log-dir", type=Path, required=True)
    ap.add_argument("--state", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        result = run_once(args.log_dir, args.state, args.output)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: estado NO confirmado: {exc}", file=sys.stderr)
        return 1
    print("=== POWERBEAM MONITOR — FASE 2 (EXPERIMENTAL) ===")
    print(f"Líneas nuevas completas: {result['lines']}")
    print(f"Eventos de autenticación nuevos: {result['auth']}")
    print(f"Alertas SOC-001 detectadas: {result['soc001']}")
    print(f"Alertas SOC-002 detectadas: {result['soc002']}")
    print(f"Alertas JSONL nuevas: {result['written']}")
    print(f"Estado y cursores: {args.state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
