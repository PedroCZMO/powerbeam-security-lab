#!/usr/bin/env python3
"""Día 7 (EXPERIMENTAL): gzip con verificación de históricos desaparecidos.

No reemplazar el servicio systemd actual. Requiere un --state NUEVO (version=3).
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from stateful_monitor import (blank_state as v1_blank, correlate,
                              exclusive_lock, append_unique,
                              save_checkpoint, sync_directory)
from gzip_reader_v3 import snapshot

VERSION = 3


def blank_state():
    state = v1_blank()
    state.update(version=VERSION, raw_prefixes={}, gzip_seen={})
    return state


def read_checkpoint(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Estado symlink no admitido")
    if not path.exists():
        return blank_state()
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Estado corrupto") from exc
    if not isinstance(state, dict) or set(state) != set(blank_state()) or state.get("version") != VERSION:
        raise ValueError("Estado versión distinta/estructura inesperada. Usar estado NUEVO para v3")
    if not isinstance(state["cursors"], dict) or not isinstance(state["raw_prefixes"], dict) or not isinstance(state["gzip_seen"], dict):
        raise ValueError("Estructura de cursores inválida")
    for ident, offset in state["cursors"].items():
        if not re.fullmatch(r"\d+:\d+", ident) or type(offset) is not int or offset < 0:
            raise ValueError("Cursor inválido")
    for ident, meta in state["raw_prefixes"].items():
        if not isinstance(meta, dict) or set(meta) != {"offset", "sha256"} or ident not in state["cursors"]:
            raise ValueError("Prefijo raw inválido")
        if type(meta["offset"]) is not int or meta["offset"] != state["cursors"][ident]:
            raise ValueError("Prefijo raw con offset inválido")
        if not isinstance(meta["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", meta["sha256"]):
            raise ValueError("Hash de prefijo inválido")
    for archive_id, consumed in state["gzip_seen"].items():
        if not isinstance(archive_id, str) or not re.fullmatch(r"\d+:\d+:[a-f0-9]{64}", archive_id) or consumed is not True:
            raise ValueError("Identidad gzip inválida")
    from stateful_monitor import parse_time
    for key in ("soc001_failures", "soc002_failures"):
        if not isinstance(state[key], dict):
            raise ValueError("Contexto SOC inválido")
        for ip, timestamps in state[key].items():
            if not isinstance(ip, str) or not isinstance(timestamps, list):
                raise ValueError("Historial inválido")
            for stamp in timestamps:
                parse_time(stamp)
    if not isinstance(state["soc001_last_alert"], dict):
        raise ValueError("Alertas previas inválidas")
    for stamp in state["soc001_last_alert"].values():
        parse_time(stamp)
    if state["last_event_timestamp"] is not None:
        parse_time(state["last_event_timestamp"])
    return state


def run_once(log_dir, state_path, output_path):
    log_dir, state_path, output_path = map(Path, (log_dir, state_path, output_path))
    if state_path == output_path:
        raise ValueError("Estado y alertas deben ser diferentes")
    with exclusive_lock(state_path):
        previous = read_checkpoint(state_path)
        lines, cursors, prefixes, archived = snapshot(log_dir, previous)
        alerts, counts, next_state = correlate(lines, previous)
        next_state.update(cursors=cursors, raw_prefixes=prefixes, gzip_seen=archived)
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
    ap = argparse.ArgumentParser(description="Demo continuidad de logs (NO producción)")
    ap.add_argument("--log-dir", type=Path, required=True)
    ap.add_argument("--state", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        result = run_once(args.log_dir, args.state, args.output)
    except (OSError, ValueError, EOFError, RuntimeError) as exc:
        print(f"ERROR: estado NO confirmado: {exc}", file=sys.stderr)
        return 1
    print("=== POWERBEAM MONITOR — DÍA 7 (RES-003 EXPERIMENTAL) ===")
    print(f"Líneas nuevas: {result['lines']}")
    print(f"Eventos autenticación nuevos: {result['auth']}")
    print(f"Alertas SOC-001: {result['soc001']}")
    print(f"Alertas SOC-002: {result['soc002']}")
    print(f"Alertas JSONL nuevas: {result['written']}")
    print(f"Estado: {args.state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
