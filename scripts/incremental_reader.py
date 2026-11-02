#!/usr/bin/env python3
"""Día 6, fase 1: lector incremental experimental para logs PowerBeam.

Solo lee archivos sin comprimir powerbeam.log y powerbeam.log.N (N entero).
NO está conectado al monitor SOC ni al temporizador systemd.

Uso de prueba:
  python3 scripts/incremental_reader.py --log-dir ./logs --state ./alerts/preview-state.json
  python3 scripts/incremental_reader.py --log-dir ./logs --state ./alerts/preview-state.json --commit

Importante: --commit guarda offsets de una lectura de prueba; NO equivale a
procesamiento transaccional por los detectores. Nunca utilices el estado de
prueba para el monitor productivo.
"""
import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

STATE_VERSION = 1
RAW_PATTERN = re.compile(r"^powerbeam\.log(?:\.[0-9]+)?$")


def read_state(path):
    """Devuelve mapa de cursores de inodos; falla cerrado ante corrupción."""
    if not Path(path).exists():
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        raise ValueError("Versión de estado desconocida o estructura inválida")
    cursors = data.get("cursors")
    if not isinstance(cursors, dict):
        raise ValueError("Estado sin cursores válidos")
    for key, offset in cursors.items():
        if not isinstance(key, str) or not re.fullmatch(r"\d+:\d+", key):
            raise ValueError("Identificador de inode inválido")
        if type(offset) is not int or offset < 0:
            raise ValueError("Offset inválido en el estado")
    return cursors


def snapshot_raw(log_dir, cursors):
    """Lee solo líneas terminadas en LF y devuelve (líneas, cursores_propuestos).

    Los cursores NO se guardan aquí. Esto permitirá que en fases posteriores
    el commit se haga solo DESPUÉS de procesar y almacenar las alertas.
    """
    log_dir = Path(log_dir)
    entries = [p for p in log_dir.iterdir() if RAW_PATTERN.fullmatch(p.name)]
    # Ordenamos rotados antiguos primero para ayudar al procesador por lotes.
    def rank(p):
        if p.name == "powerbeam.log":
            return (1, 0)
        return (0, -int(p.name.rsplit(".", 1)[-1]))
    entries.sort(key=rank)
    proposed = dict(cursors)
    lines = []
    for path in entries:
        # No seguir enlaces: evitamos rutas arbitrarias por symlink.
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Archivo no regular o enlace simbólico: {path}")
        with path.open("rb") as fh:
            stat = os.fstat(fh.fileno())
            ident = f"{stat.st_dev}:{stat.st_ino}"
            previous = proposed.get(ident, 0)
            # Protección ante truncado. Con rename+create el inode suele cambiar.
            start = previous if previous <= stat.st_size else 0
            fh.seek(start)
            chunk = fh.read()
            # No consumir el fragmento final si no termina en LF; podrá
            # completarse con bytes nuevos durante la siguiente ejecución.
            final_newline = chunk.rfind(b"\n")
            if final_newline < 0:
                proposed[ident] = start
                continue
            complete = chunk[: final_newline + 1]
            lines.extend(complete.decode("utf-8", errors="replace").splitlines(keepends=True))
            proposed[ident] = start + len(complete)
    return lines, proposed


def save_state(path, cursors):
    """Escritura atómica de estado, permisos 0600; llamada solo tras éxito."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmpname = tempfile.mkstemp(prefix=".powerbeam-state-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump({"version": STATE_VERSION, "cursors": cursors}, file, sort_keys=True)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.chmod(tmpname, 0o600)
        os.replace(tmpname, path)
    finally:
        if os.path.exists(tmpname):
            os.unlink(tmpname)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Vista previa de lectura incremental (NO producción)")
    ap.add_argument("--log-dir", required=True, type=Path)
    ap.add_argument("--state", required=True, type=Path)
    ap.add_argument("--commit", action="store_true", help="Guardar cursores solo para la demostración")
    args = ap.parse_args(argv)
    try:
        before = read_state(args.state)
        lines, after = snapshot_raw(args.log_dir, before)
        archives = sum(1 for p in args.log_dir.iterdir() if p.name.startswith("powerbeam.log") and p.name.endswith(".gz"))
        print(f"Líneas nuevas completas (sin comprimir): {len(lines)}")
        print(f"Archivos gzip históricos omitidos por esta versión: {archives}")
        if args.commit:
            save_state(args.state, after)
            print(f"Cursores de PRUEBA guardados en: {args.state}")
        else:
            print("Vista previa: no se guardó ningún estado (sin --commit).")
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"ERROR: no se confirmó el estado: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
