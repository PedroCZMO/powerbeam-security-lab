#!/usr/bin/env python3
"""Lector experimental v3 con guardia frente a desaparición de logs raw.

No sustituye el servicio systemd. Abarca rename+create+delaycompress,
conserva cursores raw y reconoce archives por identidad+hash.
"""
import gzip
import hashlib
import os
import re
from pathlib import Path

RAW_RE = re.compile(r"^powerbeam\.log(?:\.[0-9]+)?$")
GZ_RE = re.compile(r"^powerbeam\.log\.[0-9]+\.gz$")
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024


def rank(p):
    """Más antiguo primero (sufijo mayor), actual al final."""
    name = p.name
    if name == "powerbeam.log":
        return (0, 0)
    suffix = int(name.split(".")[2])
    return (1, suffix)


def snapshot(log_dir, state):
    """Lee líneas nuevas completas, devuelve (líneas, cursores, raw_prefixes, gzip_seen).

    Recibe contexto propio de v2. Nunca muta el estado de entrada.
    """
    log_dir = Path(log_dir)
    entries = [p for p in log_dir.iterdir() if RAW_RE.fullmatch(p.name) or GZ_RE.fullmatch(p.name)]
    entries.sort(key=rank, reverse=True)
    raw_entries = [p for p in entries if RAW_RE.fullmatch(p.name)]
    live_raw_ids = set()
    reused_raw_ids = set()
    for path in raw_entries:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Archivo no regular/symlink: {path}")
        st = path.stat(follow_symlinks=False)
        ident = f"{st.st_dev}:{st.st_ino}"
        live_raw_ids.add(ident)
        # El SO puede reciclar un inodo después de comprimir/eliminar un
        # archivo antiguo. dev:ino deja de identificar unívocamente al
        # contenido ya confirmado: comprobar su prefijo antes de confiar.
        meta = state["raw_prefixes"].get(ident)
        if meta is not None:
            old_offset = meta["offset"]
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                with os.fdopen(fd, "rb", closefd=False) as f:
                    if (os.fstat(fd).st_size < old_offset or
                            hashlib.sha256(f.read(old_offset)).hexdigest() != meta["sha256"]):
                        reused_raw_ids.add(ident)
            finally:
                os.close(fd)

    cursors = dict(state["cursors"])
    prefixes = {key: dict(value) for key, value in state["raw_prefixes"].items()}
    archived = dict(state["gzip_seen"])
    lines = []
    reconciled_raw_ids = set()

    for path in entries:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Archivo no regular/symlink: {path}")
        if GZ_RE.fullmatch(path.name):
            # Abrimos sin seguir symlinks para reducir ventana de TOCTOU.
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                stat = os.fstat(fd)
                with os.fdopen(fd, "rb", closefd=False) as raw:
                    compressed = raw.read()
                import io
                with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as f:
                    data = f.read(MAX_DECOMPRESSED_BYTES + 1)
                if len(data) > MAX_DECOMPRESSED_BYTES:
                    raise ValueError(f"Descompresión fuera de límite: {path}")
            finally:
                os.close(fd)
            identity = f"{stat.st_dev}:{stat.st_ino}:{hashlib.sha256(compressed).hexdigest()}"
            if identity in archived:
                continue
            # Seleccionar entre cursores raw desaparecidos cuyo prefijo coincida.
            candidates = [(raw_id, meta["offset"]) for raw_id, meta in prefixes.items()
                          if (raw_id not in live_raw_ids or raw_id in reused_raw_ids)
                          and raw_id not in reconciled_raw_ids
                          and meta["offset"] > 0 and meta["offset"] <= len(data)
                          and hashlib.sha256(data[:meta["offset"]]).hexdigest() == meta["sha256"]]
            if len(candidates) > 1:
                raise ValueError(f"Emparejamiento gzip ambiguo: {path}")
            start = candidates[0][1] if candidates else 0
            remaining = data[start:]
            if remaining and not remaining.endswith(b"\n"):
                # No podemos esperar más datos de un archivo ya comprimido.
                raise ValueError(f"Gzip contiene línea final incompleta: {path}")
            lines.extend(remaining.decode("utf-8", errors="replace").splitlines(keepends=True))
            archived[identity] = True
            if candidates:
                reconciled_raw_ids.add(candidates[0][0])
        else:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                with os.fdopen(fd, "rb", closefd=False) as fh:
                    stat = os.fstat(fd)
                    ident = f"{stat.st_dev}:{stat.st_ino}"
                    # Un inodo reciclado solo se acepta si su histórico
                    # previo pudo reconciliarse verificando el gzip.
                    if ident in reused_raw_ids:
                        if ident not in reconciled_raw_ids:
                            raise ValueError(
                                f"RES-ROTACION: inodo reutilizado sin histórico verificable: {path}"
                            )
                        previous = 0
                    else:
                        previous = cursors.get(ident, 0)
                    if previous > stat.st_size:
                        raise ValueError(f"Truncado/copytruncate no soportado: {path}")
                    # Verificar integridad del contenido ya confirmado. Lectura <= maxsize habitual.
                    prefix = fh.read(previous)
                    old_fingerprint = None if ident in reused_raw_ids else prefixes.get(ident)
                    if old_fingerprint and hashlib.sha256(prefix).hexdigest() != old_fingerprint["sha256"]:
                        raise ValueError(f"El contenido ya leído ha cambiado: {path}")
                    chunk = fh.read()
                    last = chunk.rfind(b"\n")
                    consumed = chunk[: last + 1] if last >= 0 else b""
                    lines.extend(consumed.decode("utf-8", errors="replace").splitlines(keepends=True))
                    new_offset = previous + len(consumed)
                    cursors[ident] = new_offset
                    prefixes[ident] = {"offset": new_offset,
                                       "sha256": hashlib.sha256(prefix + consumed).hexdigest()}
            finally:
                os.close(fd)
    # RES-003: un raw previamente registrado no puede desaparecer sin
    # reconciliación verificable con el gzip de reemplazo. Podría contener
    # bytes nuevos nunca observados: no avanzar checkpoint silenciosamente.
    missing_ids = set(state["cursors"]) - live_raw_ids - reconciled_raw_ids
    if missing_ids:
        raise ValueError(
            "RES-003: posible pérdida de histórico no reconciliado "
            f"({', '.join(sorted(missing_ids))}). Restaurar el archivo o investigar "
            "la rotación antes de volver a procesar."
        )
    # Tras reconciliar un raw con un archivo comprimido ya no necesitamos
    # conservar su cursor: el gzip queda registrado por identidad y hash.
    for raw_id in reconciled_raw_ids:
        if raw_id not in reused_raw_ids:
            cursors.pop(raw_id, None)
            prefixes.pop(raw_id, None)
    return lines, cursors, prefixes, archived
