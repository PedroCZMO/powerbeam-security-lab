#!/usr/bin/env python3
"""PowerBeam Security Monitor v1.0: integra SOC-001 y SOC-002 (modo batch).

Uso (desde la raíz del repositorio):
    cat registros_saneados.txt | python3 scripts/security_monitor.py
    cat registros_saneados.txt | python3 scripts/security_monitor.py --output alerts/alerts.jsonl

NO envía tráfico al PowerBeam. NO es monitorización continua.
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from auth_detector import detect as detect_soc002
from bruteforce_detector import detect as detect_soc001

RULES = {
    "SOC-001": ("medium", "Posibles intentos de fuerza bruta"),
    "SOC-002": ("medium", "Autenticación correcta tras varios fallos"),
}


def make_alert(rule_id, timestamp, source_ip, failures):
    """Alerta normalizada; su ID es determinista para deduplicar reejecuciones."""
    time_text = timestamp.isoformat()
    key = f"{rule_id}|{time_text}|{source_ip}".encode("utf-8")
    alert_id = f"{rule_id}-{hashlib.sha256(key).hexdigest()[:16]}"
    severity, description = RULES[rule_id]
    return {
        "alert_id": alert_id,
        "timestamp": time_text,
        "rule_id": rule_id,
        "severity": severity,
        "source_ip": source_ip,
        "failed_attempts": failures,
        "window_minutes": 5,
        "description": description,
    }


def analyze(lines):
    """Analiza todos los registros recibidos y devuelve alertas y resumen.

    Ambos detectores reutilizan sus funciones existentes. Entrada en memoria,
    orden temporal interno y sin estado persistente entre ejecuciones.
    """
    lines = list(lines)
    bruteforce_alerts, counts = detect_soc001(lines)
    access_alerts, _ = detect_soc002(lines)
    alerts = (
        [make_alert("SOC-001", ts, ip, n) for ts, ip, n in bruteforce_alerts]
        + [make_alert("SOC-002", ts, ip, n) for ts, ip, n in access_alerts]
    )
    alerts.sort(key=lambda alert: (alert["timestamp"], alert["rule_id"], alert["source_ip"]))
    return alerts, {
        "lines_read": len(lines),
        "auth_events": sum(counts.values()),
        "successful": counts["autenticacion_correcta"],
        "bad_password": counts["contrasena_incorrecta"],
        "unknown_user": counts["usuario_inexistente"],
        "SOC-001": len(bruteforce_alerts),
        "SOC-002": len(access_alerts),
    }


def append_unique(alerts, path):
    """Añade solo IDs nuevos a JSONL; no sobreescribe registros existentes.

    Válido para una instancia de laboratorio. No provee bloqueo entre procesos
    ni deduplicación global en escrituras concurrentes.
    """
    path = Path(path)
    existing_ids = set()
    if path.is_file():
        with path.open(encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"JSONL inválido en línea {lineno}: {exc}") from exc
                if not isinstance(record, dict) or not isinstance(record.get("alert_id"), str):
                    raise ValueError(f"Alerta JSONL sin alert_id válido en línea {lineno}")
                existing_ids.add(record["alert_id"])

    new_alerts = [alert for alert in alerts if alert["alert_id"] not in existing_ids]
    if new_alerts:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            for alert in new_alerts:
                handle.write(json.dumps(alert, ensure_ascii=False, sort_keys=True) + "\n")
    return len(new_alerts)


def main(argv=None):
    parser = argparse.ArgumentParser(description="PowerBeam Security Monitor (batch)")
    parser.add_argument("--output", type=Path, help="Ruta local donde añadir alertas JSONL")
    args = parser.parse_args(argv)

    lines = sys.stdin.readlines()
    if not lines:
        print("ERROR: no se recibieron registros en stdin; verifica la lectura y permisos.", file=sys.stderr)
        return 2

    alerts, counts = analyze(lines)
    print("=== POWERBEAM SECURITY MONITOR v1.0 ===")
    print(f"Líneas leídas: {counts['lines_read']}")
    print(f"Eventos de autenticación reconocidos: {counts['auth_events']}")
    print(f"Correctas: {counts['successful']}")
    print(f"Contraseñas incorrectas: {counts['bad_password']}")
    print(f"Usuarios inexistentes: {counts['unknown_user']}")
    print(f"Alertas SOC-001: {counts['SOC-001']}")
    print(f"Alertas SOC-002: {counts['SOC-002']}")
    for alert in alerts:
        print(
            f"[{alert['rule_id']}] {alert['timestamp']} "
            f"origen={alert['source_ip']} fallos={alert['failed_attempts']} "
            f"id={alert['alert_id']}"
        )
    if not counts["auth_events"]:
        print("ADVERTENCIA: no se reconocieron autenticaciones en las líneas recibidas.", file=sys.stderr)

    if args.output:
        try:
            written = append_unique(alerts, args.output)
        except (OSError, ValueError) as exc:
            print(f"ERROR al escribir alertas: {exc}", file=sys.stderr)
            return 1
        print(f"Alertas nuevas añadidas a {args.output}: {written}")
    print("Nota: una alerta requiere revisión; no constituye prueba de ataque.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
