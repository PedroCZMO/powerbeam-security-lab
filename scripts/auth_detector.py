#!/usr/bin/env python3
"""SOC-002: alertar por un inicio de sesión tras varios fallos desde una IP.

Lee eventos Syslog de PowerBeam desde la entrada estándar. No modifica logs.
Uso: sudo cat /var/log/powerbeam/powerbeam.log.1 /var/log/powerbeam/powerbeam.log | python3 scripts/auth_detector.py
"""

import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

WINDOW = timedelta(minutes=5)
FAILURE_THRESHOLD = 2
SOURCE_IP = re.compile(r"\bfrom (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_event(line):
    """Devuelve (fecha_recepcion, ip_origen, tipo) o None."""
    if "Login attempt for nonexistent user" in line:
        kind = "usuario_inexistente"
    elif "Bad password attempt" in line:
        kind = "contrasena_incorrecta"
    elif "Password auth succeeded" in line:
        kind = "autenticacion_correcta"
    else:
        return None

    match = SOURCE_IP.search(line)
    if match is None:
        return None

    try:
        received_at = datetime.fromisoformat(line.split(maxsplit=1)[0])
    except (ValueError, IndexError):
        return None
    if received_at.tzinfo is None:
        return None

    return received_at, match.group("ip"), kind


def detect(lines):
    """Devuelve (alertas, conteos) para reutilizar SOC-002 desde otros programas.

    Cada alerta es (fecha_recepcion, ip_cliente, fallos_previos).
    Mantiene el comportamiento del detector original: reinicia la secuencia
    de fallos de esa IP después de cada autenticación correcta.
    """
    events = [event for line in lines if (event := parse_event(line))]
    # Evitamos confiar en la hora interna del PowerBeam: usamos recepción en Ubuntu.
    events.sort(key=lambda item: item[0])

    counts = defaultdict(int)
    recent_failures = defaultdict(deque)
    alerts = []

    for received_at, ip, kind in events:
        counts[kind] += 1
        queue = recent_failures[ip]
        while queue and received_at - queue[0] > WINDOW:
            queue.popleft()

        if kind in ("usuario_inexistente", "contrasena_incorrecta"):
            queue.append(received_at)
        elif kind == "autenticacion_correcta":
            if len(queue) >= FAILURE_THRESHOLD:
                alerts.append((received_at, ip, len(queue)))
            queue.clear()

    return alerts, counts


def main():
    alerts, counts = detect(sys.stdin)
    for received_at, ip, failed in alerts:
        print(
            f"[SOC-002] POSIBLE ACCESO TRAS FALLOS | "
            f"{received_at.isoformat()} | origen={ip} | "
            f"fallos_previos={failed} | ventana=5m"
        )

    print("\n=== RESUMEN DE AUTENTICACIONES ===")
    print(f"Correctas: {counts['autenticacion_correcta']}")
    print(f"Contraseñas incorrectas: {counts['contrasena_incorrecta']}")
    print(f"Usuarios inexistentes: {counts['usuario_inexistente']}")
    print(f"Alertas SOC-002: {len(alerts)}")
    if alerts:
        print("Nota: una alerta requiere revisión; no demuestra un ataque.")


if __name__ == "__main__":
    main()
