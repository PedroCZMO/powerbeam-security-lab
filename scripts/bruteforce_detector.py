#!/usr/bin/env python3
"""SOC-001: detectar varios fallos de autenticación por IP en cinco minutos.

Uso desde la raíz del repositorio:
    sudo cat /var/log/powerbeam/powerbeam.log.1 \
      /var/log/powerbeam/powerbeam.log | python3 scripts/bruteforce_detector.py

No altera logs ni envía tráfico al PowerBeam. Reutiliza el parser SOC-002.
"""

import sys
from collections import defaultdict, deque
from datetime import timedelta

from auth_detector import parse_event

WINDOW = timedelta(minutes=5)
FAILURE_THRESHOLD = 5
FAILURE_KINDS = {"usuario_inexistente", "contrasena_incorrecta"}


def detect(lines):
    """Devuelve alertas y conteos; cada IP tiene un enfriamiento de cinco minutos.

    La ventana usa la fecha/hora de recepción del syslog en Ubuntu.
    El detector procesa el lote completo (no lectura en tiempo real).
    """
    events = [evt for line in lines if (evt := parse_event(line))]
    events.sort(key=lambda evt: evt[0])

    counts = defaultdict(int)
    recent_failures = defaultdict(deque)
    last_alert = {}
    alerts = []

    for timestamp, ip, kind in events:
        counts[kind] += 1
        if kind not in FAILURE_KINDS:
            continue
        window = recent_failures[ip]
        while window and timestamp - window[0] > WINDOW:
            window.popleft()
        window.append(timestamp)
        if len(window) < FAILURE_THRESHOLD:
            continue
        # Limita alertas repetidas de una misma IP durante cinco minutos.
        last = last_alert.get(ip)
        if last is None or timestamp - last > WINDOW:
            alerts.append((timestamp, ip, len(window)))
            last_alert[ip] = timestamp

    return alerts, counts


def main():
    alerts, counts = detect(sys.stdin)
    for timestamp, ip, failures in alerts:
        print(
            f"[SOC-001] POSIBLE FUERZA BRUTA | {timestamp.isoformat()} "
            f"| origen={ip} | fallos_5m={failures} | umbral={FAILURE_THRESHOLD}"
        )
    print("\n=== RESUMEN SOC-001 ===")
    print(f"Contraseñas incorrectas: {counts['contrasena_incorrecta']}")
    print(f"Usuarios inexistentes: {counts['usuario_inexistente']}")
    print(f"Autenticaciones correctas: {counts['autenticacion_correcta']}")
    print(f"Alertas SOC-001: {len(alerts)}")
    print("Nota: una alerta es una hipótesis de detección, no una prueba de ataque.")


if __name__ == "__main__":
    main()
