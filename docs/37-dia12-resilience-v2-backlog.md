# Día 12 — Fase 5: resiliencia V2 y gestión de alertas pendientes

**Propósito.** Integrar el estado *operativo* de las alertas SOC V1 en el informe
`resilience_report.py`, sin mezclar permisos y sin modificar la cola.

## Motivo de la integración por STDIN

- El token OAuth pertenece al usuario personal de Ubuntu y se guarda con modo `0600`.
- La cola SOC pertenece a `powerbeam-monitor` y se guarda con modo `0600`.
- No debe cambiarse el propietario de los secretos, bajar los permisos, ni ejecutar el informe completo como root.
- `alert_backlog_health.py` se ejecuta con el usuario restringido, lee su estado y devuelve **solo métricas agregadas**. El informe recibe ese JSON por STDIN, descarta cualquier campo no previsto y no lo escribe a disco.
- Por defecto, si no se solicita `--backlog-stdin`, el informe anterior sigue funcionando y marca `backlog_status=NOT_CHECKED`. `--online` sigue siendo optativo: el análisis de backlog no requiere red.

## Instalación local, sin tocar servicios

Desde la raíz del repositorio:

```bash
unzip -o ~/Descargas/PowerBeam_Dia12_Fase5_Resilience_V2.zip
python3 -m unittest discover -s tests -p 'test_resilience_backlog_integration.py' -v
python3 -m unittest discover -s tests -q
```

**Esperado:** 30 pruebas nuevas y un total de 368 pruebas si se parte de las 338 del día 12/fase 4. Algunas pruebas previas escriben mensajes de rechazo del CLI de Gmail; lo decisivo es que unittest finalice con `OK`.

## Verificación en vivo, sin tocar las alertas

Usar la versión instalada de `alert_backlog_health.py`, que tiene acceso al estado de la cola, y combinarla con el informe local que sí puede leer el token privado:

```bash
sudo -u powerbeam-monitor /usr/bin/python3 -B \
  /opt/powerbeam-monitor-v3/scripts/alert_backlog_health.py \
  --state /var/lib/powerbeam-monitor/alert-queue/state.json \
| python3 -B scripts/resilience_report.py \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json" \
  --backlog-stdin
```

*Si la cola contiene alertas `WARNING` o `CRITICAL`, el primer comando puede salir con código 1 o 2 a propósito. El JSON sigue siendo válido para el segundo programa.* Si el comando de la izquierda falla sin producir informe válido, la integración marca `backlog_status=UNKNOWN`, nunca `HEALTHY`.

Esperado cuando la cola está vacía y los servicios siguen correctos:

```json
{
  "detection_status": "HEALTHY",
  "alert_queue_status": "HEALTHY",
  "backlog_status": "HEALTHY",
  "alert_management_status": "HEALTHY",
  "alert_backlog": {
    "pending_total": 0,
    "seen_total": 2,
    "acknowledged_total": 0,
    "oldest_event_age_minutes": null,
    "age_basis": "EVENT_TIMESTAMP_NOT_QUEUE_ENTRY"
  },
  "notification_delivery": "NOT_AUTOMATED"
}
```

El programa devuelve más campos; este fragmento es ilustrativo. El informe no publica direcciones IP ni IDs de alertas. Si se omite `--backlog-stdin`, aparecerá `backlog_status=NOT_CHECKED`.

## Interpretación

| `detection_status` | `alert_queue_status` | `backlog_status` | Interpretación |
| --- | --- | --- | --- |
| HEALTHY | HEALTHY | HEALTHY | Servicios correctos y backlog dentro de política |
| HEALTHY | HEALTHY | WARNING | Servicios correctos, pero hay alertas pendientes retrasadas |
| HEALTHY | HEALTHY | CRITICAL | Servicios correctos, backlog crítico |
| HEALTHY | CRITICAL | HEALTHY | El proceso de cola requiere revisión, aunque el último estado leído parezca sano |
| HEALTHY | HEALTHY | UNKNOWN | No se pudo validar el resumen de backlog |

Los tiempos se calculan **desde la marca temporal del evento, no desde su entrada en cola**. Solo se analizan alertas V1. El estado de los servicios no garantiza ingestión de logs ni una notificación por correo: el envío automático sigue desactivado.

## Precauciones de seguridad

- Mantener `LEEME-PRIMERO.txt`, token OAuth y JSON de credenciales fuera de Git.
- No modificar `systemd`, `/opt`, scripts de detección ni el estado real durante esta fase.
- El informe valida esquema y contadores del JSON agregado, y no conserva campos adicionales.
- `UNKNOWN` significa que no tenemos evidencia suficiente para declarar la cola sana.
- No ejecutar `ack` ni `bootstrap` para efectuar esta comprobación.
