# Día 12 · Fase 4 — Supervisión del backlog SOC (solo lectura)

## Objetivo

Medir las alertas **pendientes** de la cola persistente de V1 sin tocar los
registros originales ni sus acuses. El módulo consulta únicamente
`state.json` y genera un resumen agregado apto para observabilidad.

Archivo nuevo: `scripts/alert_backlog_health.py`.
Pruebas nuevas: `tests/test_alert_backlog_health.py` (32 casos).

## Política de laboratorio (ajustable)

| Condición | Resultado |
| --- | --- |
| Ninguna alerta pendiente | HEALTHY |
| Alertas pendientes recientes | HEALTHY (pendientes por revisar) |
| Una HIGH con fecha de evento >= 30 min | WARNING |
| Cualquier alerta con fecha de evento >= 60 min | WARNING |
| Cualquier alerta con fecha de evento >= 240 min | CRITICAL |
| Una alerta con severidad `critical`, de cualquier antigüedad | CRITICAL |
| Fecha de evento en el futuro más de 60 s | WARNING (salvo condición más grave) |

**Muy importante:** la edad se calcula desde `timestamp` del **evento**, no
desde cuándo entró en la cola. No se debe denominar “tiempo de espera” ni
utilizar estos umbrales como SLA corporativos. Para medir espera real haría
falta almacenar `queued_at` en el esquema de la cola en otra fase.

## Pruebas

```bash
python3 -m unittest discover -s tests -p 'test_alert_backlog_health.py' -v
python3 -m unittest discover -s tests -q
```

Con los 306 tests previos, se esperan **338 tests** en la batería completa.

## Uso local con estado simulado

```bash
python3 -B - <<'PY'
import sys
from datetime import datetime, timedelta, timezone
sys.path.insert(0, 'scripts')
import alert_backlog_health

now = datetime.now(timezone.utc)
for severity, minutes in [('medium', 5), ('high', 35), ('medium', 250)]:
    alert = {'alert_id': 'SOC-TEST-001', 'rule_id': 'SOC-001',
             'severity': severity, 'source_ip': '192.0.2.11',
             'timestamp': (now-timedelta(minutes=minutes)).isoformat()}
    state = {'schema_version': 1, 'seen_alert_ids': ['SOC-TEST-001'],
             'pending': [alert]}
    report = alert_backlog_health.evaluate(state, now=now)
    print(severity, minutes, report['operational_status'], report['status_reason'])
PY
```

Salida prevista: `HEALTHY`, `WARNING`, `CRITICAL`. No se crea ningún archivo.

## Comprobación de la cola real

El usuario `powerbeam-monitor` **no puede acceder al repositorio** ubicado en
`~/Escritorio`. No cambies permisos de tu carpeta personal.

Tras pasar las pruebas, instala *solo este script nuevo* junto a `alert_queue.py`:

```bash
sudo install -o root -g root -m 0644 \
  scripts/alert_backlog_health.py \
  /opt/powerbeam-monitor-v3/scripts/alert_backlog_health.py

sudo -u powerbeam-monitor /usr/bin/python3 -B \
  /opt/powerbeam-monitor-v3/scripts/alert_backlog_health.py \
  --state /var/lib/powerbeam-monitor/alert-queue/state.json
```

El resultado para `pending_total=0` será `operational_status=HEALTHY`,
`pending_by_severity` todo a cero y `oldest_event_age_minutes=null`.
No se envía correo, ni se crea lock, ni se marca alerta con `ack`.

## Códigos de salida

* `0`: HEALTHY.
* `1`: WARNING.
* `2`: CRITICAL o estado ilegible/corrupto (`UNKNOWN` + razón explícita).

Si más adelante se ejecuta mediante systemd, hay que decidir cómo representar
WARNING/CRITICAL sin interpretar automáticamente estos códigos de supervisión
como fallos de ejecución del servicio. **En esta fase no instalamos timer.**

## Limitaciones y seguridad

* Los estados se leen a través de la validación existente `alert_queue.py`.
* Se rechazan rutas finales que sean enlaces simbólicos; no se recomienda
  proporcionar rutas ajenas al estado previsto del laboratorio.
* La respuesta es agregada: no revela IPs ni identificadores individuales.
* Si el estado no es válido, el CLI no imprime el contenido del JSON ni las
  rutas privadas; genera `STATE_UNREADABLE_OR_INVALID`.
* El resumen solo comprueba los datos actualmente almacenados en la cola V1.
  No certifica la recepción de logs, la disponibilidad de Gmail, ni la revisión
  humana efectiva de las alertas.

## Siguiente fase

Integrar opcionalmente este informe dentro de `resilience_report.py` sin
mezclar el estado técnico de los servicios con el riesgo operativo del backlog.
