# Día 11 — Fase 1: cola local de avisos SOC (sin correo todavía)

## Objetivo

Preparar una cola **persistente e idempotente** de alertas basada **solo** en el
archivo del monitor V1 (`alerts.jsonl`). V3 continúa siendo experimental y
podría generar la misma alerta, por lo que **no se usa** como segundo origen.

Esta fase **NO ENVÍA emails ni mensajes de red**. Antes de incorporar un canal
externo necesitamos probar la lectura, los permisos y la deduplicación.

## Archivos

- `scripts/alert_queue.py`: procesador de alertas y estado privado.
- `tests/test_alert_queue.py`: pruebas unitarias offline.

## Modos de ejecución

- `bootstrap`: registra los IDs históricos sin ponerlos en cola, para que no
  haya una avalancha de avisos al activar el sistema por primera vez.
  **No se puede ejecutar dos veces sobre el mismo archivo de estado.**
- `scan`: examina el JSONL de V1 y registra en cola únicamente IDs nuevos.
  Una segunda ejecución no vuelve a agregarlos.
- `status`: lee y muestra el estado y los elementos en cola; no envía nada.

Los tres modos utilizan `--source` y `--state`. No modifican el JSONL origen.
El estado se guarda de forma atómica en un único JSON (`seen_alert_ids` y
`pending` juntos), con bloqueo `flock`, permisos `0600` y carpeta privada
`0700` cuando es creada por el programa.

## Prueba local sin tocar la instalación

Desde la raíz del repositorio:

```bash
python3 -m unittest discover -s tests -p 'test_alert_queue.py' -v
python3 -m unittest discover -s tests -q
```

### Demostración opcional con eventos de ejemplo

```bash
DEMO=$(mktemp -d)
cat > "$DEMO/alerts.jsonl" <<'JSON'
{"alert_id":"SOC-002-demo-historica","rule_id":"SOC-002","severity":"medium","source_ip":"192.0.2.10","timestamp":"2026-11-04T11:00:00+01:00"}
JSON
python3 scripts/alert_queue.py bootstrap --source "$DEMO/alerts.jsonl" --state "$DEMO/private/state.json"
cat >> "$DEMO/alerts.jsonl" <<'JSON'
{"alert_id":"SOC-001-demo-nueva","rule_id":"SOC-001","severity":"medium","source_ip":"192.0.2.10","timestamp":"2026-11-04T11:01:00+01:00"}
JSON
python3 scripts/alert_queue.py scan --source "$DEMO/alerts.jsonl" --state "$DEMO/private/state.json"
python3 scripts/alert_queue.py scan --source "$DEMO/alerts.jsonl" --state "$DEMO/private/state.json"
python3 scripts/alert_queue.py status --source "$DEMO/alerts.jsonl" --state "$DEMO/private/state.json"
```

La primera ejecución `scan` registra una alerta. La segunda registra cero.

## Antes del despliegue real

**No instalar aún como servicio.** Comprobar el acceso a las alertas con el
usuario de mínimos privilegios:

```bash
sudo -u powerbeam-monitor test -r /var/lib/powerbeam-monitor/alerts.jsonl && echo 'V1 legible' || echo 'Revisar permisos'
sudo stat -c '%U:%G %a %n' /var/lib/powerbeam-monitor/alerts.jsonl
```

El directorio final de estado será distinto del de V1 y V3. Se preparará en una
fase posterior tras verificar permisos. En la primera inicialización en el
sistema real se usará `bootstrap`, para ignorar alertas ya investigadas.

## Limitaciones deliberadas

- **No envía notificaciones**: `pending` es una cola de preparación, no una
  bandeja de correo.
- **No tiene acuse de entrega** ni eliminación de elementos en cola. La fase de
  envío deberá implementar una política explícita de confirmación y reintentos;
  el correo no puede garantizar entrega exactamente una vez.
- Lee todo el fichero de alertas en cada pasada. Es adecuado para este
  laboratorio pequeño, no aún para un archivo de tamaño ilimitado.
- Una última línea JSONL incompleta se ignora hasta que se complete.
- Una línea completa malformada o un estado corrupto causan error sin actualizar
  el estado.
- Solo conserva los campos permitidos: `alert_id`, `rule_id`,
  `severity`, `source_ip`, `timestamp`. No almacena descripción ni mensajes
  originales ni credenciales.
- No ejecutar `bootstrap` para "arreglar" un estado corrupto: eso podría
  ocultar avisos pendientes. Primero diagnosticar.

## Fases siguientes

Validación con el usuario restringido y origen V1 real; automatización con
systemd; transporte de notificaciones a un canal elegido, credenciales fuera
del repositorio y protección contra reenvíos.
