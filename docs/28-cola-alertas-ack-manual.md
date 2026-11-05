# Día 11 — Fase 5: reconocimiento manual auditable de alertas

## Objetivo

Añadir una operación `ack` **explícita, persistente y auditable** a la cola
existente del monitor V1. Esta fase NO envía notificaciones ni modifica
`alerts.jsonl`, los checkpoints de los monitores o los timers existentes.

## Compatibilidad

- Conserva `schema_version: 1`.
- Los estados ya inicializados por la fase 1 siguen siendo válidos.
- El campo `acknowledged` se crea al reconocer la primera alerta.
- `status` muestra `acknowledged` (conteo) además de `seen` y `pending`.
- La operación utiliza el mismo bloqueo (`flock`), validación de esquema y
  escritura atómica de estado de la fase 1.

## Semántica

`ack` retira **una** alerta de `pending` y añade al historial
`acknowledged`: `alert_id`, `reason` y `acknowledged_at` (UTC).

- `reviewed`: un analista la revisó manualmente y decidió darla por atendida;
  **NO** significa que se haya enviado un mensaje.
- `delivered`: **solo** debe usarse después de comprobar que el canal de
  salida aceptó la notificación. Ese canal se desarrollará más adelante.
  Tampoco prueba lectura del destinatario.

`ack` rechaza IDs desconocidos, históricos no pendientes y los ya reconocidos.
No permite reconocer varias alertas con una sola invocación.
Los IDs siguen en `seen_alert_ids`, por lo que `scan` no los reencola.

> Importante: esto no implementa entrega exactamente una vez. Una caída entre
> el envío externo y el `ack` posterior puede ocasionar reintentos duplicados.
> El transportador futuro requerirá un identificador estable y políticas
> explícitas de reintento y trazabilidad.

## Pruebas

```bash
python3 -m unittest discover -s tests -p 'test_alert_ack.py' -v
python3 -m unittest discover -s tests -q
```

## Ejemplo seguro en directorio temporal

```bash
bash <<'BASH'
set -euo pipefail
D="$(mktemp -d -t powerbeam-ack-demo-XXXXXX)"
trap 'rm -rf -- "$D"' EXIT
SRC="$D/alerts.jsonl"
STATE="$D/state.json"
cat > "$SRC" <<'JSON'
{"alert_id":"SOC-002-HIST-001","rule_id":"SOC-002","severity":"medium","source_ip":"192.0.2.10","timestamp":"2026-11-05T09:00:00+01:00"}
JSON
python3 -B scripts/alert_queue.py bootstrap --source "$SRC" --state "$STATE"
cat >> "$SRC" <<'JSON'
{"alert_id":"SOC-001-DEMO-001","rule_id":"SOC-001","severity":"high","source_ip":"192.0.2.11","timestamp":"2026-11-05T10:00:00+01:00"}
JSON
python3 -B scripts/alert_queue.py scan --source "$SRC" --state "$STATE"
python3 -B scripts/alert_queue.py ack --source "$SRC" --state "$STATE" --alert-id SOC-001-DEMO-001 --reason reviewed
python3 -B scripts/alert_queue.py status --source "$SRC" --state "$STATE"
python3 -B scripts/alert_queue.py scan --source "$SRC" --state "$STATE"
BASH
```

Esperado al final: `seen: 2`, `pending: 0`, `acknowledged: 1`;
la última ejecución de `scan` no reencola el ID.

## Puesta en producción

**Aún no ejecutar `ack` sobre el estado real.** Primero validar el ejemplo
temporal y los tests, después actualizar el script instalado conservando
sin modificaciones el estado existente de `/var/lib/powerbeam-monitor/alert-queue/state.json`.

No ejecutar `bootstrap` otra vez. No eliminar el estado para reinicializar.
No marcar `delivered` sin haber comprobado la aceptación por un canal externo.
