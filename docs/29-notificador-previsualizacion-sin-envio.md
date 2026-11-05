# Día 11 · Fase 7 — Previsualización de notificaciones (sin envío)

## Propósito

Preparar el contenido de los avisos a partir de las alertas **pendientes**
de la cola V1, sin utilizar correo ni red. Es una fase de verificación antes
de conectar un proveedor SMTP. V3 no se procesa para evitar duplicados.

## Archivos nuevos

- `scripts/alert_notifier.py`
- `tests/test_alert_notifier.py`

Este paquete **no sobrescribe** el script `scripts/alert_queue.py`.

## Comando

```bash
python3 -B scripts/alert_notifier.py preview \
  --source /ruta/temporal/alerts.jsonl \
  --state /ruta/temporal/state.json
```

`--max-alerts 10` limita el número mostrado (entre 1 y 50). El comando
produce JSON con `pending_total`, `previewed`, `remaining`, `messages`,
`sent: 0`, `acknowledged: 0` y `dry_run: true`.

La operación lee el estado con el bloqueo de `alert_queue` y **no modifica**
el JSON de estado, `alerts.jsonl` ni los acuses. No requiere acceso al
archivo `--source`, aunque se acepta el argumento por compatibilidad.

## Verificación automática

```bash
python3 -m unittest discover -s tests -p 'test_alert_notifier.py' -v
python3 -m unittest discover -s tests -q
```

Resultado previsto de esta fase: 21 tests nuevos y 185 en total, si las
164 pruebas de la fase anterior permanecen presentes.

## Prueba real en modo lectura (opcional, tras test)

No instalar todavía como servicio: ejecutar desde una ruta que permita
acceso al usuario `powerbeam-monitor`, con copia instalada junto a
`alert_queue.py` y su estado real.

No hay canal SMTP, envío, entrega ni reintentos en esta fase. Una alerta
pendiente **no** implica un incidente confirmado.

## Siguientes fases

Definir el proveedor de correo y credenciales fuera del repositorio; probar
el canal con un servidor SMTP simulado; diseñar un registro de intentos de
envío y manejo de fallos antes de automatizar la entrega. Un servidor SMTP
que acepta el mensaje no garantiza que el destinatario lo lea ni que llegue
al buzón. El transporte deberá contemplar posibles duplicados si falla el
proceso entre enviar y registrar el acuse.
