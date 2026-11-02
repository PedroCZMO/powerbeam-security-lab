# Día 6 · Fase 2 — Persistencia de contexto SOC (prototipo)

**Proyecto:** PowerBeam Security Lab
**Componentes:** SOC-001 (5 fallos/5 min), SOC-002 (2 fallos seguidos de éxito/5 min)
**Estado:** prototipo aislado validado con registros de prueba; **NO desplegado en systemd**.

## Problema reproducido

Cuando los eventos se dividen en dos ejecuciones, `security_monitor.py` v1.0 procesa cada lote de forma independiente:

- Lote 1: contraseña incorrecta a las 21:00 y usuario inexistente a las 21:01 → SOC-002 = 0.
- Lote 2: acceso correcto a las 21:02 desde la misma IP → SOC-002 = 0.
- Lotes unidos → SOC-002 = 1.

Por tanto, un sistema realmente incremental debe conservar más que el offset de los ficheros: también debe guardar **el historial de fallos recientes y la ventana de deduplicación**.

## Diseño de `stateful_monitor.py`

- Reutiliza `incremental_reader.snapshot_raw` para obtener las líneas nuevas de los registros **sin comprimir**, incluyendo `.1`, `.2`, etc.
- Reutiliza `auth_detector.parse_event` para reconocer mensajes de autenticación.
- Mantiene por IP los fallos recientes independientes de SOC-001 y SOC-002 (ventana de 5 minutos).
- Mantiene el tiempo de la última alerta SOC-001 por IP para aplicar el periodo de enfriamiento.
- Genera las mismas alertas normalizadas que `security_monitor.make_alert` y usa `append_unique` para evitar duplicados por ID.
- Guarda cursores y contexto de detección **en un mismo fichero de estado**, mediante reemplazo atómico; permisos `0600`.
- Serializa las ejecuciones que comparten un estado mediante `flock`.

### Orden de confirmación (recuperación ante errores)

1. Leer el checkpoint anterior; preparar las líneas y los nuevos cursores sin guardarlos aún.
2. Correlacionar las líneas con el contexto conservado.
3. Añadir las alertas no existentes y sincronizar el fichero JSONL con `fsync`.
4. Confirmar con reemplazo atómico el checkpoint con **cursores + contexto**.

Si falla el paso 4 tras escribir una alerta, se repetirán los eventos al reintentar. El identificador determinista impide duplicar la alerta en JSONL. **No es una transacción exactamente-una-vez**; la secuencia propuesta proporciona recuperación mediante reprocesamiento en este laboratorio.

## Prueba manual reproducible, sin root

**Ejecutar en la raíz del repositorio.** Estos comandos no tocan los registros reales ni el servicio activo.

```bash
mkdir -p alerts/demo-persistente/logs
chmod 700 alerts/demo-persistente
cp alerts/demo-lote1.log alerts/demo-persistente/logs/powerbeam.log

python3 scripts/stateful_monitor.py \
  --log-dir alerts/demo-persistente/logs \
  --state alerts/demo-persistente/state.json \
  --output alerts/demo-persistente/alerts.jsonl

cat alerts/demo-lote2.log >> alerts/demo-persistente/logs/powerbeam.log

python3 scripts/stateful_monitor.py \
  --log-dir alerts/demo-persistente/logs \
  --state alerts/demo-persistente/state.json \
  --output alerts/demo-persistente/alerts.jsonl

# Repetir una tercera vez: no debe añadir nada ni releer registros.
python3 scripts/stateful_monitor.py \
  --log-dir alerts/demo-persistente/logs \
  --state alerts/demo-persistente/state.json \
  --output alerts/demo-persistente/alerts.jsonl
```

Se espera una alerta SOC-002 en la segunda ejecución; primera y tercera sin alertas nuevas.

```bash
python3 -m unittest discover -s tests -v
```

**Pruebas locales:** 44/44 en la versión preparada (32 previas + 12 nuevas), pendiente de validación en Ubuntu del autor.

## Limitaciones antes de pasar a producción

1. **Históricos `.gz`:** no son compatibles. El prototipo rechaza el directorio si detecta alguno, en lugar de ignorarlo silenciosamente. El entorno PowerBeam real ya tiene históricos comprimidos; **no ejecutar este prototipo contra `/var/log/powerbeam`**.
2. **Eventos tardíos:** las marcas temporales de recepción deben ser monótonas entre ejecuciones. Un evento nuevo anterior al último procesado bloquea el avance del cursor. Se necesita una estrategia de reordenamiento para producción.
3. **Identidad de archivo:** `snapshot_raw` usa dispositivo/inodo y tamaño. Falta un tratamiento exhaustivo de sustitución, reutilización de inodos, escrituras concurrentes, rotaciones y pérdidas de históricos.
4. **Crash recovery:** usa reintentos y deduplicación por ID, no una transacción ACID entre JSONL y el checkpoint.
5. **Observabilidad:** todavía no hay métricas de retraso, alarmas por falta de registros ni supervisión de eventos perdidos.
6. **Despliegue:** no modificar `/opt/powerbeam-monitor/`, `powerbeam-monitor.service` ni `powerbeam-monitor.timer` en esta fase. El sistema desplegado mantiene el modo batch probado.

## Próximo paso

Extender el lector a `logrotate` y ficheros `.gz`, ensayar eventos tardíos y rotaciones con líneas pendientes, y solo después planificar la migración controlada del servicio `systemd`.
