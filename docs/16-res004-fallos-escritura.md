# Día 7 · RES-004 — Recuperación ante fallos de escritura

**Proyecto:** PowerBeam Security Lab
**Estado:** pruebas experimentales sobre `stateful_monitor_v3.py`; **no desplegado en systemd**.
**Fecha:** 03/11/2026.

## Objetivo

Verificar que los errores al guardar alertas o el checkpoint no provocan que el monitor confirme eventos que no pudo registrar correctamente. Comprobar además la deduplicación durante un reintento.

## Orden actual de las operaciones

1. Leer los registros y calcular las detecciones sin modificar el checkpoint.
2. Añadir las alertas nuevas al archivo JSONL y solicitar su sincronización (`fsync`).
3. Guardar el checkpoint de cursores y contexto mediante un archivo temporal y sustitución atómica.

Este orden favorece el **reprocesamiento tras fallos**. Si las alertas se escribieron pero falla el checkpoint, se repetirán los eventos: `alert_id` permite no duplicar esa alerta.

## Pruebas automatizadas nuevas

Archivo: `tests/test_res004_write_failure.py`.

- Fallo simulado al guardar el primer checkpoint **después** de escribir una alerta: la alerta permanece y el reintento no duplica.
- Fallo simulado al actualizar un checkpoint existente: sus bytes no cambian y el reintento reanaliza los eventos pendientes.
- Fallo simulado antes de añadir alertas: no avanza el checkpoint; un reintento normal incorpora la alerta.
- JSONL ya corrupto: el programa falla sin sobrescribirlo ni avanzar el checkpoint.
- Fallo simulado en la sincronización del directorio de alertas: se reintenta y la deduplicación evita una nueva entrada.

Ejecutar desde la raíz del repositorio:

```bash
python3 -m unittest discover -s tests -v
```

Si están los 63 tests anteriores, se esperan **68 tests en total**.

## Precauciones y límites

- Son **fallos inyectados con `unittest.mock`**, no desconexiones reales del disco ni pruebas de corte de corriente. Demuestran propiedades del flujo de control, no garantías absolutas de durabilidad del almacenamiento.
- `append_unique` escribe JSONL por adición y **no garantiza escritura atómica de una línea**. Una caída abrupta durante una escritura puede dejar una línea parcial: el parser la rechazará en el siguiente inicio y requerirá intervención. Este caso no queda resuelto por RES-004.
- El identificador estable evita duplicados para las mismas condiciones detectadas, pero no es una garantía de procesamiento exactamente una vez en todos los escenarios.
- La versión v3 aún rechaza eventos tardíos fuera de orden y necesita conciliación de históricos desaparecidos; no debe reemplazar al servicio systemd actual.
- No usar registros privados ni credenciales en las pruebas publicadas; las IP `192.0.2.0/24` son direcciones de ejemplo.

## Evidencia que debe adjuntarse

La salida local de `unittest` con los cinco casos nuevos correctos, más el total de pruebas de todo el repositorio. No publicar el contenido real de `/var/log/powerbeam/` ni archivos de estado/alertas.
