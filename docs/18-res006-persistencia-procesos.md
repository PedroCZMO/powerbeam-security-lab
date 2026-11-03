# Día 7 · RES-006 — Persistencia entre procesos independientes

**Proyecto:** PowerBeam Security Lab
**Fecha:** 03/11/2026
**Estado:** pruebas sobre `stateful_monitor_v3.py` **experimental**; no despliegue en systemd.

## Objetivo

Confirmar que el checkpoint mantiene el contexto necesario para correlacionar eventos SOC-002 en distintas ejecuciones del monitor; asimismo, comprobar que no se releen eventos ya confirmados ni se duplican alertas JSONL.

## Procedimiento de prueba automatizada

Archivo: `tests/test_res006_persistencia_procesos.py` (3 casos).

1. Se ejecuta el monitor en **procesos independientes**: primer fallo, segundo fallo, autenticación correcta y nueva ejecución sin eventos. La tercera ejecución genera una SOC-002 con dos fallos anteriores y la cuarta no duplica la alerta.
2. Se verifica que el estado `v3` escrito por un proceso puede abrirse por otro y mantiene `soc002_failures` en el checkpoint. Comprueba también permisos `0600` del estado.
3. Se verifica que un **checkpoint diferente** no hereda el contexto de otros archivos de estado; un éxito aislado no dispara SOC-002.

Todas las fuentes se construyen en `tempfile` y utilizan IP de documentación. Se ejecuta el CLI real en subprocessos Python, evitando mocks del estado persistente.

## Ejecución

```bash
python3 -m unittest discover -s tests -p 'test_res006_persistencia_procesos.py' -v
python3 -m unittest discover -s tests -v
```

**Resultado esperado:** 3 pruebas nuevas correctas; **74 en total** si también están presentes los seis archivos nuevos de RES-003 y RES-004 y los de RES-005/006.

## Limitaciones

- **No equivale a un reinicio real del sistema operativo**, a un corte de luz o a un fallo de almacenamiento. Se comprueba la persistencia entre procesos Python distintos.
- No garantiza exactamente una vez bajo todos los posibles fallos: el JSONL admite escritura parcial si el proceso se interrumpe durante la operación.
- La versión `v3` exige un checkpoint nuevo y todavía no está preparada para sustituir el servicio systemd estable.

## Estado de las pruebas del Día 7

- RES-001/002: detección de eventos temporalmente tardíos y checkpoint sin cambios al rechazar procesar (validación manual).
- RES-003: detección conservadora de históricos desaparecidos, recuperación al restaurar y siete pruebas nuevas.
- RES-004: cinco pruebas nuevas de inyección de fallos de escritura y reintento.
- RES-005: tres pruebas nuevas de concurrencia entre procesos.
- RES-006: tres pruebas nuevas de persistencia entre procesos; **reinicio real de Ubuntu pendiente**.

Ninguna de estas pruebas modifica el servicio `/opt/powerbeam-monitor/`.
