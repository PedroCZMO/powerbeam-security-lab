# Día 7 · RES-005 — Protección contra ejecuciones simultáneas

**Proyecto:** PowerBeam Security Lab
**Fecha:** 03/11/2026
**Estado:** pruebas sobre `stateful_monitor_v3.py` **experimental**; sin cambios en el servicio systemd.

## Objetivo

Comprobar que dos procesos no avanzan simultáneamente un mismo checkpoint. Evitar que una ejecución tardía sobrescriba la información confirmada por otra ejecución.

## Mecanismo examinado

`stateful_monitor.exclusive_lock(state_path)` emplea `fcntl.flock(fd, LOCK_EX | LOCK_NB)` sobre `<ruta_del_estado>.lock`, conservando el descriptor abierto durante todo el análisis y la confirmación del estado. Si el archivo está bloqueado por otro proceso, la nueva ejecución falla con código `1` y el mensaje `Ya hay otra ejecución utilizando este estado`.

El bloqueo es **consultivo (advisory)**: protege a los procesos que respeten la misma convención y el mismo sistema de archivos, no evita que otros programas editen directamente los archivos. No se ha evaluado su funcionamiento en sistemas de ficheros distribuidos.

## Pruebas automatizadas

Archivo: `tests/test_res005_concurrencia.py` (3 casos).

1. Un proceso externo mantiene `state-v3.json.lock`; el monitor independiente rechaza ejecutar, no crea checkpoint, y reanuda después de liberar el bloqueo.
2. Con checkpoint ya existente y nuevos eventos pendientes, otro proceso mantiene el bloqueo: se rechaza el análisis y los bytes del checkpoint permanecen intactos. Una vez liberado, procesa correctamente SOC-002.
3. Dos procesos **reales de monitor** compiten por el mismo checkpoint: el primero se pausa de manera determinista mientras posee el bloqueo y el segundo es rechazado. Cuando se libera el primero, puede terminar y una ejecución posterior detecta cero líneas nuevas.

Todos los datos son ficticios (`192.0.2.0/24`) y se emplean carpetas temporales.

## Ejecución

```bash
python3 -m unittest discover -s tests -p 'test_res005_concurrencia.py' -v
```

**Resultado esperado:** 3 pruebas correctas. Las pruebas no necesitan privilegios de administrador ni usan el log real.

## Limitaciones

- El protocolo de exclusión depende de que todos los escritores usen el mismo archivo `.lock`.
- No se estudia la caída forzada de procesos en medio de la escritura ni la exclusión sobre recursos de red.
- No reemplazar ni reiniciar el servicio systemd actual para ejecutar estas pruebas.
