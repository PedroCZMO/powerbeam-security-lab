# Día 6 · Fase 3 — Archivos comprimidos y rotación (prototipo)

**Proyecto:** PowerBeam Security Lab
**Estado:** Experimental; no sustituye el servicio `powerbeam-monitor.service`.

## Problema

`logrotate` utiliza `daily`, `rotate 14`, `maxsize 10M`, `compress`, `delaycompress`, `create 0640` y `postrotate` con HUP a rsyslog. Los históricos pueden pasar de `powerbeam.log.1` a `powerbeam.log.2.gz`. La compresión crea otro archivo/inodo: identificar cada archivo solo por su nombre o inodo puede provocar reprocesamiento de líneas, mientras que ignorar gzip puede perder eventos aún pendientes.

## Implementación experimental

- `scripts/gzip_reader.py`: lee `powerbeam.log`, `powerbeam.log.N` y `powerbeam.log.N.gz`, con orden de más antiguo a más reciente.
- `scripts/stateful_monitor_v2.py`: utiliza una versión **2** de checkpoint exclusiva de este prototipo y reutiliza la correlación SOC-001/SOC-002 del Día 6.
- Un prefijo leído de un archivo sin comprimir se registra con longitud y SHA-256. Si aparece comprimido, se comprueba que el contenido gzip comienza por el prefijo consumido antes de leer el resto.
- Los archivos `.gz` ya reconocidos se identifican por dispositivo, inodo y hash SHA-256 de su contenido comprimido para evitar lecturas duplicadas tras renombrados.
- El sistema falla sin avanzar el checkpoint si detecta gzip dañado, línea final incompleta en un gzip, truncado/alteración de un archivo raw, estado incompatible o eventos anteriores a la marca temporal ya confirmada.
- Las alertas se sincronizan antes de confirmar el checkpoint. La deduplicación de IDs evita repetir una alerta después de reintentar una ejecución.
- Limita los bytes descomprimidos por gzip a 64 MiB para evitar consumo excesivo de memoria.

## Restricciones y riesgos conocidos

1. **No poner aún en producción.** Solo se ha probado con archivos sintéticos y no se ha sustituido systemd.
2. Un evento tardío (marca de recepción anterior al último procesado) detiene el proceso a propósito; falta política de reordenación y tolerancia a retrasos.
3. Si desaparece un archivo antes de que el lector lo vea (por retención, apagado prolongado o rotación), no podemos garantizar recuperación. Se necesita una verificación adicional de archivos perdidos y retención.
4. El checkpoint crece con las identidades de archivos; hace falta gestión de caducidad segura y comprobaciones de posibles reutilizaciones de inodos.
5. El reconocimiento por hash es experimental: cambios de contenido, duplicidad de prefijos, `copytruncate` o rotaciones anómalas requieren más pruebas. Los eventos pueden quedar pendientes si no se logra vincular una compresión al archivo anterior.
6. Hay que validar las ACL efectivas de los archivos comprimidos, las ejecuciones concurrentes y los reinicios reales, así como el rendimiento con archivos grandes.
7. No garantiza entrega *exactly once* del Journal (puede volver a mostrarse una alerta); sí se evita duplicarla en el JSONL bajo los casos probados.
8. **No reutilizar** `alerts/demo-persistente/state.json` de la fase 2. El estado v2 no es compatible con v1 y debe guardarse en otro fichero independiente.

## Pruebas

```bash
python3 -m unittest discover -s tests -v
```

Las 12 pruebas nuevas comprueban: lectura inicial de gzip, deduplicación, compresión tras haber consumido prefijos, eventos añadidos al antiguo archivo antes de su compresión, renombrado `.gz`, corrupción, líneas incompletas, truncado, cambios de contenido, incompatibilidad v1/v2, eventos tardíos, permisos 0600 y recuperación tras fallo del checkpoint.

**Total con el paquete del Día 6:** 56 pruebas (44 previas + 12 nuevas).

## Verificación manual aislada

Trabajar siempre en `alerts/demo-gzip-v2/`. No ejecutar contra `/var/log/powerbeam/` todavía.

```bash
mkdir -p alerts/demo-gzip-v2/logs
chmod 700 alerts/demo-gzip-v2 alerts/demo-gzip-v2/logs
```

Crear dos intentos fallidos sintéticos en `alerts/demo-gzip-v2/logs/powerbeam.log`, ejecutar `stateful_monitor_v2.py` con `--state alerts/demo-gzip-v2/state-v2.json` y `--output alerts/demo-gzip-v2/alerts-v2.jsonl`. Esperar dos líneas procesadas, cero alertas. Después, renombrar el archivo a `.1`, **crear enseguida un nuevo `powerbeam.log` (como hace logrotate)**, añadir un éxito al antiguo `.1`, comprimirlo como `.2.gz`, borrar el `.1` y ejecutar otra vez: el monitor debe leer el nuevo éxito sin duplicar los dos fallos anteriores y generar SOC-002.

## Próximos hitos

- Detectar pérdidas de archivos y comprobación de retención.
- Resolver eventos tardíos y reordenación entre lotes.
- Probar con ACL reales y cronología de rotación de rsyslog.
- Revisar la persistencia y el bloqueo con la versión previa del servicio.
- Solo después preparar migración controlada a `/opt` y `systemd`.
