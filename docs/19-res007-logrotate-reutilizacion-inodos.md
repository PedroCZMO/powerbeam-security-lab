# Día 8 — RES-007: compatibilidad de V3 con rotaciones e inodos reutilizados

**Proyecto:** PowerBeam Security Lab
**Estado:** corrección experimental. No reemplaza aún a V1.

## Hallazgo

Durante una prueba aislada con `logrotate -f`, `rotate 14`, `compress`, `delaycompress` y `create 0640`, la primera rotación funcionó. En la segunda, Linux reutilizó para `powerbeam.log` el inodo de un histórico que acababa de comprimirse y desaparecer del directorio. La versión V3 anterior solo utilizaba `st_dev:st_ino` para identificar archivos sin comprimir; por tanto, trató el archivo nuevo como si fuera el anterior y devolvió `Truncado/copytruncate no soportado`. El checkpoint no se confirmó, pero V3 dejó de procesar registros.

## Cambio experimental

`scripts/gzip_reader_v3.py` contrasta el prefijo previamente confirmado (`offset` y SHA-256) del archivo actual antes de confiar en la identidad `st_dev:st_ino`. Si el inodo parece reutilizado, exige reconciliar el contenido anterior con un histórico gzip verificable. Solo después reinicia a cero el cursor del nuevo archivo (conservando el contexto SOC y evitando releer el histórico). Si no existe correspondencia verificable, falla de forma conservadora y no confirma un estado nuevo.

La estructura del checkpoint sigue siendo `version=3` para este cambio acotado, pero siempre se debe respaldar el estado antes de actualizar el código instalado. El cambio no promete resolver todas las carreras de sistema de archivos ni todas las pérdidas de logs, y **no** habilita `copytruncate`.

## Pruebas automatizadas

`tests/test_res007_inode_reuse.py` añade cuatro escenarios:

1. Inodo reutilizado con histórico gzip verificable y archivo nuevo vacío: no relee ni duplica.
2. Inodo reutilizado con nuevos eventos: mantiene la correlación SOC-002.
3. Inodo reutilizado sin histórico verificable: falla cerrado y conserva el checkpoint.
4. Dos rotaciones reales con `logrotate` + `delaycompress` en un directorio temporal, sin tocar `/var/log/powerbeam`.

Ejecutar desde la raíz del repositorio:

```bash
python3 -m unittest discover -s tests -p 'test_res007_inode_reuse.py' -v
python3 -m unittest discover -s tests -v
```

En el entorno de validación: 4 pruebas nuevas correctas y 78/78 en la suite completa.

## Implantación segura

1. Pausar el **temporizador experimental** V3; no modificar V1.
2. Incorporar los archivos al repositorio y ejecutar las pruebas.
3. Hacer una copia de respaldo del `state-v3.json` y de `alerts-v3.jsonl` actuales, con permisos restrictivos.
4. Instalar el lector corregido en `/opt/powerbeam-monitor-v3/scripts/` como root:root, modo `0644`.
5. Ejecutar una vez `powerbeam-monitor-v3.service` y comprobar el journal, el código de salida y los permisos.
6. Solo si todo funciona, reactivar el temporizador V3 y observar varias rotaciones sin desactivar V1.

## Limitaciones pendientes

- Eventos tardíos o cronológicamente desordenados pueden bloquear el checkpoint; no hay recuperación automática completa.
- Los cambios de contenido de archivos y algunas carreras concurrentes siguen siendo casos conservadores.
- La ausencia permanente de un histórico sin respaldo verificable necesita intervención y nunca debe solucionarse borrando checkpoints sin análisis.
- La corrección debe validarse en el Ubuntu de laboratorio antes de desplegarse como servicio automático.
