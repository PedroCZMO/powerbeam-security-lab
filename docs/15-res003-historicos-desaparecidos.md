# Día 7 · RES-003B — Histórico desaparecido con eventos pendientes

**Proyecto:** PowerBeam Security Lab
**Fecha:** 03/11/2026
**Estado:** Corrección experimental; **no reemplazar el servicio systemd actual**.

## Hallazgo reproducido

En una prueba controlada se registró un intento fallido a las 11:00. Después se añadió un segundo fallo (11:01) al mismo archivo, pero este se retiró del directorio monitorizado antes de que el lector pudiera procesar el segundo evento. El archivo nuevo contenía un éxito (11:02).

- `stateful_monitor_v2.py`: procesó el éxito, guardó un nuevo checkpoint y **no** generó SOC-002.
- Análisis por lotes con respaldo + archivo actual: reconoció **dos fallos seguidos de un éxito** y generó **una alerta SOC-002**.

Se trata de una **detección omitida por una discontinuidad de ingestión**. En este escenario sabemos que faltó un evento porque controlamos la simulación. En una instalación real no siempre se puede determinar qué eventos se perdieron.

## Corrección conservadora (experimental)

Se añaden dos archivos nuevos sin modificar los de las fases anteriores:

- `scripts/gzip_reader_v3.py`: comprueba las identidades raw guardadas en el checkpoint. Si una desaparece y no puede emparejarse con un archivo `.gz` cuyo prefijo confirmado tenga la misma huella SHA-256, produce error `RES-003` y no ofrece cursores nuevos.
- `scripts/stateful_monitor_v3.py`: utiliza exclusivamente un checkpoint nuevo de **versión 3**; escribe alertas antes del estado y hereda el bloqueo de ejecuciones simultáneas. No migra estados v1/v2.

Cuando un raw desaparecido **sí** está representado por un archivo gzip cuyo contenido empieza con el prefijo confirmado, el monitor recupera sus bytes pendientes y retira el cursor raw, conservando la identidad del gzip procesado. Así, eliminar posteriormente el gzip por la política de retención no bloquea el programa debido a ese cursor antiguo.

### Limitación intencionada

La ausencia de un archivo raw anteriormente visto **no demuestra por sí sola que haya datos perdidos**. La versión v3 se detiene de forma preventiva, incluso si ese archivo estaba completamente leído, cuando no existe una reconciliación verificable con gzip. Necesita intervención manual. Eso es preferible a confirmar silenciosamente un estado potencialmente incompleto, pero puede generar bloqueos ante eliminaciones legítimas o rotaciones anómalas.

No puede descubrir pérdidas de archivos que nunca vio, ni probar que no hubo eventos añadidos y borrados entre dos lecturas, ni resolver eventos recibidos fuera de orden; hay que mantener esta limitación documentada.

## Instalación local de pruebas

Descomprimir el paquete **en la raíz del repositorio**. Los tres archivos nuevos van a `scripts/` y `tests/`. **No cambiar `/opt/powerbeam-monitor`, el servicio ni el temporizador systemd.**

```bash
python3 -m unittest discover -s tests -v
```

Resultado esperado, si también están presentes los 56 tests de los días anteriores: **63 tests, OK**.

## Prueba manual RES-003B (aislada)

Usar un **directorio nuevo** y un checkpoint **v3 nuevo**; no copiar los estados utilizados en las fases anteriores. Desde la raíz del repositorio:

```bash
mkdir -p alerts/dia7-guardia/logs alerts/dia7-guardia/respaldo
chmod 700 alerts/dia7-guardia alerts/dia7-guardia/logs

cat > alerts/dia7-guardia/logs/powerbeam.log <<'LOG'
2026-11-03T11:00:00+01:00 source=192.0.2.20 httpd[100]: Bad password attempt for 'testuser' from 192.0.2.10
LOG

python3 scripts/stateful_monitor_v3.py \
  --log-dir alerts/dia7-guardia/logs \
  --state alerts/dia7-guardia/state-v3.json \
  --output alerts/dia7-guardia/alerts-v3.jsonl

cat >> alerts/dia7-guardia/logs/powerbeam.log <<'LOG'
2026-11-03T11:01:00+01:00 source=192.0.2.20 httpd[101]: Login attempt for nonexistent user from 192.0.2.10
LOG

mv alerts/dia7-guardia/logs/powerbeam.log \
   alerts/dia7-guardia/respaldo/powerbeam.log.1

cat > alerts/dia7-guardia/logs/powerbeam.log <<'LOG'
2026-11-03T11:02:00+01:00 source=192.0.2.20 httpd[102]: Password auth succeeded for 'testuser' from 192.0.2.10
LOG

sha256sum alerts/dia7-guardia/state-v3.json
python3 scripts/stateful_monitor_v3.py \
  --log-dir alerts/dia7-guardia/logs \
  --state alerts/dia7-guardia/state-v3.json \
  --output alerts/dia7-guardia/alerts-v3.jsonl
sha256sum alerts/dia7-guardia/state-v3.json
```

**Esperado:** error que contiene `RES-003` y código de salida distinto de cero; las huellas SHA-256 del checkpoint antes/después coinciden.

Recuperación:

```bash
mv alerts/dia7-guardia/respaldo/powerbeam.log.1 alerts/dia7-guardia/logs/
python3 scripts/stateful_monitor_v3.py \
  --log-dir alerts/dia7-guardia/logs \
  --state alerts/dia7-guardia/state-v3.json \
  --output alerts/dia7-guardia/alerts-v3.jsonl
```

**Esperado:** `Líneas nuevas: 2`, `Alertas SOC-002: 1`, `Alertas JSONL nuevas: 1`. Una tercera ejecución sin nuevos datos devuelve cero líneas y cero alertas nuevas.

## Pruebas automatizadas añadidas

`tests/test_res003_missing_history.py` añade siete casos: ausencia con checkpoint intacto, recuperación tras restauración, parada conservadora si el archivo estaba ya leído, rotación gzip válida con retención posterior, gzip no relacionado que no oculta pérdida, carga inicial gzip y rechazo de checkpoint v2.

## Trabajo pendiente

- Implementar tratamiento de eventos atrasados fuera de orden entre ejecuciones.
- Investigar qué hacer con pérdidas de fuentes no observadas y carreras entre lectura/rotación.
- Definir procedimiento de investigación/reparación y métricas de salud de la ingestión.
- Probar permisos ACL y rotaciones reales, con directorios y servicio de ensayo, antes de migrar `/opt` o systemd.
