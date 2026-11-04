# Día 9 · HEALTH-005 — Última recepción observada de syslog

## Qué aporta

El monitor de salud ahora puede inspeccionar **opcionalmente**, y sin modificar nada, la
marca de tiempo de recepción escrita por el `rsyslog` de Ubuntu en
`/var/log/powerbeam/powerbeam.log` y sus históricos (`.1`, `.2.gz`, …, `.14.gz`).

El formato esperado es:

```text
2026-11-04T11:00:25.523253+01:00 source=192.168.1.20 <14>Nov  4 10:00:25 ...
```

**Utiliza únicamente `2026-11-04T11:00:25.523253+01:00`**, generado por Ubuntu. El
reloj de la antena puede estar desajustado y **no se utiliza**.

La comprobación `checks.log_activity` puede indicar:

- **HEALTHY:** existe evidencia de mensaje recibido en los últimos 30 minutos
  (umbral configurable). No confirma que el dispositivo esté conectado ahora.
- **WARNING:** la última evidencia es más antigua que el umbral. Puede ser
  inactividad normal: **no demuestra caída de la antena**.
- **UNKNOWN:** el usuario no tiene permisos, faltan registros, hay corrupción,
  la marca es incoherente, o la inspección no se ha activado.

La comprobación requiere `--inspect-log-activity`; por defecto, el supervisor
mantiene el comportamiento anterior y no intenta leer registros protegidos.

**`ingestion_status` permanece `UNKNOWN` sin heartbeat fiable**, aunque
`log_activity` diga `HEALTHY`.

**`overall_status` sigue evaluando únicamente servicios y socket UDP**:
una antena sin accesos durante horas no pone en CRITICAL a toda la infraestructura.

## Seguridad

- No envía tráfico de red ni realiza inicios de sesión.
- No cambia logs, alertas, checkpoints ni configuración de systemd.
- Abre ficheros con `O_NOFOLLOW` y verifica que sean ficheros regulares.
- Procesa como máximo el tramo final de 256 KiB de cada archivo; al abrir
  gzip establece límite de 12 MiB descomprimidos por archivo.
- No imprime líneas de autenticación ni contraseñas; solo hora de recepción
  y antigüedad.
- Los permisos de lectura existentes del usuario `powerbeam-monitor` son
  suficientes, si se conservan las ACL configuradas anteriormente.

## Prueba en Ubuntu

1. Desde el repositorio:

   ```bash
   python3 -m unittest discover -s tests -p 'test_log_activity.py' -v
   python3 -m unittest discover -s tests -q
   python3 scripts/health_check.py
   ```

2. Para probar la lectura protegida sin ejecutar código mutable del usuario
   como root, instalar **solo el nuevo supervisor** en la ruta experimental
   propiedad de root:

   ```bash
   sudo install -o root -g root -m 0644 scripts/health_check.py \
       /opt/powerbeam-monitor-v3/scripts/health_check.py
   ```

3. Ejecutar el supervisor como usuario restringido existente:

   ```bash
   sudo -u powerbeam-monitor /usr/bin/python3 \
       /opt/powerbeam-monitor-v3/scripts/health_check.py \
       --inspect-log-activity --fresh-minutes 30
   ```

Si aparece `UNKNOWN` por falta de permisos, verificar las ACL del directorio y
ficheros **sin otorgar lectura general a `/var/log`**. Si es `WARNING`,
comprobar la hora de la última recepción antes de asumir una avería.

No instalar temporizadores nuevos todavía. V1 y V3 siguen independientes.

## Limitaciones

- Una llegada observada recientemente no garantiza la continuidad de ingestión.
- Este chequeo no establece que `rsyslogd` sea dueño del socket UDP.
- Los registros pueden ser escasos cuando la antena está inactiva.
- Si el último mensaje queda fuera de los 256 KiB finales de un fichero con
  otros contenidos, el resultado puede ser `UNKNOWN`.
- Los ficheros gzip malformados o demasiado grandes hacen fallar la observación
  de forma conservadora.
- Para distinguir fallo real de silencio se necesita un heartbeat auténtico o
  una fuente independiente de telemetría.

## Pruebas nuevas

`tests/test_log_activity.py`: 14 pruebas aisladas de recepción reciente,
registro antiguo, fuente incorrecta, ficheros ausentes, rotados y comprimidos,
symlinks, gzip corrupto y sobredimensionado, marcas futuras, líneas incompletas,
permisos y separación entre estado operativo y observación de ingestión.
