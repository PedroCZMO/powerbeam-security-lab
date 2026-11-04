# Día 9 — HEALTH-004 (fase 2): disponibilidad del receptor syslog UDP

## Contexto de laboratorio

El 4 de noviembre de 2026 se confirmó la configuración de producción del
laboratorio en `/etc/rsyslog.d/30-powerbeam.conf`:

- Entrada `imudp` ligada a `192.168.1.10:5514`.
- `ruleset=PowerBeamRemote`.
- Filtrado por origen `192.168.1.20` (antena Ubiquiti PowerBeam).
- Destino `/var/log/powerbeam/powerbeam.log`.
- Formato con hora de recepción y mensaje original.

`ss -H -lunp` confirmó el socket UDP perteneciente a `rsyslogd` al ejecutar
la consulta con privilegios. Este puerto **no** es el UDP 514 genérico.

La prueba controlada de SOC-002 se completó con tres autenticaciones
(dos fallos y un éxito), recibidas y correlacionadas por V1 y V3. Ambas
produjeron el ID `SOC-002-2ad9ffcb5b5d0b58`. Este dato prueba recepción
puntual, no garantiza entrega continua.

## Qué incorpora el script

El Health Check consulta `ss -H -lun` sin `sudo` y añade el check `syslog_udp`
antes de calcular `overall_status`.

- **HEALTHY**: existe socket UDP local ligado exactamente a `192.168.1.10:5514`,
  sin detección simultánea de un enlace wildcard para el mismo puerto.
- **WARNING**: se observa un socket `0.0.0.0:5514`, `*:5514` o `[::]:5514`.
  Podría aceptar conexiones de redes no previstas o no garantizar la recepción
  IPv4 requerida. Se debe revisar la exposición real.
- **CRITICAL**: no hay socket UDP en la IP/puerto esperados, incluso si otro
  socket escucha el mismo puerto en `127.0.0.1` u otra dirección.
- **UNKNOWN**: no se pudo consultar `ss` (por ejemplo, el comando falla).

Los procesos de V1 y V3 siguen funcionando sin cambios. El script no envía
paquetes, no altera el firewall, no reinicia servicios y no modifica logs,
checkpoints ni alertas.

La consulta sin privilegios **no verifica qué proceso es propietario del
socket**. Se comprueba por separado que `rsyslog.service` esté activo, pero
eso no prueba que el socket concreto pertenezca a rsyslog. En una inspección
manual se puede confirmar mediante `sudo ss -lunp`.

## Diferencia entre salud del receptor y entrega de mensajes

Un socket disponible no garantiza que un dispositivo envíe syslog ni que las
reglas filtren/almacenen sus mensajes. Se mantiene el campo independiente:

```json
"ingestion_status": "UNKNOWN"
```

`overall_status=HEALTHY` significa que las comprobaciones operativas
configuradas pasan, **no** que exista ingestión continua.

## Instalación segura en el repositorio

Desde el repositorio, antes de descomprimir la fase 2:

```bash
cp scripts/health_check.py /tmp/powerbeam-health-check-fase1.py
cp tests/test_health_check.py /tmp/powerbeam-health-tests-fase1.py
unzip -o ~/Descargas/PowerBeam-Dia9-Fase2-UDP.zip
```

La fase 2 sustituye solo `scripts/health_check.py` y
`tests/test_health_check.py`, y añade `docs/22-health004-receptor-udp.md`.

## Verificación

```bash
python3 -m unittest discover -s tests -p 'test_health_check.py' -v
python3 -m unittest discover -s tests -q
python3 scripts/health_check.py
```

El paquete de fase 2 contiene **22 pruebas** del supervisor: 12 anteriores y
10 nuevas. Sumadas a las 78 pruebas previas del laboratorio, se esperan
**100 pruebas** si todos los ficheros anteriores siguen presentes.

Salida esperada en la máquina del laboratorio, si los timers y servicios
siguen sanos:

```json
"overall_status": "HEALTHY",
"ingestion_status": "UNKNOWN",
"checks": {
  "syslog_udp": {
    "status": "HEALTHY",
    "detail": "Socket UDP presente en 192.168.1.10:5514 (propietario y recepción no verificados)"
  }
}
```

La muestra es un fragmento ilustrativo, no la salida completa.

## Parámetros

```bash
python3 scripts/health_check.py --syslog-address 192.168.1.10 --syslog-port 5514
```

Se conservan `--max-age-minutes` y `--max-runtime-seconds` de la fase 1.
El código de salida sigue siendo 0/1/2 según el estado general.

## Próxima fase

Comprobar recepción efectiva sin generar falsas alarmas en periodos sin
actividad. Para verificar ingestión continua, implementar y probar un
heartbeat seguro desde el propio dispositivo o una señal equivalente que
pueda distinguirse de una inyección local hacia rsyslog. No modificar el
firmware ni las credenciales durante esta fase.
