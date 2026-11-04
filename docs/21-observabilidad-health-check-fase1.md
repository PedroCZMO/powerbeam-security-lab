# Día 9 — Supervisión de salud del laboratorio (fase 1)

## Propósito

Comprobar el estado operativo de la infraestructura de PowerBeam Security Lab
sin modificar registros, alertas ni checkpoints. Este primer entregable es **una
herramienta manual de solo lectura**, no un servicio automático de alerta.

## Comprobaciones implementadas

- **HEALTH-001**: `rsyslog.service` activo.
- **HEALTH-002**: `powerbeam-monitor.timer` activo y último proceso V1 finalizado
  con éxito dentro de una ventana configurable.
- **HEALTH-003**: `powerbeam-monitor-v3.timer` activo y último proceso V3
  finalizado con éxito dentro de una ventana configurable.
- **HEALTH-004 (pendiente)**: ingestión continua de syslog. Se declara `UNKNOWN`
  porque el laboratorio no recibe todavía una señal periódica verificable
  (heartbeat) de la antena. Un archivo vacío puede ser normal tras `logrotate`.
- **HEALTH-005**: informe estructurado JSON imprimible por terminal.
- **HEALTH-006**: 12 nuevas pruebas automatizadas.

## Diseño y umbrales

`health_check.py` consulta `systemctl show` sin utilizar `shell=True`.
Los servicios V1/V3 son de tipo `oneshot`: el estado `inactive` tras una
finalización exitosa es normal. Para evitar falsos positivos, se distingue:

- `HEALTHY`: el servicio finalizó con código 0 y su ejecución es reciente.
- `WARNING`: el servicio está ejecutándose y su resultado aún es desconocido,
  no hay ejecución confirmada o falla la consulta de estado (en este último
  caso se emplea `UNKNOWN`).
- `CRITICAL`: servicio esencial inactivo, error del proceso, ejecución demasiado
  antigua o ejecución excesivamente prolongada.
- `UNKNOWN`: no se puede confirmar el estado (incluida la recepción de syslog).

Por defecto, la ejecución correcta no debe tener más de **15 minutos** de
antigüedad y un `oneshot` no debería estar ejecutándose más de **120 segundos**.
Estos umbrales son conservadores frente a temporizadores de aproximadamente
cinco minutos y pueden ajustarse por línea de comandos.

**Importante:** `overall_status` mide solamente los componentes supervisados;
**no certifica la conectividad de la antena ni la recepción de nuevos eventos**.
El resultado de ingestión se publica aparte como `ingestion_status=UNKNOWN`.

## Instalación local para pruebas

Desde la raíz del repositorio:

```bash
python3 -m unittest discover -s tests -p 'test_health_check.py' -v
python3 -m unittest discover -s tests -q
python3 scripts/health_check.py
```

Umbrales alternativos:

```bash
python3 scripts/health_check.py --max-age-minutes 20 --max-runtime-seconds 180
```

Código de salida: `0` si infraestructura `HEALTHY`, `1` si `WARNING` o
`UNKNOWN`, `2` si `CRITICAL`. La salida JSON es la fuente completa para
integraciones futuras.

## Interpretación del caso de referencia (4 de noviembre de 2026)

- `rsyslog` y ambos temporizadores estaban activos.
- V1 terminó correctamente a las 10:45 CET.
- V3 fue consultado durante una nueva ejecución: tenía marca de inicio,
  pero todavía no había marca de finalización. **`ExecMainStatus=0` en ese
  momento no demuestra que la ejecución en curso haya terminado bien.**
- `powerbeam.log` estaba vacío tras la rotación de las 10:12 CET; no es una
  señal concluyente de fallo de ingestión.
- La actualización del checkpoint a las 10:47 CET demuestra actividad del
  software, no recepción de un mensaje nuevo de la antena.

## Próximas etapas

1. Confirmar la ingestión con heartbeat o evento controlado y registro fiable
   del momento de recepción en el colector.
2. Documentar un despliegue de mínimo privilegio para health-check.
3. Programar ejecuciones periódicas y persistir métricas sin afectar V1/V3.
4. Añadir deduplicación y alertas ante fallos persistentes, con pruebas.

## Seguridad

- No altera archivos bajo `/var/log/powerbeam/`.
- No lee ni cambia los checkpoints V1/V3.
- No instala ni reinicia servicios.
- No requiere `sudo` para consultar propiedades de systemd en un entorno
  Ubuntu habitual. Si no puede consultar una unidad, lo indica como `UNKNOWN`.
- Los resultados de `systemctl show` dependen de la disponibilidad de systemd
  y deben verificarse en el equipo real antes de automatizar.
