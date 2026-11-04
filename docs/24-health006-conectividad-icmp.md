# Día 9 · HEALTH-006 — Comprobación ICMP de conectividad con la antena

## Objetivo

Añadir una señal independiente de accesibilidad IP al `health_check.py` existente, sin modificar V1, V3, rsyslog, systemd, los registros ni sus checkpoints. La fase anterior HEALTH-005 inspecciona **cuándo Ubuntu recibió el último mensaje de syslog**, usando su timestamp de recepción, no el reloj interno de la antena.

Una respuesta ICMP no confirma que UDP 5514 esté entregando logs; una ausencia de respuesta ICMP tampoco confirma que la antena esté apagada. Puede existir filtrado ICMP, pérdida de paquetes o un problema de permisos de la herramienta `ping`.

## Comportamiento

- La comprobación ICMP está **desactivada por defecto**. Solo se ejecuta con `--check-antenna-icmp`.
- Usa la dirección IPv4 de `--source-ip` (por defecto `192.168.1.20`). Valida la dirección y ejecuta `ping` sin shell.
- Envía como máximo dos ecos: `ping -n -c 2 -W 2 -w 6 192.168.1.20`; el comando se detiene como máximo tras seis segundos y Python establece un tiempo límite de ocho segundos.
- Fija `LC_ALL=C` al subproceso para interpretar consistentemente las estadísticas de paquetes transmitidos y recibidos.
- **HEALTHY**: los dos paquetes recibieron respuesta.
- **WARNING**: cero respuestas (sin prueba de desconexión) o respuesta parcial (pérdida).
- **UNKNOWN**: comando ausente, permisos insuficientes, error de ejecución, timeout, IPv4 inválida o estadísticas incoherentes.

El JSON expone `checks.antenna_icmp` y `connectivity_status`. **Ni HEALTH-006 ni HEALTH-005 afectan a `overall_status`**, que sigue describiendo la infraestructura local. `ingestion_status` permanece `UNKNOWN` sin una señal fiable de heartbeat o de extremo a extremo. Las alertas SOC-001/SOC-002 son independientes.

## Comandos de validación en Ubuntu

Desde `powerbeam-security-lab`:

```bash
unzip -o ~/Descargas/powerbeam_dia9_health006.zip
python3 -m unittest discover -s tests -p 'test_antenna_icmp.py' -v
python3 -m unittest discover -s tests -q
```

Los archivos añadidos son `tests/test_antenna_icmp.py` y este documento; `scripts/health_check.py` es una actualización del script existente. En la revisión actual se esperan **15 pruebas nuevas** y **129 pruebas totales**.

Antes de instalar la copia del script, se puede guardar la anterior:

```bash
cp scripts/health_check.py /tmp/health_check-health006-repositorio.py
```

**Nota:** este comando debe ejecutarse *antes* de descomprimir el ZIP si se quiere preservar la versión anterior. Si ya se ha descomprimido, es posible utilizar la copia en `/opt/powerbeam-monitor-v3/scripts/health_check.py` como referencia.

Instalación solo de `health_check.py` (no se modifica ningún servicio systemd):

```bash
sudo install -o root -g root -m 0644 \
  scripts/health_check.py \
  /opt/powerbeam-monitor-v3/scripts/health_check.py
```

Ejecución puntual como usuario restringido:

```bash
sudo -u powerbeam-monitor /usr/bin/python3 -B \
  /opt/powerbeam-monitor-v3/scripts/health_check.py \
  --inspect-log-activity \
  --fresh-minutes 30 \
  --check-antenna-icmp
```

El resultado para una antena que responda será similar a:

```json
{
  "overall_status": "HEALTHY",
  "connectivity_status": "HEALTHY",
  "ingestion_status": "UNKNOWN",
  "checks": {
    "antenna_icmp": {
      "status": "HEALTHY",
      "packets_sent": 2,
      "packets_received": 2,
      "packet_loss_percent": 0.0
    }
  }
}
```

Es un **fragmento ilustrativo** del informe completo, no una captura de una ejecución real. El resultado puede ser `WARNING` o `UNKNOWN` según la red y los permisos de ICMP.

El código de salida actual se basa en `overall_status` y no se altera por el estado ICMP (0 si la infraestructura local está HEALTHY, 1 para WARNING/UNKNOWN local, 2 para CRITICAL local). Las alertas por ausencia de ping exigirían una política independiente y suficientemente conservadora.

## Escenarios de comprobación

| ICMP | Última recepción (HEALTH-005) | Conclusión admisible |
|---|---|---|
| HEALTHY | HEALTHY | Se observó respuesta ICMP y un syslog reciente. Sin certificación de recepción continua. |
| HEALTHY | WARNING | Antena alcanzable por ICMP, pero sin actividad syslog reciente. Investigar sin asumir avería. |
| WARNING | HEALTHY | Se recibió syslog recientemente, pero el ICMP actual no respondió o fue parcial. |
| WARNING | WARNING | Posible problema de conectividad o simplemente ICMP bloqueado y falta de eventos. |
| UNKNOWN | Cualquiera | No puede inferirse conectividad a partir de esta prueba. |

## Limitaciones de seguridad y alcance

- `ping` supone **tráfico de red activo**, aunque no escribe registros ni cambia la configuración de la antena.
- El sondeo es opcional para impedir que cada ejecución del Health Check genere tráfico inesperado.
- No hay servicios systemd nuevos ni tareas programadas en esta fase.
- Los tests sustituyen la ejecución de `ping` por dobles de prueba: no envían paquetes a ningún dispositivo.
- No publicar datos personales ni información sensible en ejemplos o capturas de GitHub.
- No habilitar avisos de incidente exclusivamente a partir de ICMP o de la falta de autenticaciones.
