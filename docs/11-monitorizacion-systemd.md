# Día 5 — Ejecución automatizada de PowerBeam Security Monitor

**Fecha:** 1 de noviembre de 2026

**Proyecto:** PowerBeam Security Lab

**Componente:** PowerBeam Security Monitor v1.1 (automatización de la v1.0)

**Estado:** primera ejecución automática comprobada; pendiente de validar rotaciones futuras y lectura incremental.

## Objetivo

Automatizar el análisis periódico de los registros Syslog procedentes de un Ubiquiti PowerBeam mediante `systemd`, ejecutando el monitor con una **cuenta de servicio no privilegiada** y almacenando las alertas en un archivo JSONL protegido.

El monitor ejecuta dos casos de uso:

- **SOC-001:** cinco o más intentos fallidos de autenticación desde una misma IP durante cinco minutos.
- **SOC-002:** una autenticación correcta precedida de dos o más intentos fallidos desde la misma IP durante cinco minutos.

La clasificación se realiza sobre registros recibidos por rsyslog. Las marcas temporales de recepción de Ubuntu se utilizan en la correlación; se detectaron desfases en el reloj del dispositivo.

## Arquitectura

```text
Ubiquiti PowerBeam
      |
      | Syslog
      v
   rsyslog
      |
      v
/var/log/powerbeam/powerbeam.log (+ históricos rotados)
      |
      | ACL: solo lectura
      v
powerbeam-monitor (usuario de sistema)
      |
      v
/opt/powerbeam-monitor/scripts/run_monitor.sh
      |
      v
security_monitor.py -> SOC-001 + SOC-002
      |
      v
/var/lib/powerbeam-monitor/alerts.jsonl

powerbeam-monitor.timer -> powerbeam-monitor.service (cada 5 minutos)
```

## Seguridad: mínimo privilegio

- Cuenta de servicio: `powerbeam-monitor`, sin inicio de sesión interactivo.
- La cuenta tiene ACL `r-x` sobre `/var/log/powerbeam/` y `r--` sobre `powerbeam.log`. Se comprobó apertura real del archivo y denegación de escritura.
- Código instalado en `/opt/powerbeam-monitor/scripts/`, propiedad de `root:root` y legible por la cuenta de servicio.
- Alertas en `/var/lib/powerbeam-monitor/`, directorio privado de la cuenta de servicio (modo `700`); JSONL con permisos restrictivos.
- Unidad `systemd` con `User=`, `Group=`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `UMask=0077` y `StateDirectory=powerbeam-monitor`.
- Los archivos de alerta **no deben publicarse**: pueden contener IP y horarios. Los datos reales permanecen fuera de GitHub.

## Componentes de despliegue

Se mantienen bajo control de versiones:

```text
scripts/run_monitor.sh
systemd/powerbeam-monitor.service
systemd/powerbeam-monitor.timer
```

El servicio es `Type=oneshot`: analiza un lote y termina. El temporizador contiene:

```ini
[Timer]
OnCalendar=*:0/5
AccuracySec=30s
Persistent=true
Unit=powerbeam-monitor.service
```

`Persistent=true` puede recuperar una ejecución perdida al reactivar el temporizador; **no ejecuta una vez por cada intervalo omitido**.

La instalación en `/opt` y `/etc/systemd/system/` requiere una cuenta administradora. El análisis posterior se ejecuta sin privilegios de root.

## Evidencias verificadas el 01/11/2026

### Ejecución manual como usuario de servicio

El análisis de los registros existentes devolvió:

| Métrica | Resultado |
|---|---:|
| Líneas leídas | 18 |
| Eventos de autenticación | 11 |
| Autenticaciones correctas | 9 |
| Contraseñas incorrectas | 1 |
| Usuarios inexistentes | 1 |
| Alertas SOC-001 | 0 |
| Alertas SOC-002 | 1 |
| Nuevas alertas guardadas en el directorio del servicio | 1 |

Se verificó la generación de `alerts.jsonl` en `/var/lib/powerbeam-monitor/`.

### Ejecución del servicio bajo systemd

El servicio mostró `Result=success` y `ExecMainStatus=0`. La ejecución manual previa guardó **0 alertas nuevas**, confirmando la deduplicación respecto del JSONL ya existente.

### Primera ejecución automática del temporizador

En el Journal se observó una ejecución iniciada a las **21:20:07 CET** que procesó las mismas **18 líneas / 11 eventos**, detectó **1 alerta SOC-002** previamente conocida y terminó con:

```text
Alertas nuevas añadidas a /var/lib/powerbeam-monitor/alerts.jsonl: 0
powerbeam-monitor.service: Deactivated successfully.
Finished powerbeam-monitor.service.
```

La siguiente activación se inició a las **21:25:05 CET**; la captura aportada no incluía su finalización, por lo que no se documenta como verificada en ese momento.

### Pruebas del código

El monitor integrado había superado **24 pruebas automatizadas**: 10 de SOC-001, 6 de SOC-002 y 8 de integración.

## Comandos de verificación y operación

```bash
# Comprobar el temporizador
systemctl status powerbeam-monitor.timer --no-pager
systemctl list-timers --all | grep powerbeam

# Comprobar el resultado reciente del servicio
systemctl show powerbeam-monitor.service -p ActiveState -p SubState -p Result -p ExecMainStatus

# Consultar ejecuciones y errores
sudo journalctl -u powerbeam-monitor.service -n 50 --no-pager

# Comprobar el servicio bajo demanda
sudo systemctl start powerbeam-monitor.service

# Revisar permisos de lectura del usuario de servicio
sudo -u powerbeam-monitor test -r /var/log/powerbeam/powerbeam.log && echo 'Lectura OK'
sudo -u powerbeam-monitor test ! -w /var/log/powerbeam/powerbeam.log && echo 'Escritura denegada OK'

# Ejecución de los tests desde el repositorio de desarrollo
python3 -m unittest discover -s tests -v
```

## Limitaciones conocidas y próximos pasos

1. **Procesamiento repetido:** cada ejecución relee los registros actuales e históricos disponibles. El JSONL evita duplicar alertas almacenadas con el mismo ID, pero no evita repetir el análisis ni los mensajes del Journal.
2. **Estado de correlación:** la lógica actual no conserva un estado incremental propio entre ejecuciones; deben diseñarse checkpoints y contexto de eventos para evitar pérdida o duplicidad tras rotaciones.
3. **Rotaciones y ACL:** verificar expresamente que `powerbeam-monitor` puede leer el archivo nuevo tras una rotación automática de `logrotate`.
4. **Reloj del PowerBeam:** hay una diferencia temporal entre algunos mensajes del equipo y la recepción en Ubuntu. Verificar NTP y zona horaria del dispositivo.
5. **Cobertura:** dos reglas basadas en umbrales no equivalen a un SIEM, una evaluación completa de seguridad ni a una detección probada de ataques reales.
6. **Reinicios y fallos:** validar posteriormente el arranque automático tras reinicio y la recuperación ante errores de lectura o archivos comprimidos corruptos.

## Nota para GitHub

Publicar los scripts, las unidades `systemd`, los tests y esta documentación. **No publicar** `alerts.jsonl`, logs originales, copias de seguridad del dispositivo, credenciales ni tokens. Para ilustrar alertas en documentación utilizar IP ficticias de rangos reservados para documentación (por ejemplo, `192.0.2.10`).
