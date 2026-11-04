# PowerBeam Security Lab - Despliegue automático del Health Check

## Objetivo

Supervisar periódicamente la infraestructura del laboratorio SOC mediante
un servicio systemd independiente de los detectores V1 y V3.

## Arquitectura

PowerBeam (192.168.1.20)
        |
        | Syslog UDP 5514
        v
Ubuntu (192.168.1.10)
        |
        v
      rsyslog
        |
        v
 /var/log/powerbeam/
        |
        +-- Monitor V1
        |
        +-- Monitor V3
        |
        +-- Health Check
                |
                v
             journald

## Comprobaciones

El Health Check supervisa:

- Estado del servicio rsyslog.
- Estado de los temporizadores V1 y V3.
- Resultado de las últimas ejecuciones de ambos monitores.
- Disponibilidad del socket UDP 192.168.1.10:5514.
- Fecha de recepción del último mensaje de la antena.
- Conectividad ICMP con 192.168.1.20.

## Archivos

Script:
scripts/health_check.py

Servicio:
systemd/powerbeam-health.service

Temporizador:
systemd/powerbeam-health.timer

Instalación del script:
/opt/powerbeam-monitor-v3/scripts/health_check.py

## Instalación

Instalar el script:

sudo install -o root -g root -m 0644 \
scripts/health_check.py \
/opt/powerbeam-monitor-v3/scripts/health_check.py

Instalar las unidades:

sudo install -o root -g root -m 0644 \
systemd/powerbeam-health.service \
/etc/systemd/system/powerbeam-health.service

sudo install -o root -g root -m 0644 \
systemd/powerbeam-health.timer \
/etc/systemd/system/powerbeam-health.timer

Recargar systemd:

sudo systemctl daemon-reload

Probar manualmente:

sudo systemctl start powerbeam-health.service

Activar el temporizador:

sudo systemctl enable --now powerbeam-health.timer

## Frecuencia

El temporizador utiliza:

OnCalendar=*:4/10
AccuracySec=30s
Persistent=true

Se ejecuta aproximadamente cada diez minutos.

## Seguridad

El servicio utiliza el usuario restringido powerbeam-monitor.

Configuraciones principales:

- UMask=0077
- NoNewPrivileges=yes
- ProtectSystem=strict
- ProtectHome=yes
- PrivateTmp=yes

No modifica los checkpoints de V1 ni V3.

## Validación real

Fecha: 4 de noviembre de 2026.

Primera ejecución automática observada:
12:34:01 CET.

Resultado:
Finalización satisfactoria mediante systemd.

Estado observado:
HEALTHY.

Pruebas automatizadas del proyecto:
129 correctas.

## Diagnóstico

Consultar temporizador:

systemctl status powerbeam-health.timer

Consultar ejecuciones:

sudo journalctl -u powerbeam-health.service --no-pager

Consultar los tres temporizadores:

systemctl list-timers --all --no-pager | grep powerbeam

## Reversión

Detener únicamente la supervisión automática:

sudo systemctl disable --now powerbeam-health.timer

El monitor V1 y el monitor V3 permanecen independientes.

## Limitaciones

HEALTHY indica que las comprobaciones operativas han sido satisfactorias.

La presencia del socket UDP no garantiza recepción de mensajes.

La disponibilidad ICMP no demuestra que syslog funcione.

La ausencia de registros puede deberse a inactividad normal.

La recepción continua permanece UNKNOWN mientras no exista una señal
periódica fiable del dispositivo.

El Health Check registra resultados en journald, pero todavía no envía
notificaciones externas ni constituye un sistema de alertas independiente.

## Estado

Despliegue automático validado.

V1 continúa como monitor principal.
V3 continúa como monitor incremental experimental.
Health Check se ejecuta automáticamente cada diez minutos.
