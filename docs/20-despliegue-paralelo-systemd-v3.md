# Despliegue paralelo de PowerBeam Monitor V3

## Objetivo

Validar el monitor incremental V3 mediante systemd sin interrumpir el monitor original V1.

## Arquitectura

PowerBeam Ubiquiti
    |
    v
rsyslog (Ubuntu)
    |
    v
/var/log/powerbeam/
    |
    +-- Monitor V1 (procesamiento por lotes)
    |
    +-- Monitor V3 (procesamiento incremental)

Ambos monitores utilizan los mismos registros, pero mantienen archivos de estado y alertas independientes.

## Monitor V1

Servicio:
- powerbeam-monitor.service

Temporizador:
- powerbeam-monitor.timer

Estado y alertas:
- /var/lib/powerbeam-monitor/alerts.jsonl

## Monitor V3

Servicio:
- powerbeam-monitor-v3.service

Temporizador:
- powerbeam-monitor-v3.timer

Codigo instalado:
- /opt/powerbeam-monitor-v3/scripts/

Checkpoint:
- /var/lib/powerbeam-monitor/parallel-v3/state-v3.json

Alertas:
- /var/lib/powerbeam-monitor/parallel-v3/alerts-v3.jsonl

## Seguridad

La ejecucion utiliza el usuario restringido powerbeam-monitor.

Medidas aplicadas:
- UMask=0077
- NoNewPrivileges=yes
- ProtectSystem=strict
- ProtectHome=yes
- PrivateTmp=yes
- StateDirectoryMode=0700

Permisos comprobados:
- Directorio de estado: 0700
- Checkpoint: 0600
- Archivo de alertas: 0600

## Temporizadores

V1 utiliza su temporizador original.

V3 utiliza:
- OnCalendar=*:2/5
- AccuracySec=30s
- Persistent=true

Los horarios estan desfasados para evitar que ambas versiones comiencen exactamente al mismo tiempo.

## Validaciones realizadas

- Recepcion real de registros syslog.
- Ejecucion mediante usuario restringido.
- Procesamiento incremental.
- Persistencia del checkpoint.
- Coincidencia de detecciones SOC-001 y SOC-002 entre versiones en los registros disponibles.
- Ejecucion automatica mediante systemd.
- Rotacion real de registros con delaycompress.
- Recuperacion del procesamiento tras la rotacion observada.
- Correccion RES-007 para reutilizacion de inodos.
- 78 pruebas automatizadas superadas.

## Procedimiento de reversion

Para detener exclusivamente V3:

    sudo systemctl disable --now powerbeam-monitor-v3.timer

Comprobar que V1 sigue activo:

    systemctl is-active powerbeam-monitor.timer

No eliminar el checkpoint ni las alertas de V3 durante la investigacion.

Antes de restaurar codigo o estado de V3, comprobar que su temporizador y servicio estan detenidos.

Las copias de seguridad de RES-007 se conservan en:

    /var/backups/powerbeam-monitor-v3-res007/

## Limitaciones

V3 sigue siendo experimental.

Las pruebas realizadas no garantizan el comportamiento correcto ante todas las rotaciones, interrupciones de energia o eventos fuera de orden.

La rotacion real observada se completo sin eventos nuevos pendientes de procesamiento.

La migracion definitiva de V1 a V3 sigue pendiente de validacion adicional.

## Estado

Despliegue paralelo operativo.

V1 se mantiene como monitor principal.
V3 se mantiene como monitor experimental.
