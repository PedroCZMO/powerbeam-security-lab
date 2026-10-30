# Día 2 — Rotación y retención de logs

**Fecha de prueba:** 30/10/2026

## Regla comprobada

Archivo del sistema: `/etc/logrotate.d/powerbeam`. Se ha reproducido el contenido proporcionado y verificado en [`configs/logrotate-powerbeam.conf`](../configs/logrotate-powerbeam.conf).

| Opción | Efecto |
|---|---|
| `daily` | Evalúa rotación diaria |
| `maxsize 10M` | Rota por tamaño si supera 10 MiB al ejecutarse logrotate |
| `rotate 14` | Mantiene hasta 14 copias rotadas, **no garantiza 14 días exactos** |
| `notifempty` + `missingok` | Evita rotar vacíos y errores por ausencia del archivo |
| `compress` + `delaycompress` | Comprime archivos antiguos, salvo el histórico más reciente hasta el siguiente ciclo |
| `su syslog syslog` | Procesa el log con identidad de usuario/grupo `syslog` |
| `create 0640 syslog syslog` | Crea el nuevo archivo con permisos y propietario definidos |
| `postrotate` | Envía HUP al proceso principal de rsyslog si está activo |

El HUP permite a rsyslog cerrar la referencia del archivo rotado y reabrir el nuevo en posteriores escrituras; esto está alineado con su documentación oficial del módulo `omfile`. El `|| true` presente en la regla permite continuar aunque falle la señal, por lo que resulta importante comprobar recepción tras la rotación.

## Prueba real

1. `sudo logrotate -d /etc/logrotate.d/powerbeam`: lectura de sintaxis sin modificar archivos.
2. `sudo logrotate -v /etc/logrotate.d/powerbeam`: evaluó reglas; no rotó al constar tratamiento previo ese día.
3. `sudo logrotate -vf /etc/logrotate.d/powerbeam`: **rotación forzada** de prueba.
4. Se movió `powerbeam.log` a `powerbeam.log.1` y se creó `powerbeam.log` nuevo con modo `0640` y propietario `syslog:syslog`.
5. Se observó que `powerbeam.log.1` contenía aproximadamente **1,6 KB** y que el nuevo `powerbeam.log` pasó de **0 bytes** a **139 bytes** cuando llegó otro evento de autenticación desde el PowerBeam.

No se han verificado todavía 14 ciclos de retención ni una compresión efectiva; esas son políticas **configuradas**, no resultados de una prueba de varios días.

## Programación automática

`logrotate.timer` estaba **enabled** y **active (waiting)**. En la salida del 30/10/2026 constaban:

- Última activación: **30/10/2026 09:56:18 CET**.
- Siguiente activación prevista: **31/10/2026 00:39:33 CET**.

El temporizador activa el servicio global de logrotate; todavía conviene verificar la inclusión real con:

```bash
grep -n 'include /etc/logrotate.d' /etc/logrotate.conf
```

## Comandos de validación

```bash
sudo logrotate -d /etc/logrotate.d/powerbeam
sudo ls -lah /var/log/powerbeam/
systemctl status logrotate.timer --no-pager
systemctl list-timers --all | grep logrotate
sudo tail -F /var/log/powerbeam/powerbeam.log
```

**Advertencia:** `logrotate -vf` cambia de verdad los archivos. No se recomienda ejecutarlo repetidamente solo para obtener nuevas capturas.

**Conclusión:** rotación real y continuidad de ingesta confirmadas; retención/compresión a largo plazo, por verificar con ejecuciones futuras.
