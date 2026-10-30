# PowerBeam Security Lab

**Laboratorio práctico de Blue Team / SOC L1** · Ubiquiti PowerBeam PBE-M5-400 · Ubuntu · Octubre de 2026

> Proyecto personal de análisis y monitorización de un dispositivo de red propio. Documenta lo que se ha comprobado, lo que se ha observado y lo que sigue pendiente. No es una auditoría formal ni un despliegue de producción.

## Resumen

Diseño e implementación de un pequeño laboratorio para identificar la superficie de exposición de un dispositivo Ubiquiti con airOS, centralizar eventos mediante Syslog, preservar registros y verificar su disponibilidad después de tareas de mantenimiento.

**Hitos verificados (29–30/10/2026):**

- Reconocimiento de puertos TCP y servicios; revisión de algoritmos SSH y certificado HTTPS.
- Recepción de Syslog por **UDP/5514** en Ubuntu y almacenamiento en `/var/log/powerbeam/powerbeam.log`.
- Permisos restrictivos del directorio y los registros; rotación con `logrotate` y retención de **14 archivos históricos**.
- Prueba real de rotación y constatación de un nuevo evento de autenticación después de rotar.
- Servicio Chrony operativo en Ubuntu y temporizador de `logrotate` activo.

**Pendiente:** demostrar la corrección del desfase horario del PowerBeam respecto al receptor y revisar la configuración NTP en el equipo. La regla de rsyslog incluida aquí es una **reconstrucción de referencia**, que debe cotejarse con el archivo real antes de desplegarla.

## Topología del laboratorio

```text
                   RED LOCAL DE LABORATORIO

  Ubiquiti PowerBeam PBE-M5-400             Ubuntu / estación de análisis
  airOS 6.1.11 (XW)                         rsyslog + Chrony + logrotate
  IP privada: 192.168.1.20                  IP privada: 192.168.1.10
             |                                         |
             +--------- Syslog UDP/5514 ------------->|
                                                       |
                                  /var/log/powerbeam/powerbeam.log
                                                       |
                                  logrotate: daily + maxsize 10M
                                          rotate 14 + compress
```

Direcciones RFC 1918 del laboratorio (no son IP públicas). No se publican contraseñas, copias de configuración, certificados privados, capturas de tráfico originales ni registros completos.

## Metodología y cronología

| Fecha | Fase | Resultado |
|---|---|---|
| **29/10/2026** | Reconocimiento | Puertos 22/80/443 abiertos; Telnet 23 cerrado; identificación de Dropbear/lighttpd |
| **29/10/2026** | Revisión de seguridad | Algoritmos SSH heredados y certificado HTTPS autofirmado caducado |
| **29/10/2026** | Centralización | Eventos Syslog reales recibidos por UDP 5514 y guardados |
| **30/10/2026** | Persistencia y respaldo | Persistencia comprobada tras reinicio; backup de airOS realizado y mantenido fuera del repositorio |
| **30/10/2026** | Hora | Chrony activo/sincronizado en Ubuntu; NTP del PowerBeam aún por validar |
| **30/10/2026** | Ciclo de vida de logs | Rotación forzada probada, nuevo archivo creado y escritura posterior confirmada |
| **30/10/2026** | Automatización | `logrotate.timer` habilitado y activo |

## Resultados destacados

**Superficie de ataque observada.** SSH (22/TCP), HTTP (80/TCP) y HTTPS (443/TCP) accesibles desde el analista del laboratorio. HTTP redirige a HTTPS; Telnet (23/TCP) aparece cerrado. El escaneo no demuestra accesibilidad desde Internet.

**Riesgos a evaluar.** Algoritmos SSH antiguos (`diffie-hellman-group1-sha1`, `ssh-dss`, entre otros) y certificado TLS autofirmado expirado el **28/03/2024**. Son hallazgos de configuración, no pruebas de explotación ni de compromiso. Véase [Hallazgos y recomendaciones](docs/05-hallazgos-y-recomendaciones.md).

**Trazabilidad.** Tras ejecutar `sudo logrotate -vf /etc/logrotate.d/powerbeam` se obtuvo `powerbeam.log.1` con ~1,6 KB y un `powerbeam.log` nuevo con permisos `0640`. A continuación se recibió un evento de autenticación en el nuevo archivo (~139 B). Evidencia resumida en [Validaciones](docs/06-evidencias-y-validacion.md).

## Documentación

| Documento | Contenido |
|---|---|
| [01 · Reconocimiento](docs/01-reconocimiento.md) | Escaneo, servicios y observaciones técnicas |
| [02 · Centralización de Syslog](docs/02-centralizacion-syslog.md) | Receptor, flujo, permisos y verificaciones |
| [03 · Sincronización horaria](docs/03-sincronizacion-horaria.md) | Chrony verificado y comprobaciones pendientes |
| [04 · Rotación y retención](docs/04-rotacion-y-retencion.md) | Regla real de logrotate y prueba de continuidad |
| [05 · Hallazgos y mitigaciones](docs/05-hallazgos-y-recomendaciones.md) | Riesgos y medidas propuestas |
| [06 · Evidencias y validación](docs/06-evidencias-y-validacion.md) | Matriz de resultados: confirmado vs pendiente |
| [07 · Roadmap](docs/07-roadmap.md) | Próximas tareas de detección SOC |

## Configuraciones publicadas

- [`configs/30-powerbeam.conf.example`](configs/30-powerbeam.conf.example): ejemplo de rsyslog **reconstruido**, no un volcado literal del equipo.
- [`configs/logrotate-powerbeam.conf`](configs/logrotate-powerbeam.conf): regla de logrotate **copiada del contenido verificado**.
- [`configs/chrony-snippet.conf.example`](configs/chrony-snippet.conf.example): fragmento **orientativo**, no configuración aplicada verificada.
- [`evidencias/evento-sanitizado.txt`](evidencias/evento-sanitizado.txt): evento ilustrativo anonimizado basado en un evento real.

## Reproducibilidad y límites

El sistema de origen era Ubuntu; `rsyslog`, `chrony` y `logrotate` dependen de la versión y las políticas de la distribución. Las rutas, interfaces y direcciones IP deben ajustarse a cada instalación. Este repositorio no debe ejecutarse a ciegas: revisar primero las reglas y probar con `rsyslogd -N1` y `logrotate -d`.

No hay evidencia de ataque, compromiso, fuerza bruta ni alerta SOC funcional hasta la fecha. El evento de autenticación documentado es una **sesión exitosa observada**, no una detección de actividad maliciosa.

## Buenas prácticas

Escanear solo equipos propios o con autorización; mantener el tráfico Syslog sin cifrar dentro de la red aislada o protegida; limitar accesos administrativos; no publicar archivos de respaldo de airOS ni logs originales. Véase [`SECURITY.md`](SECURITY.md).

## Estado del proyecto

**En desarrollo — fases 1 y 2 documentadas (30/10/2026).** Próxima fase: verificar NTP extremo a extremo, normalizar registros y diseñar casos de uso de autenticación.
