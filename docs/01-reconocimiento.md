# Día 1 — Reconocimiento y exposición de servicios

- **Fecha:** 29/10/2026
- **Activo analizado:** Ubiquiti PowerBeam PBE-M5-400; airOS 6.1.11 (rama XW)
- **Alcance:** equipo propio en red de laboratorio, desde Ubuntu. IP del equipo `192.168.1.20`; estación `192.168.1.10`.

## Objetivo

Enumerar servicios TCP accesibles desde la estación de análisis e identificar configuraciones que merezcan revisión. No se realizaron pruebas de explotación documentadas.

## Comprobaciones

Escaneo de los cuatro puertos de administración relevantes realizado con Nmap:

```bash
nmap -sT -Pn -p 22,23,80,443 192.168.1.20
```

| Puerto | Resultado | Servicio observado |
|---|---|---|
| 22/TCP | open | SSH, Dropbear (SSH protocolo 2) |
| 23/TCP | closed | Telnet |
| 80/TCP | open | HTTP, lighttpd 1.4.39; respuesta 302 hacia HTTPS |
| 443/TCP | open | HTTPS, lighttpd 1.4.39 |

Posteriormente se identificaron versiones mediante escaneo de servicios (`-sV`). Los resultados solo caracterizan la visibilidad **desde la estación del laboratorio**, no desde Internet.

## Análisis de SSH

La negociación del servidor ofrecía, entre otros, estos algoritmos heredados:

- Intercambio de claves: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`.
- Claves de host: `ssh-rsa`, `ssh-dss`.
- También se observaron variantes AES-CTR y HMAC-SHA1.

La presencia de algoritmos antiguos es un **indicador de configuración mejorable**. No demuestra por sí misma explotación, acceso no autorizado ni compromiso.

## Análisis de HTTPS

Se observó certificado TLS autofirmado, clave RSA de 2048 bits, con validez desde **28/03/2019** hasta **28/03/2024**. En el momento del análisis, el certificado estaba caducado.

La respuesta HTTP redirigía a HTTPS, comportamiento positivo para evitar usar HTTP como canal principal, aunque no elimina la advertencia de confianza del certificado ni los riesgos de la versión de software.

## Observación temporal

El dispositivo mostraba una referencia temporal antigua durante las pruebas iniciales; se revisó la sincronización de tiempo el Día 2. No se ha confirmado que el equipo finalizara correctamente su ajuste mediante NTP.

## Interpretación SOC

Este inventario ayuda a construir una **línea base de servicios**. Ante cambios futuros, comparar puertos, certificados y parámetros SSH permite detectar desviaciones de configuración o exposición inesperada.

**Siguiente paso:** [Centralización de eventos](02-centralizacion-syslog.md) y [Hallazgos de seguridad](05-hallazgos-y-recomendaciones.md).
