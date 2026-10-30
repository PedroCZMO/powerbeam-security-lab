# Matriz de evidencias y validación

**Corte documental:** 30/10/2026. Resumen de salidas observadas durante el trabajo; no se publican capturas privadas ni registros en bruto.

| ID | Verificación | Estado | Evidencia resumida |
|---|---|---|---|
| E01 | Inventario de puertos TCP 22,23,80,443 | **Confirmado** | 22, 80, 443 abiertos; 23 cerrado |
| E02 | Identificación de software | **Confirmado** | SSH Dropbear; lighttpd 1.4.39; airOS 6.1.11 XW |
| E03 | Algoritmos SSH heredados | **Confirmado** | Group1/SHA-1 y DSS ofertados |
| E04 | Certificado caducado | **Confirmado** | TLS autofirmado, caducidad 28/03/2024 |
| E05 | Recepción Syslog desde PowerBeam | **Confirmado** | Eventos autenticación recibidos por UDP/5514 |
| E06 | Persistencia de ingesta tras reinicio | **Confirmado** | Revisión del Día 2 |
| E07 | Respaldo de configuración del dispositivo | **Confirmado** | Backup realizado; archivo deliberadamente fuera del repo |
| E08 | Chrony sincronizado en Ubuntu | **Confirmado** | stratum 3, Leap Normal; listener UDP/123 |
| E09 | NTP sincronizado en PowerBeam | **Pendiente** | Desfase aparente de una hora por interpretar |
| E10 | Regla de rotación leída por logrotate | **Confirmado** | Sin errores de sintaxis en `-d` y `-v` |
| E11 | Rotación real de registros | **Confirmado** | `-vf`, `powerbeam.log.1` y archivo nuevo 0640 |
| E12 | Escritura después de rotación | **Confirmado** | Archivo nuevo recibió un evento adicional (139 B) |
| E13 | Temporizador logrotate activo | **Confirmado** | `enabled` / `active (waiting)` |
| E14 | Regla incluida en ejecución global | **Por comprobar explícitamente** | Ejecutar `grep ... /etc/logrotate.conf` |
| E15 | Compresión efectiva y 14 copias | **No probado aún** | Política configurada; esperar ciclos futuros |

## Ejemplo de evento anonimizado

```text
2026-10-30T11:31:44+01:00 source=192.168.1.20 <14>Oct 30 10:31:44 httpd[PID]: Password auth succeeded for '<usuario>' from 192.168.1.10
```

**Lectura:** autenticación web exitosa del dispositivo desde la estación del laboratorio. Un evento correcto no es por sí solo una alerta de seguridad ni indica amenaza. Es posible que el equipo envíe tiempo en otra zona horaria; todavía requiere revisión.

## Preservación y privacidad

Si se incorporan capturas futuras: cortar nombres de host, direcciones públicas, tokens y MAC; conservar las salidas originales solo fuera del repositorio público; añadir fecha, comando y conclusión de cada captura. El archivo `evidencias/evento-sanitizado.txt` es exclusivamente ilustrativo.
