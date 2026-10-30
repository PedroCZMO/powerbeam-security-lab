# Hallazgos de seguridad y recomendaciones

**Fuente:** pruebas realizadas el 29–30/10/2026 sobre un equipo de laboratorio propio. Las prioridades siguientes son una **valoración de laboratorio**, no un CVSS formal ni una afirmación de vulnerabilidad explotable.

| ID | Hallazgo | Evidencia | Prioridad orientativa | Recomendación |
|---|---|---|---|---|
| PB-01 | Algoritmos SSH heredados | `diffie-hellman-group1-sha1`, `ssh-dss`, `ssh-rsa` ofrecidos | Alta | Priorizar firmware compatible actualizado y deshabilitar algoritmos obsoletos si airOS lo permite; restringir acceso administrativo |
| PB-02 | Certificado HTTPS expirado | Autofirmado RSA 2048, fin de validez 28/03/2024 | Media | Revisar reloj y renovar certificado si la plataforma lo soporta; no ignorar avisos TLS fuera del laboratorio |
| PB-03 | Servicios de administración accesibles desde LAN | 22, 80 y 443/TCP abiertos desde Ubuntu | Media | Limitar IPs/redes de administración; mantener equipo aislado de Internet; deshabilitar lo que no se necesite |
| PB-04 | Diferencia entre marcas temporales | Receptor 11:31:44 +01:00 vs mensaje 10:31:44 | Pendiente de investigar | Verificar zona horaria y NTP del equipo antes de calificarlo como fallo |
| PB-05 | Transporte Syslog UDP sin cifrar | Recepción del laboratorio en UDP/5514 | Media (depende de red) | Segmentar la red y filtrar IP de origen; valorar transporte más fiable y seguro si se amplía el laboratorio |

## Observaciones positivas

- Telnet (23/TCP) apareció **cerrado** en el escaneo realizado.
- HTTP respondía con **redirección 302** hacia HTTPS.
- Los archivos de registros de Ubuntu presentaron **propietario y permisos restrictivos**.
- Se validó la continuidad tras rotación de registros.

## Qué no está demostrado

No hay datos suficientes para afirmar que el dispositivo sea explotable mediante un CVE específico, que exista un atacante, que se haya comprometido una contraseña o que el servicio sea accesible desde fuera de la LAN.

## Próximas acciones

1. Contrastar firmware con versiones soportadas del fabricante y planificar actualización **sin asumir compatibilidad**.
2. Restringir la administración del dispositivo a una red/estación de confianza.
3. Confirmar sincronización temporal extremo a extremo.
4. Integrar casos de uso de intentos de inicio de sesión fallidos y cambios administrativos, cuando existan eventos representativos.
