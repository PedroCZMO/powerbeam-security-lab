# SOC-002 — Autenticación correcta después de intentos fallidos

**Proyecto:** PowerBeam Security Lab  
**Fecha de validación inicial:** 30/10/2026  
**Estado:** prototipo funcional, análisis offline  
**Severidad propuesta:** media; requiere valoración contextual

## Objetivo

Detectar una autenticación correcta en la interfaz web de un PowerBeam cuando **la misma IP cliente** ha originado **dos o más intentos fallidos en los cinco minutos anteriores**. La alerta es un indicio para triaje, **no evidencia de compromiso**.

## Fuente de datos

- Dispositivo: Ubiquiti PowerBeam con airOS.
- Transporte: Syslog enviado al receptor Ubuntu (rsyslog).
- Archivo de análisis: `/var/log/powerbeam/powerbeam.log` y rotaciones disponibles.
- Fecha usada para correlación: **marca temporal de recepción en Ubuntu**, debido al desfase observado en la marca temporal del dispositivo.

## Mensajes observados en la prueba autorizada

| Mensaje del dispositivo | Clasificación |
|---|---|
| `Login attempt for nonexistent user from <IP>` | Fallo: usuario inexistente |
| `Bad password attempt for '<usuario>' from <IP>` | Fallo: contraseña incorrecta |
| `Password auth succeeded for '<usuario>' from <IP>` | Éxito |

Los ejemplos de IP en las pruebas automatizadas usan rangos reservados para documentación (`192.0.2.0/24`). Nunca subir logs originales ni credenciales.

## Lógica de detección

1. Leer registros desde la entrada estándar (`stdin`).
2. Filtrar los tres mensajes de autenticación anteriores.
3. Extraer la IP cliente del campo `from <IP>` y la fecha de recepción del inicio de la línea.
4. Ordenar cronológicamente los eventos por la fecha de recepción.
5. Mantener, por IP cliente, los fallos de los últimos cinco minutos.
6. Cuando aparezca un éxito, generar **SOC-002** si existen al menos dos fallos de esa IP en dicha ventana.
7. Limpiar los fallos asociados a la IP tras el éxito para evitar reutilizarlos en éxitos sucesivos.

## Ejecución (offline, sin modificar el dispositivo)

Desde la raíz del repositorio:

```bash
sudo cat /var/log/powerbeam/powerbeam.log.1 \
  /var/log/powerbeam/powerbeam.log \
  | python3 scripts/auth_detector.py
```

La lectura requiere privilegios debido a los permisos de los archivos; **Python se ejecuta sin `sudo`**. Este ejemplo considera solamente las dos rutas indicadas. Para históricos comprimidos deben emplearse otras herramientas como `zcat`.

## Evidencia de validación — 30/10/2026

Secuencia de laboratorio **generada deliberadamente por el administrador**:

| Hora de recepción (CET) | Resultado |
|---|---|
| 12:22:17 | Intento con usuario inexistente |
| 12:22:35 | Contraseña incorrecta de cuenta existente |
| 12:22:45 | Autenticación correcta |

Los tres eventos procedían de la misma IP privada de administración.

Resultado del detector:

```text
[SOC-002] POSIBLE ACCESO TRAS FALLOS | 2026-10-30T12:22:45.290386+01:00 | origen=<IP_INTERNA> | fallos_previos=2 | ventana=5m

=== RESUMEN DE AUTENTICACIONES ===
Correctas: 9
Contraseñas incorrectas: 1
Usuarios inexistentes: 1
Alertas SOC-002: 1
Nota: una alerta requiere revisión; no demuestra un ataque.
```

**Resultado:** prueba positiva superada. Una coincidencia en condiciones conocidas, no un incidente real.

## Pruebas negativas automatizadas

```bash
python3 -m unittest discover -s tests -v
```

Incluyen: un solo fallo; fallos desde otra IP; fallos fuera de la ventana; orden de llegada desordenado; registros ajenos. Ejecutar estas pruebas antes de afirmar que la cobertura negativa ha sido validada en el entorno local.

## Triaje propuesto para un analista SOC L1

- Comprobar si la IP origen es una estación administrativa autorizada.
- Identificar usuario, hora, número de intentos y otros eventos cercanos.
- Comparar con una ventana de mantenimiento o prueba programada.
- Comprobar actividad posterior al acceso, si el equipo ofrece registros suficientes.
- Escalar según el procedimiento de respuesta del laboratorio; no bloquear ni reiniciar automáticamente basándose en esta única alerta.

## Limitaciones conocidas

- Solo reconoce los tres mensajes Syslog observados; otros servicios o formatos pueden quedar fuera.
- La herramienta es **offline**, no monitoriza continuamente ni persiste alertas.
- Carga los eventos reconocidos en memoria; no está optimizada para grandes volúmenes.
- No correlaciona entre distintos orígenes IPv4, direcciones IPv6 ni identidades de usuario.
- Los intentos exitosos sin suficientes fallos previos no disparan alerta, incluso si son anómalos por otros motivos.
- La IP cliente se toma del mensaje `from`, y el filtrado del archivo de entrada debe garantizar que los eventos pertenecen al PowerBeam esperado.
- La configuración horaria del dispositivo sigue pendiente de verificación.
- Los umbrales y la severidad deben ajustarse a la actividad normal; existen falsos positivos por errores legítimos.

## Mejoras pendientes

- Añadir SOC-001 (volumen de fallos por IP), con pruebas positivas y negativas.
- Valorar alertas en JSON y deduplicación.
- Validar NTP del PowerBeam y ampliar la normalización de registros.
- Preparar una ejecución incremental con control de archivos rotados antes de hablar de monitorización en tiempo real.
