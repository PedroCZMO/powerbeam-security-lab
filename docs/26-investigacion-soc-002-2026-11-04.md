# Caso SOC-002 — Investigación de autenticación correcta tras fallos

**Proyecto:** PowerBeam Security Lab  
**Identificador de caso:** CASE-2026-11-04-SOC-002-01  
**Identificador de alerta:** `SOC-002-2ad9ffcb5b5d0b58`  
**Fecha del evento:** 2026-11-04  
**Tipo de análisis:** Investigación SOC L1 de un simulacro autorizado  
**Estado del caso:** Cerrado como prueba controlada, según el contexto conocido del ejercicio  
**Severidad de la regla:** `medium` (no equivale a impacto confirmado)  
**Fuente de evidencia:** salidas de comandos locales facilitadas durante la investigación.

## 1. Resumen ejecutivo

El 4 de noviembre de 2026, el laboratorio registró dos intentos fallidos de autenticación seguidos de un acceso correcto al dispositivo Ubiquiti PowerBeam. La secuencia ocurrió en **19,318 segundos**, dentro de la ventana de correlación de cinco minutos de la regla **SOC-002**. Los monitores V1 y V3 generaron alertas coincidentes: mismo identificador, origen, marca temporal y número de fallos.

Las acciones formaban parte de un **simulacro autorizado**, por lo que las evidencias respaldan una **detección correcta de un patrón de riesgo en una prueba controlada**, pero **no acreditan un ataque real ni un acceso no autorizado**. La comprobación demuestra la correlación de la regla con registros reales enviados por la antena, no la eficacia frente a todos los escenarios de ataque.

## 2. Alcance y contexto técnico

| Campo | Dato observado |
| --- | --- |
| Dispositivo que envía syslog | PowerBeam `192.168.1.20` |
| Equipo desde el que se originan los accesos | `192.168.1.10` |
| Usuario objetivo | `ubnt` |
| Aplicación que registra los eventos | `httpd` de la antena |
| Receptor | Ubuntu con `rsyslog`, destino `/var/log/powerbeam/powerbeam.log` |
| Regla activada | `SOC-002`: autenticación correcta tras varios fallos |
| Ventana declarada por la alerta | 5 minutos |
| Severidad declarada por la alerta | `medium` |
| Detectores comparados | Monitor V1 y monitor V3 incremental |

La IP `source=192.168.1.20` en la cabecera normalizada identifica **el dispositivo que remitió el mensaje syslog**. La IP `192.168.1.10` dentro del texto `from ...` identifica **el origen del intento de autenticación**, no al emisor del mensaje syslog.

## 3. Cronología comprobada

Se utiliza como referencia la **marca temporal de recepción añadida por rsyslog**, en hora local de Madrid (`CET`, UTC+01:00).

| Hora CET | Descripción | Evidencia |
| --- | --- | --- |
| 11:00:06.205386 | Contraseña incorrecta para `ubnt` | `Bad password attempt` — `httpd[864]` |
| 11:00:20.921474 | Segunda contraseña incorrecta para `ubnt` | `Bad password attempt` — `httpd[866]` |
| 11:00:25.523253 | Contraseña correcta para `ubnt` | `Password auth succeeded` — `httpd[868]` |
| 11:00:25.523253 | Marca temporal asignada a la alerta SOC-002 | Coincide en V1 y V3 |

**Tiempos calculados a partir de los registros:**

- Primer fallo → segundo fallo: **14,716088 segundos**.
- Segundo fallo → acceso correcto: **4,601779 segundos**.
- Primer fallo → acceso correcto: **19,317867 segundos**.

La marca temporal de la alerta se corresponde con la autenticación correcta. **No se dispone aquí de una hora independiente de emisión de alerta**; por tanto, no se afirma que los detectores hayan ejecutado la correlación exactamente a las 11:00:25.

## 4. Evidencias primarias: registros syslog

Comando utilizado:

```bash
sudo grep -n '^2026-11-04T11:00:' /var/log/powerbeam/powerbeam.log
```

Salida obtenida:

```text
1:2026-11-04T11:00:06.205386+01:00 source=192.168.1.20 <14>Nov  4 10:00:06 httpd[864]: Bad password attempt for 'ubnt' from 192.168.1.10
2:2026-11-04T11:00:20.921474+01:00 source=192.168.1.20 <14>Nov  4 10:00:20 httpd[866]: Bad password attempt for 'ubnt' from 192.168.1.10
3:2026-11-04T11:00:25.523253+01:00 source=192.168.1.20 <14>Nov  4 10:00:25 httpd[868]: Password auth succeeded for 'ubnt' from 192.168.1.10
```

Los números de línea corresponden a la salida observada y **no son identificadores forenses permanentes**: pueden cambiar por la rotación o reescritura de archivos.

## 5. Evidencias derivadas: alertas de V1 y V3

### Monitor V1

**Archivo:** `/var/lib/powerbeam-monitor/alerts.jsonl`  
**Comando:**

```bash
sudo grep -n 'SOC-002-2ad9ffcb5b5d0b58' /var/lib/powerbeam-monitor/alerts.jsonl
```

**Resultado (línea 2):**

```json
{"alert_id": "SOC-002-2ad9ffcb5b5d0b58", "description": "Autenticación correcta tras varios fallos", "failed_attempts": 2, "rule_id": "SOC-002", "severity": "medium", "source_ip": "192.168.1.10", "timestamp": "2026-11-04T11:00:25.523253+01:00", "window_minutes": 5}
```

### Monitor V3

**Archivo:** `/var/lib/powerbeam-monitor/parallel-v3/alerts-v3.jsonl`  
**Comando:**

```bash
sudo grep -n 'SOC-002-2ad9ffcb5b5d0b58' /var/lib/powerbeam-monitor/parallel-v3/alerts-v3.jsonl
```

**Resultado (línea 2):**

```json
{"alert_id": "SOC-002-2ad9ffcb5b5d0b58", "description": "Autenticación correcta tras varios fallos", "failed_attempts": 2, "rule_id": "SOC-002", "severity": "medium", "source_ip": "192.168.1.10", "timestamp": "2026-11-04T11:00:25.523253+01:00", "window_minutes": 5}
```

### Comparación

**Coinciden** el identificador de alerta, la descripción, el número de intentos fallidos, la regla, la severidad, la IP de origen, la marca temporal y la ventana. Los datos disponibles muestran concordancia entre ambos detectores **para este caso concreto**, sin demostrar equivalencia general de sus implementaciones.

## 6. Consideraciones de tiempo

La parte recibida y normalizada por Ubuntu muestra `11:00:xx+01:00`; el texto syslog del dispositivo contiene `Nov  4 10:00:xx`. Ambas expresiones están separadas aproximadamente una hora.

Comprobación posterior con `timedatectl`:

```text
Local time: mié 2026-11-04 12:57:17 CET
Universal time: mié 2026-11-04 11:57:17 UTC
Time zone: Europe/Madrid (CET, +0100)
System clock synchronized: yes
NTP service: active
RTC in local TZ: no
```

**Interpretación:** la diferencia observada es compatible con el uso de UTC por la antena y CET por Ubuntu; sin acceder a la configuración temporal de la antena, **no se puede concluir que su reloj sea incorrecto**. Para esta cronología se ha utilizado la marca temporal de recepción del colector sincronizado.

## 7. Análisis y evaluación SOC L1

**Hipótesis que motivó la investigación:** dos fallos de contraseña seguidos de un acceso correcto pueden representar un usuario legítimo que se equivoca o una autenticación potencialmente sospechosa. El patrón justifica revisión, pero no atribución de intencionalidad.

**Hallazgos verificados:**

1. Existen tres mensajes consecutivos en los registros consultados: dos fallos y un éxito para `ubnt`, todos desde `192.168.1.10`.
2. La secuencia de 19,318 segundos cumple la ventana de cinco minutos declarada por SOC-002.
3. V1 y V3 han registrado una alerta SOC-002 con campos idénticos.
4. La máquina Ubuntu reportaba zona horaria `Europe/Madrid` y sincronización NTP en la consulta posterior.
5. El ejercicio fue realizado deliberadamente de forma autorizada, según el contexto del simulacro.

**Lo que las evidencias NO demuestran:** compromiso no autorizado, robo de credenciales, fuerza bruta sostenida, movimiento lateral, cambios de configuración de la antena, exfiltración o recepción ininterrumpida de syslog. La autenticación correcta solo acredita que se registró un acceso válido en ese instante.

**Valoración de severidad:** `medium` es la severidad configurada en la regla de detección; no debe interpretarse como impacto medido ni como incidente de seguridad confirmado.

## 8. Clasificación y decisión

| Criterio | Conclusión |
| --- | --- |
| ¿La regla reconoció el patrón buscado? | **Sí**, detección verificada para este caso |
| ¿La alerta es una coincidencia errónea? | **No** para la secuencia observada |
| ¿Se ha acreditado un ataque real? | **No** |
| ¿Actividad autorizada? | **Sí**, simulacro controlado según contexto conocido |
| ¿Acción inmediata de contención? | **No necesaria por este ejercicio**, sin otros indicadores aportados |
| Clasificación final | **Prueba autorizada con detección correcta; sin compromiso demostrado** |

Se recomienda registrar este evento como **ejercicio de validación de regla**, no como incidente de intrusión real. En un SOC real, si el contexto autorizado no estuviera confirmado, procedería validar el origen del acceso y el cambio de contraseña o actividad posterior antes de cerrar el caso.

## 9. Acciones del analista y recomendaciones

**Realizadas en esta investigación:** recuperación de registros syslog, recuperación de alertas V1/V3, comparación de campos, reconstrucción cronológica, contraste de zona horaria y documentación de limitaciones.

**Recomendadas para un entorno operativo, no ejecutadas en este ejercicio:**

- Confirmar con propietario y registros de cambios si el acceso era esperado.
- Revisar otros accesos y acciones administrativas del dispositivo en una ventana temporal más amplia.
- Comprobar la configuración de NTP/zona horaria del dispositivo.
- Ajustar umbrales y correlación tras observar más actividad legítima y evitar falsos positivos.
- Preservar copias de evidencia con permisos adecuados y hashes de integridad **si se requiere una investigación forense formal**.
- Evaluar el uso de un mecanismo fiable de comprobación periódica para distinguir inactividad de interrupción de ingestión.

## 10. Integridad, alcance y limitaciones documentales

Este informe reproduce las salidas facilitadas durante la revisión, **no una adquisición forense independiente**. No se calcularon hashes de los archivos originales en el momento del evento ni se ha establecido cadena de custodia. La rotación de registros puede modificar las líneas y archivos disponibles posteriormente. No se han incluido capturas de paquetes ni registros de auditoría sobre acciones posteriores al acceso.

La detección V3 continúa catalogada como **experimental** en el laboratorio. La coincidencia con V1 en este caso apoya su validación funcional, no su madurez para producción.

## 11. Conclusión

**SOC-002 funcionó para el patrón controlado probado el 4 de noviembre de 2026.** Dos contraseñas erróneas seguidas de un acceso válido, originadas en `192.168.1.10` hacia la PowerBeam `192.168.1.20`, fueron recogidas mediante syslog y correlacionadas de forma concordante por V1 y V3. La clasificación adecuada es **simulacro autorizado con detección correcta**, sin pruebas de intrusión no autorizada.

---

**Nota de publicación:** las direcciones IP corresponden a un entorno de laboratorio privado. Revisar antes de reutilizar el documento con infraestructura real o información sensible.
