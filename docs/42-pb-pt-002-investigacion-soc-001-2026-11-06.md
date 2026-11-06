# PB-PT-002 — Detección e investigación de cinco fallos SSH reales

**Proyecto:** PowerBeam Security Lab  
**Tipo de ejercicio:** Purple Team (Red Team / Blue Team)  
**Fecha:** 6 de noviembre de 2026  
**Regla:** SOC-001 — Posibles intentos de fuerza bruta  
**Severidad de la alerta:** `medium`  
**Estado técnico de la investigación:** completada  
**Estado de la cola SOC:** alerta reconocida (`ack`, motivo `reviewed`); ninguna alerta pendiente  
**Clasificación:** verdadero positivo de la regla; actividad de laboratorio autorizada, sin compromiso observado en la ventana examinada.

> Este informe documenta un ejercicio autorizado sobre un equipo de laboratorio propio. No se utilizaron herramientas automatizadas de fuerza bruta ni se incluyen contraseñas.

## 1. Objetivo

Comprobar de extremo a extremo que cinco intentos fallidos de autenticación SSH, originados en Kali Linux contra una Ubiquiti PowerBeam física, son enviados como telemetría syslog a Ubuntu y producen una alerta SOC-001 en dos canalizaciones de monitorización: V1 (histórico/batch) y V3 (incremental).

La regla SOC-001 correlaciona **al menos cinco fallos desde una misma IP durante cinco minutos**. No pretende demostrar por sí sola que exista un atacante malicioso ni un acceso comprometido.

## 2. Alcance y topología

| Función | Elemento | Dirección |
|---|---|---|
| Origen de las pruebas (Red Team) | Kali Linux en máquina virtual, interfaz puente | `192.168.1.30` |
| Objetivo | Ubiquiti PowerBeam, servidor SSH Dropbear | `192.168.1.20:22/TCP` |
| Sensor/servidor SOC (Blue Team) | Ubuntu con rsyslog y monitores V1/V3 | `192.168.1.10` |
| Ingesta syslog | UDP en Ubuntu | `5514/UDP` |

Ruta de procesamiento: `Kali → PowerBeam/Dropbear → rsyslog Ubuntu → archivos /var/log/powerbeam/ → monitor V1 / monitor V3 → JSONL`.

La V1 genera alertas en `/var/lib/powerbeam-monitor/alerts.jsonl`, que constituye la fuente de la cola consultada. La V3 guarda sus resultados por separado en `/var/lib/powerbeam-monitor/parallel-v3/alerts-v3.jsonl`.

## 3. Cronología verificable

Todos los tiempos exteriores de recepción syslog usan `+01:00` (hora local del laboratorio). En cada registro, la marca de tiempo interna de Dropbear aparecía una hora antes; la correlación utiliza la marca exterior de recepción registrada por Ubuntu.

| Nº | Marca de tiempo de recepción | Proceso Dropbear | Puerto de origen | Resultado |
|---:|---|---|---:|---|
| 1 | `2026-11-06T18:34:26.838954+01:00` | `dropbear[860]` | 53042 | Contraseña incorrecta |
| 2 | `2026-11-06T18:34:31.160524+01:00` | `dropbear[861]` | 43882 | Contraseña incorrecta |
| 3 | `2026-11-06T18:34:35.922592+01:00` | `dropbear[862]` | 43894 | Contraseña incorrecta |
| 4 | `2026-11-06T18:34:40.775578+01:00` | `dropbear[863]` | 56028 | Contraseña incorrecta |
| 5 | `2026-11-06T18:34:45.560412+01:00` | `dropbear[864]` | 56040 | Contraseña incorrecta |

**Intervalo entre el primer y el último fallo:** aproximadamente **18,72 segundos**. Los cinco fallos comparten IP de origen (`192.168.1.30`) y usuario objetivo (`ubnt`).

Cada conexión generó tres registros: `Child connection`, `Bad password attempt` y `Exit before auth (user 'ubnt', 1 fails): Exited normally`. Por tanto, se observaron **15 líneas de Dropbear, pero solo cinco fallos de autenticación**: los cierres de sesión no deben contarse como fallos adicionales.

Una prueba aislada a las `13:45:31+01:00` del mismo día generó otro fallo SSH desde Kali, pero **queda fuera** de la ventana de cinco minutos del ejercicio de las 18:34 y no forma parte de la alerta.

## 4. Evidencia original representativa

Registro del quinto fallo (extraído de `/var/log/powerbeam/powerbeam.log`):

```text
2026-11-06T18:34:45.560412+01:00 source=192.168.1.20 <84>Nov  6 17:34:45 dropbear[864]: Bad password attempt for 'ubnt' from 192.168.1.30:56040
```

El campo `source=192.168.1.20` identifica al **emisor del syslog**; la dirección situada después de `from` (`192.168.1.30`) es la **IP cliente** responsable del intento SSH. La extracción del SOC conserva esta distinción.

La revisión de los registros de Dropbear en `2026-11-06T18:34:00+01:00` a `18:40:00+01:00` mostró exactamente cinco conexiones, cinco fallos y cinco cierres antes de autenticarse; **no mostró eventos `Password auth succeeded` en esa ventana**. Esto no permite descartar accesos en otros momentos o por otros servicios.

## 5. Detección automática: V1

El servicio `powerbeam-monitor.service`, ejecutado como `powerbeam-monitor`, finalizó correctamente a las **18:35:01**. Su resumen indicó:

```text
Líneas leídas: 66
Eventos de autenticación reconocidos: 27
Correctas: 17
Contraseñas incorrectas: 9
Usuarios inexistentes: 1
Alertas SOC-001: 1
Alertas SOC-002: 2
[SOC-001] 2026-11-06T18:34:45.560412+01:00 origen=192.168.1.30 fallos=5 id=SOC-001-36f69895f7b28039
Alertas nuevas añadidas a /var/lib/powerbeam-monitor/alerts.jsonl: 1
```

Los contadores de 66 líneas, 27 autenticaciones y 2 SOC-002 **incluyen el histórico**, no únicamente esta prueba. Las dos SOC-002 eran alertas anteriores.

En la ejecución posterior de **18:40:01**, V1 reconoció la misma SOC-001 pero añadió **0** alertas nuevas: deduplicación observada.

**Tiempo desde el quinto fallo hasta la ejecución que detectó el caso:** aproximadamente **15,44 segundos**, condicionado por la programación del temporizador.

## 6. Detección automática: V3

El servicio `powerbeam-monitor-v3.service`, que procesa líneas nuevas de forma incremental, finalizó correctamente a las **18:37:01**:

```text
Líneas nuevas: 15
Eventos autenticación nuevos: 5
Alertas SOC-001: 1
Alertas SOC-002: 0
Alertas JSONL nuevas: 1
```

En su ejecución posterior, a las **18:42:01**, informó de **0** líneas nuevas y **0** alertas nuevas. Esto respalda que no reprocesó el mismo conjunto de eventos como nuevos.

**Tiempo desde el quinto fallo hasta la ejecución que detectó el caso:** aproximadamente **135,44 segundos**. La diferencia respecto a V1 refleja también el calendario de ejecución; no es una medida aislada del rendimiento algorítmico.

V1 y V3 tienen **canalizaciones de lectura distintas**, pero reutilizan código de detección común. La concordancia valida la consistencia de ambos procesamientos para este caso; no supone dos algoritmos de detección independientes.

## 7. Concordancia de alertas y cola

En cada archivo JSONL (`alerts.jsonl` de V1 y `alerts-v3.jsonl` de V3) se recuperó **exactamente una coincidencia** para el ID investigado. La comparación de los objetos JSON devolvió: `RESULTADO: ALERTAS IDÉNTICAS`.

Alerta almacenada en ambas versiones:

```json
{
  "alert_id": "SOC-001-36f69895f7b28039",
  "description": "Posibles intentos de fuerza bruta",
  "failed_attempts": 5,
  "rule_id": "SOC-001",
  "severity": "medium",
  "source_ip": "192.168.1.30",
  "timestamp": "2026-11-06T18:34:45.560412+01:00",
  "window_minutes": 5
}
```

La consulta de la cola de alertas de V1, tras el ejercicio, devolvió:

```json
{
  "action": "status",
  "seen": 3,
  "pending": 1,
  "pending_alerts": [
    {
      "alert_id": "SOC-001-36f69895f7b28039",
      "rule_id": "SOC-001",
      "severity": "medium",
      "source_ip": "192.168.1.30",
      "timestamp": "2026-11-06T18:34:45.560412+01:00"
    }
  ],
  "acknowledged": 0
}
```

Por tanto, la **detección y el almacenamiento están verificados**. La captura anterior corresponde al estado **antes del reconocimiento**. El cierre operativo posterior se documenta en el apartado 11. La V3 no alimenta esta cola principal, sino su archivo de validación paralelo.

## 8. Triage y decisión del analista SOC L1

- **¿Se activó correctamente la regla?** Sí: cinco fallos desde la misma IP en menos de cinco minutos.
- **¿Se identificó correctamente el origen?** Sí: `192.168.1.30`, frente a `192.168.1.20` como emisor syslog.
- **¿Se observó una autenticación SSH exitosa durante la ventana revisada?** No.
- **¿La actividad fue autorizada?** Sí, correspondió a un ejercicio manual del laboratorio.
- **¿Hay evidencia de compromiso del dispositivo?** No en las evidencias revisadas; esto no equivale a una auditoría completa.
- **Clasificación:** *True Positive* de comportamiento/regla, **actividad autorizada de prueba**. No clasificar como incidente malicioso confirmado.
- **Acción ejecutada:** investigación completada y alerta reconocida con motivo `reviewed` en la cola principal. Los registros JSONL de detección se conservan como evidencia del caso.

## 9. Pruebas de regresión y cambios de código

Se añadió `tests/test_purple_team_dropbear.py`, con ocho pruebas offline del formato Dropbear, atribución de IP, hora de recepción, exclusión de errores de negociación, no duplicación de fallos y correlación SOC-001/SOC-002 con datos sintéticos. Resultado comunicado de la batería local: **482 pruebas, OK**. La ejecución de CI de estas ocho pruebas adicionales **no ha sido verificada en este informe**.

Los hashes SHA-256 de `auth_detector.py`, `bruteforce_detector.py` y `security_monitor.py` coincidieron entre el repositorio y las instalaciones V1/V3. No fue necesario modificar los detectores desplegados para que el ejercicio produjera las alertas.

## 10. Limitaciones y acciones de mejora

1. El disparo de SOC-001 demuestra detección de un patrón temporal de fallos; **no demuestra por sí solo fuerza bruta automatizada ni intención maliciosa**.
2. Revisar por separado el alcance de la telemetría SSH y cualquier configuración de bloqueo de cuenta antes de nuevas pruebas.
3. Mantener la distinción entre **hora de recepción** y **hora interna del equipo** para evitar errores de correlación.
4. Se verificó el ACK y la transición de la cola a `pending=0` y `acknowledged=1`. Para una comprobación formal adicional de preservación de evidencia, puede volver a consultarse el JSONL original tras el ACK.
5. Conservar, cuando se necesite evidencia formal, una copia controlada de los logs y sus hashes, sin publicar datos sensibles ni rutas de secretos.
6. Documentar latencias con referencia a los temporizadores; no comparar como rendimiento del detector la diferencia de horas de ejecución.

## 11. Cierre administrativo (completado)

- **Fecha de cierre:** 6 de noviembre de 2026.
- **Hora exacta del ACK:** no registrada en las evidencias facilitadas; no se infiere.
- **ID reconocido:** `SOC-001-36f69895f7b28039`.
- **Acción:** `ack`.
- **Motivo:** `reviewed` (investigada y clasificada como prueba autorizada).
- **Resultado:** reconocimiento satisfactorio; ninguna alerta pendiente en la cola principal.

Comando ejecutado bajo la cuenta de servicio `powerbeam-monitor`:

```bash
sudo -u powerbeam-monitor /usr/bin/python3 -B \
/opt/powerbeam-monitor-v3/scripts/alert_queue.py ack \
--source /var/lib/powerbeam-monitor/alerts.jsonl \
--state /var/lib/powerbeam-monitor/alert-queue/state.json \
--alert-id SOC-001-36f69895f7b28039 \
--reason reviewed
```

Respuesta observada:

```json
{
  "action": "ack",
  "alert_id": "SOC-001-36f69895f7b28039",
  "reason": "reviewed",
  "pending": 0,
  "acknowledged": 1
}
```

Comprobación posterior de `alert_queue.py status`:

```json
{
  "action": "status",
  "seen": 3,
  "pending": 0,
  "pending_alerts": [],
  "acknowledged": 1
}
```

**Interpretación:** la cola principal conoce tres alertas históricas; la SOC-001 del ejercicio quedó reconocida y ninguna alerta sigue pendiente. El ACK es un **cierre de seguimiento en la cola**, no una eliminación de la evidencia ni prueba de que se haya realizado una respuesta de contención. El estado posterior del archivo JSONL original no se releyó después del ACK en las evidencias presentadas; su persistencia anterior sí está acreditada en el apartado 7.

**Conclusión final:** El ejercicio PB-PT-002 valida con telemetría real la recepción, interpretación, correlación, persistencia y reconocimiento de una alerta SOC-001 originada desde Kali. Los registros de V1 y V3 fueron idénticos; no se observaron autenticaciones SSH exitosas durante la ventana investigada. **Caso cerrado en la cola como verdadero positivo de detección, debido a actividad de laboratorio autorizada.**
