# SOC-001 — Detección de posibles ataques de fuerza bruta

**Estado:** regla implementada y pruebas offline preparadas. Pendiente de validar en el Ubuntu del laboratorio.

## Objetivo

Identificar **cinco o más fallos de autenticación desde una misma dirección IP durante una ventana móvil de cinco minutos**, aun cuando no exista ningún acceso correcto posterior. La regla complementa SOC-002 (inicio correcto tras varios fallos).

## Fuente y campos

- Fuente: eventos Syslog reenviados por el PowerBeam a Ubuntu.
- Archivo: `/var/log/powerbeam/powerbeam.log` y archivos históricos.
- Mensajes que cuentan como fallo:
  - `Login attempt for nonexistent user from <IP>`
  - `Bad password attempt for '<usuario>' from <IP>`
- Tiempo utilizado: sello ISO 8601 de **recepción en Ubuntu**, dado que anteriormente se observaron desfases en la hora del dispositivo.
- Agrupación: IP cliente extraída de `from <IP>`, no la IP del equipo indicada por `source=`.

## Comportamiento

1. Leer el conjunto de registros, analizar el mensaje y ordenar por hora de recepción.
2. Mantener por IP las marcas de tiempo de fallos durante los cinco minutos anteriores.
3. Alertar cuando la cantidad alcance cinco, con límite de una alerta cada cinco minutos por IP.
4. No enviar notificaciones externas ni realizar bloqueos automáticos.

El umbral es una **hipótesis de laboratorio**, no una política calibrada con tráfico real. Un intento desde un usuario inexistente cuenta como fallo, igual que una contraseña equivocada.

## Ejecución

```bash
sudo cat /var/log/powerbeam/powerbeam.log.1 /var/log/powerbeam/powerbeam.log \
  | python3 scripts/bruteforce_detector.py
```

Para probar sin tocar el dispositivo:

```bash
python3 -m unittest discover -s tests -v
```

### Resultado esperado con los 11 eventos conocidos del Día 3

- 9 autenticaciones correctas.
- 1 contraseña incorrecta.
- 1 intento con usuario inexistente.
- **0 alertas SOC-001**, porque no hubo cinco fallos en cinco minutos.
- **1 alerta SOC-002** en la prueba anterior, porque sí hubo dos fallos y un acceso correcto posterior.

Esta diferencia es intencional: las reglas buscan patrones distintos.

## Validación y limitaciones

- Comprobar el parser, agrupación por IP, ventana temporal, umbral, mezcla de tipos, registros desordenados y supresión de avisos repetidos con las pruebas de `tests/test_bruteforce_detector.py`.
- Las IP y usuarios de prueba son ficticios y reservados para documentación.
- Un acceso desde NAT o un proxy puede agrupar varios usuarios detrás de una misma IP.
- El detector procesa archivos por lotes y **no** observa eventos continuamente ni persiste estado entre ejecuciones.
- El Syslog enviado por UDP puede perderse o ser manipulado si no se protege la red.
- Comprobar la sincronización horaria del PowerBeam sigue pendiente.
- Revisar los eventos completos y el contexto antes de clasificar una alerta como incidente.

## Próximos pasos

- Validación local del script y pruebas en Ubuntu.
- Añadir capturas saneadas de resultados y actualizar `README.md`.
- Explorar un modo de lectura incremental, alertas con identificador y deduplicación persistente.
