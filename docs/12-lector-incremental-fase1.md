# Día 6 — Lector incremental experimental (fase 1)

## Objetivo

Prototipo aislado para leer solo líneas nuevas de `powerbeam.log` y de los archivos rotados sin comprimir (`powerbeam.log.1`, `.2`, etc.). No altera rsyslog, las reglas de detección, los logs ni las unidades systemd existentes.

## Diseño

- Usa la identidad del archivo (`st_dev` + `st_ino`) y un desplazamiento en bytes para continuar tras reiniciar el proceso.
- Detecta `rename + create` de logrotate: puede recuperar líneas pendientes del archivo renombrado y leer el archivo nuevo.
- No confirma fragmentos finales sin salto de línea, de modo que puede procesarlos cuando se completen.
- Guarda el estado en JSON de manera atómica y con permiso `0600`, pero **solo si se especifica `--commit`**.
- Rechaza estados corruptos y enlaces simbólicos usados como archivos de entrada.

## Prueba aislada

```bash
python3 -m unittest discover -s tests -v
```

Se recomienda practicar con una carpeta `logs` temporal. `--commit` solo registra avance de lectura de prueba, **no significa que las alertas se hayan procesado**. Nunca conectar este modo al temporizador de producción.

## Limitaciones críticas y fase siguiente

**No implementar todavía en producción.**

1. Los archivos `.gz` se omiten: tras varias rotaciones o una parada prolongada podría haber eventos no leídos. Se necesita estrategia de recuperación para archivos comprimidos.
2. No conserva el contexto de fallos de los cinco minutos anteriores, necesario para las reglas SOC-001 y SOC-002 cuando una secuencia atraviesa dos ejecuciones.
3. No existe transacción conjunta entre escribir alertas y confirmar cursores. El monitor definitivo debe guardar las alertas primero y confirmar el estado solo después, con recuperación ante fallos.
4. Requiere gestionar sustitución/truncado de archivos, colisiones y posibles pérdidas si logrotate elimina históricos antes de volver a procesarlos.
5. No implementa bloqueo entre ejecuciones ni ingestión continua real; solo prueba la mecánica de lectura.

## Próximas tareas

Añadir contexto temporal persistente y gestión de `.gz`; integrar con `security_monitor.py`; comprobar errores de escritura, recuperación e idempotencia; y solo entonces probar una unidad systemd nueva, manteniendo activo el servicio v1.1 actual hasta superar la validación.
