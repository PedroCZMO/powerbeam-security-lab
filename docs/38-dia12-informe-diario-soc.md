# Día 12 · Fase 6 — Informe diario SOC (V1)

## Finalidad

Generar un informe SOC diario, en texto o JSON, sin enviar correos, alterar evidencias, confirmar alertas ni modificar el token OAuth. El informe separa la **actividad por fecha del evento** de las **alertas pendientes ahora** y de la **salud técnica actual**.

La arquitectura usa dos procesos con distinta identidad y una frontera de datos agregados:

1. `soc_daily_metrics.py` se ejecuta como `powerbeam-monitor`: lee `alerts.jsonl` (V1) y el estado restringido de la cola; únicamente imprime estadísticas agregadas en JSON.
2. `soc_daily_report.py` se ejecuta como el usuario habitual: recibe esas estadísticas por `stdin`, comprueba su estructura, lee el estado de los servicios systemd y revisa el OAuth local con `resilience_report.collect`. No abre las fuentes de alertas ni necesita acceso al estado privado de la cola.

### Alcance y límites

- **Actividad diaria:** se cuenta cada `alert_id` único fechado en el día seleccionado, calculado a partir del `timestamp` del evento en `Europe/Madrid` (no su hora de detección ni de incorporación a la cola). Los duplicados idénticos se cuentan una sola vez; identificadores duplicados y contradictorios hacen fallar el informe.
- **Acuses del día:** se cuentan por `acknowledged_at` local del historial de la cola, independientemente de la fecha del evento.
- **Pendientes:** representan la cola en el momento de la lectura, **de cualquier fecha**. La antigüedad se calcula desde la hora del evento, nunca desde su entrada en la cola.
- **Solo V1:** no se agrega V3 para evitar contar detecciones duplicadas; los logs brutos syslog y las detecciones no convertidas en alertas no están incluidos.
- **Health de infraestructura:** se consultan propiedades systemd mediante el módulo existente; un servicio activo no garantiza ingestión real. OAuth es solo local (`oauth_remote=NOT_CHECKED`). Las notificaciones automáticas siguen desactivadas.
- **Seguridad:** no se imprimen IP, IDs, contenido de alertas, rutas sensibles ni credenciales; no se guardan informes por defecto. El JSON agregado se valida antes de mostrarse.
- **Disponibilidad:** una interrupción o falta de acceso a los archivos produce estado `UNKNOWN` y retorno distinto de cero; no se fabrica un estado `HEALTHY`.

## Instalación de prueba

Descomprimir el ZIP en la raíz del repositorio. Los tres archivos del paquete son:

- `scripts/soc_daily_metrics.py`
- `scripts/soc_daily_report.py`
- `tests/test_soc_daily_metrics.py`
- `tests/test_soc_daily_report.py`
- `docs/38-dia12-informe-diario-soc.md`

Probar los 34 casos nuevos:

```bash
python3 -m unittest discover -s tests -p 'test_soc_daily_*.py' -v
python3 -m unittest discover -s tests -q
```

La suma esperada es **402 pruebas** si la base contiene las **368** de la fase 5.

## Instalación del recolector con permisos restringidos

**Solo después de aprobar las pruebas:**

```bash
sudo install -o root -g root -m 0644 \
  scripts/soc_daily_metrics.py \
  /opt/powerbeam-monitor-v3/scripts/soc_daily_metrics.py
```

Los módulos `alert_queue.py` y `alert_backlog_health.py` ya están instalados en el mismo directorio por las fases anteriores.

## Consultar el día de hoy (Madrid)

Desde la raíz del repositorio, en tu usuario normal:

```bash
set -o pipefail
sudo -u powerbeam-monitor /usr/bin/python3 -B \
  /opt/powerbeam-monitor-v3/scripts/soc_daily_metrics.py \
  --alerts /var/lib/powerbeam-monitor/alerts.jsonl \
  --state /var/lib/powerbeam-monitor/alert-queue/state.json \
| python3 -B scripts/soc_daily_report.py \
  --daily-stdin \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json" \
  --format text
```

Para un día anterior, incluir `--date 2026-11-05` en la invocación de `soc_daily_metrics.py`. Para JSON en vez de texto, cambiar `--format text` por `--format json`.

**Los códigos de salida 0, 1 y 2** indican, respectivamente, datos aceptados con salud técnica operativa; advertencias/estado desconocido; fallo crítico o error. `WARNING` por antigüedad de backlog *no modifica* ningún archivo de estado.

## Precauciones

- No modificar permisos con `chmod -R 777` ni ejecutar scripts de reporte como root.
- No transferir el token OAuth a `powerbeam-monitor`.
- No publicar estados, archivos `.jsonl` reales, `LEEME-PRIMERO.txt` ni credenciales.
- No se necesita servicio o temporizador nuevo para esta fase; el comando es manual.
- Si se automatiza en el futuro, será necesario tratar los fallos de tubería con `pipefail`, controlar los permisos de cualquier archivo de salida y gestionar los volúmenes de logs.
