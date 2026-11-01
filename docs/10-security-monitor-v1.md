# PowerBeam Security Monitor v1.0 — SOC-001 + SOC-002

**Fecha de preparación:** 01/11/2026  
**Estado:** integrado y validado con 24 pruebas automatizadas en entorno de desarrollo; pendiente de ejecutar contra los logs del equipo Ubuntu del laboratorio.

## Objetivo

Integrar los detectores existentes para analizar **un lote de registros Syslog** y emitir alertas normalizadas en **JSONL**. Sin alterar la configuración del PowerBeam, bloquear IP ni enviar tráfico de prueba.

### Componentes reutilizados

- `scripts/auth_detector.py`: SOC-002, inicio de sesión correcto tras **2 o más** intentos fallidos en 5 minutos. Se incorpora una función `detect(lines)` reutilizable sin cambiar la salida del comando anterior.
- `scripts/bruteforce_detector.py`: SOC-001, **5 o más** fallos de una IP en 5 minutos, con enfriamiento de 5 minutos por IP.
- `scripts/security_monitor.py`: correlación y resumen de ambas reglas, IDs estables y almacenamiento opcional en JSONL.

Para ambos casos, un fallo puede ser `Bad password attempt` o `Login attempt for nonexistent user`. Los eventos se agrupan por IP de cliente (`from ...`). La fecha utilizada es la de **recepción en Ubuntu** (ISO 8601), porque se observaron desfases en el reloj del PowerBeam.

## Flujo

```text
PowerBeam -> Syslog -> rsyslog -> powerbeam.log + rotaciones
                                    |
                   lectura puntual de archivos (sudo)
                                    |
                              stdin (pipe)
                                    |
                       security_monitor.py
                           /             \
                       SOC-001         SOC-002
                           \             /
                          alertas ordenadas
                                    |
                      alerts/alerts.jsonl (opcional)
```

**No es un SIEM ni un monitor en tiempo real.** Lee el lote completo cada vez; el código de correlación no mantiene estado entre ejecuciones. El JSONL únicamente evita duplicar las alertas con el mismo ID cuando se repite el análisis del mismo lote.

## Uso

Desde la raíz del repositorio, con el código disponible en `scripts/`:

### 1. Ejecutar pruebas offline

```bash
python3 -m unittest discover -s tests -v
```

Tras incorporar los tests nuevos, hay **24 pruebas** (6 SOC-002 + 10 SOC-001 + 8 de integración). Si falla alguna, no publicar aún.

### 2. Analizar archivos actuales e históricos, incluidos .gz

El directorio `/var/log/powerbeam/` no permite expandir el comodín `*` desde una shell sin permisos, aunque el comando posterior comience con `sudo`. Por tanto la expansión debe realizarla **la shell con privilegios**, sin ejecutar el detector Python como root:

```bash
set -o pipefail
sudo bash -c '
shopt -s nullglob
for f in /var/log/powerbeam/powerbeam.log*; do
  case "$f" in
    *.gz) gzip -dc -- "$f" ;;
    *) cat -- "$f" ;;
  esac
done
' | python3 scripts/security_monitor.py --output alerts/alerts.jsonl
```

Si se desea observar los resultados sin guardar alertas, omitir `--output alerts/alerts.jsonl`.

**Seguridad:** `sudo` solo abre y lee archivos de registro. El analizador se ejecuta sin privilegios elevados; el JSONL generado puede contener IP y horarios, por lo que no debe publicarse. Añadir `alerts/` al `.gitignore` (sin reemplazar las reglas existentes).

### 3. Mostrar las alertas guardadas

JSONL contiene un objeto JSON por línea. Para mostrar las alertas formateadas:

```bash
python3 -c 'import json; from pathlib import Path; [print(json.dumps(json.loads(x), indent=2, ensure_ascii=False)) for x in Path("alerts/alerts.jsonl").read_text().splitlines() if x.strip()]'
```

Si no hubo alertas, el archivo no se crea: esto es normal.

## Estructura de una alerta (ejemplo con IP ficticia)

```json
{"alert_id":"SOC-002-xxxxxxxxxxxxxxxx","timestamp":"2026-10-30T12:22:45+01:00","rule_id":"SOC-002","severity":"medium","source_ip":"192.0.2.10","failed_attempts":2,"window_minutes":5,"description":"Autenticación correcta tras varios fallos"}
```

`alert_id` se calcula de manera determinista a partir de regla, IP y sello temporal; volver a analizar el mismo archivo **no** añade esa alerta dos veces a `alerts/alerts.jsonl`. No se proporciona bloqueo entre procesos ni protección frente a datos maliciosos inyectados en Syslog.

## Resultados esperados con las evidencias conocidas (30/10/2026)

- Eventos clasificados: **9 accesos correctos**, **1 contraseña incorrecta**, **1 usuario inexistente**.
- SOC-001: **0 alertas** (no se alcanzan 5 fallos).
- SOC-002: **1 alerta** (dos fallos seguidos de un éxito desde la misma IP).
- Primer análisis con `--output`: **1 alerta escrita**; segunda ejecución idéntica: **0 nuevas**.

Estas cifras son una **expectativa** basada en los registros vistos el viernes. Pueden cambiar con nuevos eventos o si no se incluyen todos los históricos. Si el programa indica 0 líneas recibidas, devuelve código de error; si hay líneas pero 0 eventos de autenticación, muestra advertencia.

## Evidencia y seguridad operacional

- No subir `/var/log/powerbeam/`, `alerts/`, credenciales, backups, tokens ni logs sin sanitizar.
- Los eventos reflejan pruebas autorizadas; una alerta no prueba una intrusión.
- Validación del reloj NTP del PowerBeam pendiente.
- Syslog UDP puede sufrir pérdidas y no ofrece autenticación fuerte de origen.
- No probado en alta concurrencia, grandes volúmenes, archivos parcialmente escritos, truncamiento o fallos de energía durante escrituras JSONL.
- Antes de automatizar la ejecución, desarrollar una lectura incremental y una deduplicación/estado adecuados a eventos en streaming.

## Publicación en GitHub

Revisar los cambios antes de confirmarlos:

```bash
git status
git diff -- scripts/auth_detector.py
git add scripts/auth_detector.py scripts/security_monitor.py tests/test_security_monitor.py docs/10-security-monitor-v1.md .gitignore
git diff --cached --check
git diff --cached --stat
git commit -m "feat: integrate SOC-001 and SOC-002 monitor with JSONL alerts"
git push origin main
```

Conservar `bruteforce_detector.py` intacto; el monitor importa su función `detect`.
