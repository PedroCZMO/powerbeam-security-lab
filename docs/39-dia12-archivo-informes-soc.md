# Día 12 · Fase 7 — Archivo privado de informes SOC (V1)

## Objetivo

Conservar **instantáneas inmutables** de informes diarios JSON ya agregados mediante `soc_daily_metrics.py` y `soc_daily_report.py`, sin recopilar ni archivar las evidencias originales y sin tocar los cuatro temporizadores.

Una instantánea tiene dos líneas temporales:

- **`report_date`**: fecha (Europe/Madrid) de las alertas V1 contabilizadas por su fecha de evento y acuses contabilizados por la fecha de reconocimiento.
- **`captured_at_utc`**: momento en que se guardó el informe. `pending_at_capture` y `health_at_capture` son estados **de ese momento**, aunque el informe trate de un día pasado.

Por ello, al consultar el 4 de noviembre **el 6 de noviembre**, se puede recuperar una SOC-002 del día 4, pero **no** se puede reconstruir cómo estaban la cola o systemd el día 4. Las métricas históricas podrían cambiar si aparecen más registros con esa fecha.

## Archivos incluidos

- `scripts/soc_snapshot_archive.py`: importa un informe diario JSON por `stdin`, valida su contrato, elimina campos no permitidos, guarda archivos privados y lista las instantáneas.
- `tests/test_soc_snapshot_archive.py`: 32 pruebas (incluida compatibilidad real con los módulos existentes).
- `docs/39-dia12-archivo-informes-soc.md`: este documento.

## Diseño y límites de seguridad

1. **Dos identidades**: `soc_daily_metrics.py` consulta los archivos de V1 como `powerbeam-monitor`; `soc_daily_report.py` y el nuevo archivador se ejecutan como el usuario habitual. No se cambian permisos del estado ni se copia el token al usuario monitor.
2. **El archivador solo ve agregados**: fecha, contadores de reglas/severidades, pendientes agregados y estados de salud. Rechaza reportes incorrectos y descarta cualquier campo extra, incluidos posibles tokens, IP e IDs de alerta.
3. **Almacenamiento privado**: predeterminado `~/.local/share/powerbeam-security-lab/soc-reports`. Directorio modo `0700`, cada archivo `0600`; exige que el directorio padre ya sea privado y del usuario. No sigue enlaces simbólicos del directorio de salida.
4. **Sin sobrescritura**: cada ejecución genera un nombre nuevo que incluye fecha del informe, instante de captura y sufijo aleatorio. La publicación se hace escribiendo un temporal, sincronizando y enlazándolo sin reemplazar archivos existentes.
5. **Sin automatización todavía**: no instala ni habilita unidades systemd, no envía correos, no toca alertas ni renueva o modifica el token OAuth.
6. **No publicar informes privados**: aunque sean métricas, estos ficheros son datos operativos; no subirlos al repositorio GitHub. `LEEME-PRIMERO.txt` sigue excluido de los commits.

## Validar pruebas

```bash
python3 -m unittest discover -s tests -p 'test_soc_snapshot_archive.py' -v
python3 -m unittest discover -s tests -q
```

La expectativa es **32 pruebas nuevas**, para un total de **434**, si el repositorio tenía las 402 anteriores.

## Previsualizar sin escribir (día 4 de noviembre)

Desde la raíz del repositorio:

```bash
set -o pipefail
sudo -u powerbeam-monitor /usr/bin/python3 -B \
  /opt/powerbeam-monitor-v3/scripts/soc_daily_metrics.py \
  --alerts /var/lib/powerbeam-monitor/alerts.jsonl \
  --state /var/lib/powerbeam-monitor/alert-queue/state.json \
  --date 2026-11-04 \
| python3 -B scripts/soc_daily_report.py \
  --daily-stdin \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json" \
  --format json \
| python3 -B scripts/soc_snapshot_archive.py save --dry-run
```

Esperado: `saved=false`, `report_date=2026-11-04` y `snapshot_context=RETROSPECTIVE_ACTIVITY_WITH_CURRENT_STATE`.

## Guardar una instantánea real

Cuando el comando anterior funcione, repetirlo **quitando `--dry-run`**:

```bash
set -o pipefail
sudo -u powerbeam-monitor /usr/bin/python3 -B \
  /opt/powerbeam-monitor-v3/scripts/soc_daily_metrics.py \
  --alerts /var/lib/powerbeam-monitor/alerts.jsonl \
  --state /var/lib/powerbeam-monitor/alert-queue/state.json \
  --date 2026-11-04 \
| python3 -B scripts/soc_daily_report.py \
  --daily-stdin \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json" \
  --format json \
| python3 -B scripts/soc_snapshot_archive.py save
```

Para guardar un informe del día actual, omitir `--date` del recolector. El archivador lo identificará como `SAME_DAY_PARTIAL_ACTIVITY_WITH_CURRENT_STATE` (la actividad del día puede no estar completa).

## Listar instantáneas

```bash
python3 -B scripts/soc_snapshot_archive.py list
```

Solo muestra nombres de archivo y fecha del informe, sin abrir ni imprimir datos sensibles. Para comprobar permisos de un archivo concreto, usar `stat` sobre el archivo local que se ha creado, **no pegar su contenido sin revisarlo**.

Si aparece `PARENT_DIRECTORY_NOT_PRIVATE`, revisar la propiedad y permisos de `~/.local/share/powerbeam-security-lab`; el comando seguro habitual, si es un directorio personal tuyo, sería:

```bash
chmod 700 "$HOME/.local/share/powerbeam-security-lab"
```

No utilizar `chmod -R 777` ni ejecutar este archivador como root.

## Errores, duplicados y trabajo futuro

- Archivo incompleto, esquema inválido, informe en estado `UNKNOWN` o fecha futura => error, sin escribir instantánea.
- Varias ejecuciones sobre la misma fecha crean **capturas diferentes**; no se borra ninguna ni se sobrescribe otra. Esto permite comparar qué cambió entre capturas, pero no evita múltiples informes similares.
- `set -o pipefail` permite advertir fallos de cualquiera de los tres procesos. Un reporte JSON válido puede ser almacenado aun si su generador devuelve código 1/2 por salud WARNING/CRITICAL; es correcto archivarlo como evidencia de degradación.
- Próxima fase: comparación explícita de actividad entre días y, más adelante, automatización con rotación/retención definida. No es un backup de los registros brutos.
