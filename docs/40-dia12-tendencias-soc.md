# Día 12 — Fase 8: tendencias de alertas SOC archivadas (V1)

## Objetivo

Comparar **solo los recuentos agregados de alertas V1 por fecha del evento** de las instantáneas JSON creadas en la fase 7. No se consultan las alertas originales, ni el estado privado de la cola, ni OAuth. El comparador es **local, de solo lectura y sin red**.

Archivos nuevos:

- `scripts/soc_trends.py`: comparador y CLI (`text`/`json`).
- `tests/test_soc_trends.py`: 40 comprobaciones, con archivos temporales.
- `docs/40-dia12-tendencias-soc.md`: esta guía.

**Dependencia:** `scripts/soc_snapshot_archive.py` de la fase 7, ya instalado en el repositorio.

## Ejemplo real: 4 y 5 de noviembre de 2026

Estas dos fechas ya tienen instantáneas archivadas. **No hay que volver a generarlas ni copiar archivos privados al repositorio.** Desde la raíz de `powerbeam-security-lab`:

```bash
python3 -m unittest discover -s tests -p 'test_soc_trends.py' -v
python3 -m unittest discover -s tests -q

python3 -B scripts/soc_trends.py \
  --start 2026-11-04 \
  --end 2026-11-05 \
  --format text

python3 -B scripts/soc_trends.py \
  --start 2026-11-04 \
  --end 2026-11-05 \
  --format json
```

Objetivo de regresión en el repositorio del usuario: **474 pruebas** (= 434 previas + 40 nuevas). El mensaje de `usage` del test de Gmail API puede continuar apareciendo sin que implique un fallo; el resultado debe terminar en `OK`.

La carpeta por defecto coincide con la fase 7:

```text
~/.local/share/powerbeam-security-lab/soc-reports/
```

Se ejecuta **sin `sudo`**, como el usuario que generó las instantáneas. No se requiere el token Gmail.

## Semántica de los datos

- `RECORDED`: instantánea generada después del día analizado; los recuentos V1 de ese día son utilizables como observación archivada, pero no prueban ingestión completa.
- `PARTIAL_AT_CAPTURE`: la instantánea se tomó durante el mismo día; no se considera día completo aunque después avance el calendario, salvo que exista una instantánea retrospectiva posterior.
- `MISSING_SNAPSHOT`: no hay instantánea para esa fecha. **No significa cero alertas.** Sus recuentos son `null` en JSON y `N/D` en texto.
- Si existen varias instantáneas para la misma fecha se selecciona la de captura más reciente. Si sus recuentos difieren se marca `revisions_detected=true`. No se suman las instantáneas, para no duplicar alertas.
- `change_from_previous_day`: diferencia absoluta frente al día inmediatamente anterior, solo cuando ambos días son `RECORDED`.
- `change_percent`: variación porcentual si la base del día anterior es mayor que cero; si es cero se devuelve `null` (división indefinida).
- `period_total_alerts` es `null` cuando falta un día o hay algún día parcial. `known_complete_day_alerts` suma únicamente los días `RECORDED` disponibles.
- Las métricas diarias proceden de **alertas V1 por fecha del evento**, no de eventos de autenticación sin alerta ni del monitor V3.
- **La ausencia de alertas no certifica ausencia de amenazas, ni continuidad de ingestión.** No se infieren estados pasados a partir de los campos `health_at_capture` o `pending_at_capture`.

## Seguridad

- Modo **solo lectura**; sin modificar evidencias, colas ni instantáneas; sin enviar correo ni actualizar tokens.
- Directorio de archivo privado validado mediante la misma política de la fase 7.
- Archivos limitados a 64 KiB, nombres con formato fijo, directorio con un máximo de 10 000 entradas y periodo de 2 a 31 días.
- Se rechazan instantáneas con permisos de grupo/otros, symlinks, hardlinks adicionales, esquemas corruptos, recuentos incoherentes, contextos falsos y discordancia entre nombre y fecha de captura.
- Errores devuelven códigos genéricos sin imprimir rutas, IP, IDs, token o contenido JSON. El comparador solo publica claves de datos permitidas.
- No se genera firma criptográfica ni se promete resistencia contra un actor con control de la cuenta o del disco. Se trata de validación estructural y de permisos.

## Códigos de salida

- `0`: rango con instantáneas retrospectivas para todos los días (`COMPLETE_SNAPSHOTS`).
- `1`: hay días sin instantánea o parciales (`INCOMPLETE_SNAPSHOTS`); resultado informativo, no un error de Python.
- `2`: rango inválido, directorio no seguro o instantánea corrupta/insegura (`UNKNOWN`).

**Importante:** `COMPLETE_SNAPSHOTS` indica cobertura de instantáneas, **no completitud de logs ni de detecciones**.

## Publicación selectiva en GitHub

```bash
git status --short
git add scripts/soc_trends.py tests/test_soc_trends.py docs/40-dia12-tendencias-soc.md
git diff --cached --check
git diff --cached --name-only
git commit -m "feat: analyze archived SOC alert trends"
git push origin main
```

Nunca utilizar `git add .` mientras `LEEME-PRIMERO.txt` u otros archivos personales estén sin seguimiento. No subir los archivos reales de `soc-reports/`.
