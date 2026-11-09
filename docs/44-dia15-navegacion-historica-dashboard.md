# Día 15 — Navegación histórica del dashboard (HTML local)

## Resultado

El laboratorio ya genera informes HTML independientes por fecha, por ejemplo
`index.html` para el ejercicio SOC-001 del **06/11/2026** y
`2026-11-04.html` para el ejercicio SOC-002 del **04/11/2026**.
El comando `soc_dashboard_history.py` crea un **índice estático privado**
(`historico.html`) que enlaza únicamente esos informes existentes.

La navegación no depende de un servidor, JavaScript, credenciales, archivos
originales de syslog ni cambios en los permisos del SOC.

## Desde Ubuntu, como usuario habitual

Desde la raíz del repositorio, tras un `git pull --ff-only origin main`:

```bash
python3 -B scripts/soc_dashboard_history.py \
  --dir "$HOME/.local/share/powerbeam-security-lab/soc-dashboard"

xdg-open "$HOME/.local/share/powerbeam-security-lab/soc-dashboard/historico.html"
```

Resultado esperado cuando hay dos días distintos:

```json
{"status": "CREATED", "file": "historico.html", "reports": 2, "inspection": "LOCAL_READ_ONLY", "state_modified": false, "emails_sent": 0, "tokens_modified": false}
```

Se muestran las fechas ordenadas de más reciente a más antigua. El índice
verifica que el directorio sea privado (0700), que cada archivo sea regular,
pertenezca a tu usuario, tenga modo 0600 y sea un informe generado en
el formato esperado. No sigue enlaces simbólicos, rechaza fechas/archivos
incoherentes y no expone datos de las alertas.

**Importante:** `historico.html` no actualiza las métricas y las páginas
de cada día conservan su propia fecha de generación. La actividad se contabiliza
por fecha del evento; pendientes y salud describen el momento de cada captura.
Para incluir un día nuevo, primero genera su HTML con `soc_dashboard.py`
y después ejecuta otra vez el generador del índice.

## Pruebas

```bash
python3 -m unittest discover -s tests -p 'test_soc_dashboard_history.py' -v
python3 -m unittest discover -s tests -q
```

Los tests incluyen navegación, control de permisos, rechazo de symlinks,
fechas inconsistentes, tamaño de archivos, no sobrescritura si hay errores,
y generación atómica del índice. Esta fase añade **15** pruebas al conjunto
anterior de **502**. La cantidad definitiva debe confirmarse mediante CI.

No subir los HTML generados, tokens, registros originales ni archivos
personales a GitHub.
