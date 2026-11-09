# Día 15 — Histórico SOC compatible con el portal de archivos de Firefox

## Problema observado en Ubuntu

El índice original contenía enlaces a archivos hermanos:
`index.html` (06/11/2026) y `2026-11-04.html` (04/11/2026).
Al abrir `historico.html` mediante `xdg-open`, Firefox podía recibir solo
un archivo a través del **portal de documentos del escritorio**:

```text
/run/user/1000/doc/<identificador>/historico.html
```

Por eso un enlace relativo apuntaba a
`/run/user/1000/doc/<identificador>/index.html` y fallaba con
«Archivo no encontrado», aunque los informes originales sí existían y
tenían permisos correctos.

## Solución aplicada

`scripts/soc_dashboard_history.py` ahora genera un
**único archivo HTML autocontenido**, que presenta una tarjeta por fecha.
Al pulsar «Ver métricas agregadas ▾» despliega los datos **dentro de la
misma página**, sin intentar abrir `index.html` u otros archivos.

Para cada día se muestran los contadores de alertas V1, SOC-001,
SOC-002, severidades y acuses. También se muestra el estado de pendientes
y salud **en el momento en que se generó cada informe**, sin reconstruir
históricamente los servicios.

No se introducen servidores, JavaScript, redes, permisos públicos o
dependencias nuevas.

## Uso desde Ubuntu

Desde la raíz del repositorio actualizado:

```bash
git status --short
git pull --ff-only origin main

python3 -m unittest discover -s tests -p 'test_soc_dashboard_history.py' -v

python3 -B scripts/soc_dashboard_history.py \
  --dir "$HOME/.local/share/powerbeam-security-lab/soc-dashboard"

xdg-open "$HOME/.local/share/powerbeam-security-lab/soc-dashboard/historico.html"
```

Cuando existan los informes de los días 4 y 6, el programa debería
informar de `reports=2`. En Firefox **pulsa una tarjeta** y comprueba
que se despliegan las métricas en la propia página.

Los HTML `index.html` y `2026-11-04.html` siguen intactos; el generador
solo sustituye de forma atómica el índice `historico.html`.

## Seguridad

- El programa sigue rechazando directorios inseguros, archivos que no
  pertenezcan al usuario, permisos distintos de 0600, symlinks,
  informes mayores de 128 KiB y fechas incompatibles con el nombre.
- Extrae únicamente contadores y estados de campos específicos,
  comprobando que los totales cuadran. **No incrusta el HTML original** ni
  copia campos adicionales, aunque estos incluyan texto arbitrario.
- Los nuevos paneles son elementos HTML `<details>` y `<summary>`
  nativos, sin scripts, iframes ni peticiones de red.
- Conserva el archivo índice con permisos 0600 en una carpeta 0700.
- Si hay algún informe inválido, no sobrescribe el índice anterior.
- No accede a los logs originales, el estado privado de alertas ni a
  credenciales de Gmail.

## Pruebas

```bash
python3 -m unittest discover -s tests -p 'test_soc_dashboard_history.py' -v
python3 -m unittest discover -s tests -q
```

La batería del módulo cuenta con **20 pruebas**, incluidas validaciones
de extracción de métricas, no filtración de contenido inesperado,
consistencia de contadores y comportamiento autocontenido. Confirmar el
total del proyecto mediante GitHub Actions después de integrar la corrección.
