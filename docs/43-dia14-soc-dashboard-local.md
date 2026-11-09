# Día 14 — Dashboard SOC local (fase 1)

## Objetivo

Crear una primera interfaz HTML **estática, local y de solo lectura** a partir del
informe **agregado** de \`soc_daily_report.py\`. No necesita Streamlit,
dependencias extra, servicios web ni una cuenta de nube.

**Fuente y alcance:** alertas V1 por **fecha del evento** y reconocimientos
por **fecha del ACK**. El estado de la cola y la salud son **instantáneas del momento
de generación**, no el estado histórico del día seleccionado. V3 no se suma
porque duplicaría detecciones. \`HEALTHY\` no prueba ingestión continua de logs.

## Archivos

- \`scripts/soc_dashboard.py\`: valida un contrato JSON restringido, reduce
  los datos a contadores y estados permitidos, genera HTML autónomo.
- \`tests/test_soc_dashboard.py\`: pruebas de contrato, seguridad de la
  salida, privacidad y permisos.
- No cambia \`systemd\`, el monitor V1/V3, la cola, las notificaciones ni OAuth.

## Preparar un directorio privado (una vez)

Ejecutar **como el usuario habitual** de Ubuntu, sin \`sudo\`:

\`\`\`bash
mkdir -p "$HOME/.local/share/powerbeam-security-lab/soc-dashboard"
chmod 700 "$HOME/.local/share/powerbeam-security-lab/soc-dashboard"
\`\`\`

## Prueba del dashboard con el ejercicio del 06/11/2026

Desde la raíz del repositorio, tras sincronizar \`git pull --ff-only origin main\`:

\`\`\`bash
set -o pipefail

sudo -u powerbeam-monitor /usr/bin/python3 -B \
  /opt/powerbeam-monitor-v3/scripts/soc_daily_metrics.py \
  --alerts /var/lib/powerbeam-monitor/alerts.jsonl \
  --state /var/lib/powerbeam-monitor/alert-queue/state.json \
  --date 2026-11-06 \
| python3 -B scripts/soc_daily_report.py \
  --daily-stdin \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json" \
  --format json \
| python3 -B scripts/soc_dashboard.py \
  --output "$HOME/.local/share/powerbeam-security-lab/soc-dashboard/index.html"
\`\`\`

Salida esperada si la generación termina bien:

\`\`\`json
{"status": "CREATED", "inspection": "LOCAL_READ_ONLY", "file": "index.html", "state_modified": false, "emails_sent": 0, "tokens_modified": false}
\`\`\`

Abrir localmente desde Ubuntu:

\`\`\`bash
xdg-open "$HOME/.local/share/powerbeam-security-lab/soc-dashboard/index.html"
\`\`\`

Para analizar otro día, cambia \`--date\`, o quítalo para ver las alertas
fechadas hoy. **La vista no se actualiza sola:** repite la generación cuando
quieras una nueva instantánea.

## Seguridad

1. El generador no recibe logs originales, IP de cliente, IDs de alerta ni
   tokens; solamente el JSON agregado del informe diario.
2. Valida \`report_status=READY\`, \`inspection=LOCAL_READ_ONLY\`,
   fecha/zona horaria, recuentos coherentes y estados limitados.
3. No pasa al HTML los campos inesperados, incluso si aparecieran en el JSON.
4. HTML sin JavaScript, fuentes externas, imágenes ni peticiones de red.
5. Guarda por sustitución atómica en un directorio propio sin acceso de
   grupo/otros (modo \`0700\`); el archivo resulta \`0600\`.
6. El script no modifica la cola ni el detector. Se ejecuta como usuario
   interactivo, **nunca como \`root\` ni \`powerbeam-monitor\`**.
7. No subir HTML generado, archivos privados, logs ni token a GitHub. El
   dashboard es una vista local, no una consola de investigación remota.

**Precaución:** el informe muestra estados como \`READY_LOCAL\`,
\`NOT_CHECKED\`, \`NOT_AUTOMATED\`. Estos no deben presentarse como un
canal de correo operacional o una autorización remota validada.

## Validación de pruebas

\`\`\`bash
python3 -m unittest discover -s tests -p 'test_soc_dashboard.py' -v
python3 -m unittest discover -s tests -q
\`\`\`

El objetivo es añadir **20 pruebas** sin alterar las 482 anteriores. La
confirmación definitiva será el resultado observable en GitHub Actions.
