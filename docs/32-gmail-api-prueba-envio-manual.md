# Día 11 — Fase 11. Envío de prueba real con Gmail API

## Requisitos

- Autorización OAuth local realizada con `gmail_oauth_authorize.py` (solo `gmail.send`).
- Cuenta `pedroczmo23@gmail.com` añadida en Google Auth Platform → Público → Usuarios de prueba.
- Token privado en `$HOME/.local/share/powerbeam-security-lab/gmail-token.json` (0600).
- Entorno Python en `$HOME/.local/share/powerbeam-oauth-venv`.
- No habilitar servicios automáticos de envío durante las pruebas.

## Tests sin conexión

```bash
python3 -m unittest discover -s tests -p 'test_gmail_api_notifier.py' -v
python3 -m unittest discover -s tests -q
```

## Probar una alerta **ficticia y temporal**

Desde la raíz del repositorio, ejecutar el siguiente bloque por separado. Se usa un directorio temporal privado y se conserva al terminar para investigar errores; limpiarlo manualmente después de obtener la confirmación.

```bash
bash <<'BASH'
set -euo pipefail
umask 077
D="$(mktemp -d -t powerbeam-gmail-api-XXXXXX)"
SOURCE="$D/alerts.jsonl"
STATE="$D/state.json"
cat > "$SOURCE" <<'EOF'
{"alert_id":"SOC-002-HIST-OAUTH","rule_id":"SOC-002","severity":"medium","source_ip":"192.0.2.10","timestamp":"2026-11-05T09:00:00+01:00"}
EOF
python3 -B scripts/alert_queue.py bootstrap --source "$SOURCE" --state "$STATE"
printf '{"alert_id":"SOC-001-GMAIL-API-DEMO","rule_id":"SOC-001","severity":"high","source_ip":"192.0.2.11","timestamp":"%s"}\n' "$(date --iso-8601=seconds)" >> "$SOURCE"
python3 -B scripts/alert_queue.py scan --source "$SOURCE" --state "$STATE"
"$HOME/.local/share/powerbeam-oauth-venv/bin/python" -B scripts/alert_notifier.py preview --source "$SOURCE" --state "$STATE" --max-alerts 1
printf '\n*** Se enviará UN correo real a pedroczmo23@gmail.com ***\n'
"$HOME/.local/share/powerbeam-oauth-venv/bin/python" -B scripts/gmail_api_notifier.py send \
  --source "$SOURCE" --state "$STATE" \
  --sender pedroczmo23@gmail.com --recipient pedroczmo23@gmail.com \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json" \
  --max-alerts 1 --confirm-live-send YES
python3 -B scripts/alert_queue.py status --source "$SOURCE" --state "$STATE"
printf 'Directorio temporal (conservar hasta verificar Gmail): %s\n' "$D"
BASH
```

**Verificación:** Gmail API devuelve aceptación, se registra un acuse `delivered` (significa *aceptado por Gmail API*, no recibido en bandeja), se observa un único mensaje en Gmail y la cola queda a 0 pendientes. En el caso de que el programa marque `needs_reconciliation: true`, **no reintentar inmediatamente**: revisar Gmail → Enviados para no duplicar el correo. Un timeout puede ocurrir después de un envío correcto.

**Seguridad:** nunca mostrar ni compartir el JSON del cliente o el token; ni instalarlos en `/opt` ni incluirlos en `git add`. El token lo posee el usuario personal: `powerbeam-monitor` no tiene acceso. Cualquier automatización futura exige diseñar una identidad de servicio aislada y revisar la caducidad del token de OAuth en modo Testing (~7 días para `gmail.send`).
