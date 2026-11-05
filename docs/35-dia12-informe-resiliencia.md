# Día 12 · Fase 3 — Informe de resiliencia (manual)

## Objetivo

Reunir **estados observables**, sin mezclar la disponibilidad del motor SOC, la cola local y el canal de notificaciones de Gmail.

- `detection_status`: actividad de temporizadores V1/V3/Health y última ejecución correcta. **No certifica ingestión de syslog**, ataques detectados ni integridad de logs.
- `alert_queue_status`: actividad del temporizador de la cola y última ejecución correcta. **No lee pendientes ni checkpoints**. Una cola puede estar saludable y contener avisos pendientes.
- `oauth_local`: configuración de token local según el comprobador anterior; `READY_LOCAL` **no valida** Google.
- `oauth_remote`: `NOT_CHECKED` por defecto; con `--online YES` solicita una renovación puntual a Google sin enviar Gmail ni guardar el token renovado. El resultado `ACCEPTED` **no garantiza** la validez futura del refresh token.
- `notification_delivery`: `NOT_AUTOMATED` mientras no exista un servicio de envío automático.

## Ejecución

Desde la raíz del repositorio, con el **usuario que es dueño de su token privado** (NO `sudo`, NO `powerbeam-monitor`):

```bash
python3 -B scripts/resilience_report.py \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json"
```

Separa explícitamente los estados; no accede a credenciales ajenas, correos ni alertas, y no instala servicios.

Opcional, manual, con Google (no es apto para ejecutar cada minuto):

```bash
"$HOME/.local/share/powerbeam-oauth-venv/bin/python" -B \
scripts/resilience_report.py \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json" \
  --online YES
```

El modo online consulta el endpoint OAuth únicamente; **no consulta Gmail API**, no entrega mensajes y no modifica archivos. Puede devolver exit code 0 aunque OAuth remoto falle, porque el exit code del informe corresponde **solo a servicios/cola**; en esos casos se debe consultar `oauth_remote` explícitamente. Códigos: 0 operacional, 1 estado `UNKNOWN`/`WARNING`, 2 fallo crítico de servicios.

## Segregación de privilegios

El script debe ejecutarse como usuario interactivo dueño del token, no se debe copiar el token a `/var/lib/powerbeam-monitor`, modificar su modo `600` o compartir `/home` con `powerbeam-monitor`. Esta fase **no crea un quinto temporizador**.

## Casos límite

- Un servicio oneshot parado tras finalizar correctamente es normal.
- Ejecuciones antiguas o sin historial se marcan `WARNING` o `UNKNOWN`.
- Una prueba de renovación OAuth que acabe en error no indica que las detecciones SOC hayan dejado de funcionar.
- Los informes no contienen secretos, ni rutas completas al token.
- En modo Testing los refresh tokens de Gmail tienen una vida limitada (habitualmente 7 días); un resultado remoto saludable en un instante no elimina ese límite.
