# PowerBeam Security Lab — Día 12, Fase 2: comprobación remota OAuth

## Finalidad

Se ejecuta una **solicitud de renovación de access token** al endpoint oficial de Google OAuth `https://oauth2.googleapis.com/token`, usando el refresh token almacenado en un archivo privado. No consulta Gmail API, no envía correos, no crea acuses y no altera los archivos de estado ni el archivo del token.

El éxito indica que **Google aceptó esa renovación en el momento de la prueba**. No indica la fecha de caducidad futura del refresh token ni garantiza una disponibilidad sostenida de Gmail API.

## Precondiciones

- Fase 1 instalada: `scripts/oauth_health.py`.
- Bibliotecas `google-auth` y `google-auth-oauthlib` ya instaladas en el entorno virtual dedicado.
- Token privado propiedad del usuario que ejecuta la herramienta, directorio `0700`, archivo `0600`.

## Pruebas locales (sin red)

```bash
python3 -m unittest discover -s tests -p 'test_oauth_remote_health.py' -v
python3 -m unittest discover -s tests -q
```

## Prueba remota puntual (requiere red, no envía correo)

```bash
"$HOME/.local/share/powerbeam-oauth-venv/bin/python" -B \
  scripts/oauth_remote_health.py \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json" \
  --online YES
```

**No ejecutar como root ni como `powerbeam-monitor`:** este token corresponde al usuario personal; la instalación restringida será una fase distinta.

## Salida y clasificación

- `HEALTHY`, `remote_authorization: ACCEPTED`: Google aceptó la renovación.
- `DEGRADED`, `TRANSPORT_ERROR`: fallo de transporte o red, el estado de autorización no queda determinado.
- `CRITICAL`, `REFRESH_FAILED`: Google no ha completado la renovación (puede ser revocación, caducidad o rechazo temporal). No se infiere la causa concreta sin diagnosticarla de forma controlada.
- `CRITICAL`, `UNTRUSTED_TOKEN_ENDPOINT`: el JSON no señala el endpoint oficial de Google; **no hay conexión**.
- `CRITICAL`, errores locales: archivo, permisos, JSON o ámbito incorrectos; **no hay conexión**.
- `DEGRADED`, `GOOGLE_LIBRARIES_MISSING`: faltan dependencias en el Python empleado.

Códigos de salida: `0=HEALTHY`, `1=DEGRADED`, `2=CRITICAL`.

La herramienta suprime los textos originales de error: una respuesta del proveedor o una excepción pueden incluir material sensible. No se debe subir el JSON del token a GitHub ni compartir su contenido.

## Seguridad operacional

- Nunca introducir tokens ni credenciales en argumentos de línea de comandos; solo se pasa la ruta.
- El programa no escribe tokens, pero el servidor remoto puede tener sus propias políticas de rotación o revocación.
- No instalar todavía ningún temporizador para esta prueba. Antes hay que definir límites de frecuencia, aislamiento y notificaciones de fallos.
- Google puede limitar a siete días la validez de refresh tokens emitidos en el estado de publicación *Testing* con `gmail.send`.
- No habilitar Gmail automático como canal de alerta único mientras dependa de una autorización temporal.
