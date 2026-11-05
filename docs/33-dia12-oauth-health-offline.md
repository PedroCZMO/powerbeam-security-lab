# Día 12 — Fase 1: OAuth Health Check (offline)

## Objetivo

Inspeccionar, **sin red, sin envíos y sin modificar archivos**, el token OAuth de Gmail utilizado por PowerBeam Security Lab. Mantener esta comprobación separada de los detectores SOC y de la cola real mientras se valida.

El script `scripts/oauth_health.py` usa únicamente la biblioteca estándar de Python y **no necesita las dependencias Google**.

## Garantías y límites

- Rechaza ficheros o directorios con permisos demasiado amplios, enlaces simbólicos directos y propietario distinto del usuario que lo ejecuta.
- Comprueba estructura básica del JSON, permiso `gmail.send`, existencia del refresh token y datos locales necesarios para su renovación.
- Analiza la caducidad **del access token** (interpreta como UTC las fechas sin zona, tal como escribe normalmente Google Auth).
- No imprime contraseñas, access tokens, refresh tokens, IDs de cliente ni el contenido del JSON.
- No comprueba por red si Google ha revocado, bloqueado o caducado el refresh token; el `refresh_token_expiry` siempre figura como `UNKNOWN`.
- Un access token caducado con refresh token y datos de renovación presentes **no es, por sí solo, un fallo**. Se clasifica como `READY_LOCAL` con `access_token_state=EXPIRED` y queda pendiente comprobar Google en una fase posterior.
- El servicio de envío **NO** se activa en esta fase y el archivo no se instala en `/opt`.

## Incorporación al repositorio

Desde la raíz de `powerbeam-security-lab`:

```bash
unzip -o ~/Descargas/PowerBeam_Dia12_Fase1_OAuth_Health.zip
python3 -m unittest discover -s tests -p 'test_oauth_health.py' -v
python3 -m unittest discover -s tests -q
```

24 pruebas nuevas. Si permanecen las 238 anteriores, la batería completa debería ejecutar **262 pruebas**.

## Comprobación real, solo lectura

```bash
python3 -B scripts/oauth_health.py \
  --token "$HOME/.local/share/powerbeam-security-lab/gmail-token.json"
```

Salida orientativa:

```json
{
  "component": "gmail_oauth",
  "inspection": "OFFLINE_READ_ONLY",
  "remote_authorization": "NOT_CHECKED",
  "refresh_token_expiry": "UNKNOWN",
  "emails_sent": 0,
  "token_modified": false,
  "local_status": "READY_LOCAL",
  "access_token_state": "EXPIRED",
  "refresh_token_present": true,
  "refresh_configuration_complete": true,
  "gmail_send_scope": true,
  "private_file_and_directory": true,
  "detail": "Configuracion local preparada; validez del refresh token sin verificar"
}
```

`access_token_state` puede ser `VALID`, `EXPIRING_SOON`, `EXPIRED` o `UNKNOWN`. Si es `EXPIRED` con `READY_LOCAL`, no significa que Gmail haya fallado.

- Código de salida `0`: `READY_LOCAL`, configuración local preparada; **no** prueba conectividad.
- Código de salida `1`: `WARNING`, requiere atención o datos faltantes para renovar.
- Código de salida `2`: `CRITICAL`, token local inseguro, ausente o inutilizable.

**No copies el JSON a GitHub, no pegues sus valores en un chat y no ejecutes el script con `sudo`.**

## Simular un fallo de forma segura

Las pruebas `test_missing_file`, `test_world_readable_file_rejected`, `test_no_refresh_and_expired_critical` y `test_missing_scope` usan ficheros temporales. No cambian el token de la cuenta personal.

## Siguiente fase

Integrar una comprobación opcional en el Health Check, con lectura separada del token y sin elevar privilegios; después desarrollar una sonda OAuth con acceso a Google que compruebe el rechazo de renovación **sin enviar mensajes**. Tratar el token de usuario y el de `powerbeam-monitor` como credenciales distintas: **no abrir el directorio personal ni copiar tokens prematuramente**.

La aplicación OAuth sigue en modo Pruebas: un refresh token vigente hoy puede dejar de funcionar en días. El comprobador offline no detecta ese vencimiento hasta que se intenta renovar realmente.
