# Día 11 · Fase 10 — OAuth de Gmail (autorización sin envío)

Este paquete únicamente autoriza el permiso mínimo `gmail.send`; no genera correos, ni toca la cola real de alertas, ni modifica systemd. Las credenciales y el token quedan fuera del repositorio.

1. Configura en Google Cloud un cliente de tipo **Aplicación de escritorio** y añade el correo de prueba como usuario de prueba de la aplicación OAuth externa. Asegúrate de habilitar **Gmail API** y añadir el permiso `https://www.googleapis.com/auth/gmail.send`.
2. Guarda el JSON descargado, con permisos 600, en `~/.config/powerbeam-security-lab/gmail-oauth-client.json`.
3. Instala dependencias Google en un entorno virtual **fuera del repositorio** y ejecuta `gmail_oauth_authorize.py --check-client`.
4. Ejecuta `gmail_oauth_authorize.py` con el intérprete del entorno virtual. Abre el navegador y autoriza la cuenta correcta. El token se guarda, con permisos 600, en `~/.local/share/powerbeam-security-lab/gmail-token.json`.
5. No publiques el JSON ni el token y no muestres su contenido en capturas o salidas de terminal.

**Advertencia:** si la aplicación OAuth externa está en estado «Pruebas», el token de actualización para `gmail.send` puede caducar en siete días. Todavía no es una integración permanente de sistema.

## Dependencias

`google-auth-oauthlib`, `google-auth` y sus dependencias. No se necesitan bibliotecas de Gmail API hasta que implementemos el envío.

## Validación

`python3 -m unittest discover -s tests -p 'test_gmail_oauth_authorize.py' -v`

Las pruebas son locales y no llaman a Google.
