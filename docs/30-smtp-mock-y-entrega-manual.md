# Día 11 — Fase 8: SMTP con pruebas simuladas (sin envío real)

## Qué añade

- `scripts/smtp_notifier.py`: transporta **solo alertas pendientes de V1** usando SMTP con TLS verificado y credenciales leídas de un archivo privado; realiza el `ack` únicamente después de que el servidor SMTP acepta el mensaje.
- `scripts/smtp_mock_demo.py`: muestra los casos **fallo -> pendiente**, **aceptación simulada -> ack** y **segunda lectura -> sin duplicación**, exclusivamente sobre archivos temporales y sin red.
- `tests/test_smtp_notifier.py`: 21 pruebas sin conexiones de red; mocks para TLS, fallos, rechazos y problemas de acuse.

**No sobreescribe** los scripts `alert_queue.py`, `alert_notifier.py` ni las unidades systemd existentes.

## Cómo instalar los archivos solo en el repositorio

Desde la raíz de `powerbeam-security-lab`:

```bash
unzip -o ~/Descargas/PowerBeam_Dia11_Fase8_SMTP_MOCK.zip
python3 -m unittest discover -s tests -p 'test_smtp_notifier.py' -v
python3 -m unittest discover -s tests -q
python3 -B scripts/smtp_mock_demo.py
```

Si había 185 tests antes, se esperan **206** tras esta fase (185 + 21).

El ejemplo crea una cola **temporal**, por lo que el motivo `delivered` que escribe es **simulado** y no altera el estado real. No introduce ninguna credencial.

## Restricciones deliberadas

- **No instalar como servicio ni activar envío automático** todavía. La cola actual y sus cuatro temporizadores permanecen como estaban.
- El envío real solo puede iniciarse mediante el comando explícito `send` y el argumento de confirmación `--confirm-live-send YES`.
- Transportes permitidos: SMTP SSL/TLS verificado (`ssl`, habitual 465) o STARTTLS obligatorio (`starttls`, habitual 587). No hay modo SMTP en claro.
- Autenticación SMTP con usuario y contraseña procedente de `--password-file`; no pasar contraseñas mediante argumentos ni incluirlas en código, Git, logs o capturas.
- El archivo de secreto debe estar fuera del repositorio, ser regular y tener permisos `0600` o más restrictivos. Nunca se incluye en el ZIP.
- Cada ejecución procesa, como máximo, 10 alertas y por defecto **solo 1**. En cuanto ocurre un fallo, se detiene.
- El registro `reason=delivered` significa **SMTP aceptó el mensaje**, NO que el destinatario lo haya recibido o abierto.
- Si SMTP falla, permanece pendiente y puede reintentarse. Si SMTP acepta y el proceso falla **antes de guardar el ack**, el reintento puede generar un correo duplicado. El resultado indica `needs_reconciliation=true` si detecta un error de acuse; un corte de corriente entre ambos pasos podría no dejar ese aviso. Para una solución comercial serían necesarios mecanismos adicionales de reconciliación e idempotencia en el proveedor.
- El bloqueo `smtp-dispatch.lock` evita dos envíos simultáneos desde instancias de **este mismo despachador**. Un `ack` manual simultáneo no forma parte de la garantía de exclusión: evitar operaciones de ack manual durante el envío.

## Más adelante: ejemplo de sintaxis para envío real, NO EJECUTAR TODAVÍA

```bash
# EJEMPLO DOCUMENTAL, NO EJECUTAR SIN CONFIGURAR UNA CUENTA CONTROLADA:
python3 -B scripts/smtp_notifier.py send \
  --state /ruta/segura/state.json \
  --source /ruta/alertas.jsonl \
  --sender soc@example.org \
  --recipient analyst@example.org \
  --smtp-host smtp.example.org \
  --smtp-port 587 \
  --tls-mode starttls \
  --smtp-user soc@example.org \
  --password-file /ruta/privada/smtp.secret \
  --max-alerts 1 \
  --confirm-live-send YES
```

**Siguiente paso antes de enviar de verdad:** elegir el proveedor SMTP y una cuenta de prueba; revisar sus requisitos de autenticación, preparar credenciales fuera de Git, validar el envío de una alerta simulada a una dirección propia. No usar el estado real en la primera prueba de red.
