# Roadmap — Siguientes pasos para SOC L1

## Por cerrar en la fase 2

- [ ] Verificar la configuración y la hora NTP del PowerBeam; explicar la diferencia horaria observada.
- [ ] Comprobar que `/etc/logrotate.conf` incluye `/etc/logrotate.d` en la ejecución global.
- [ ] Cotejar `configs/30-powerbeam.conf.example` con la configuración realmente aplicada en Ubuntu.
- [ ] Validar compresión y retención con rotaciones naturales, evitando pruebas forzadas innecesarias.

## Fase 3 — Detección y triaje

- [ ] Inventariar tipos de eventos realmente emitidos por el PowerBeam (autenticación exitosa/fallida, cambios de configuración, reinicios, si están disponibles).
- [ ] Normalizar campos mínimos: fecha de recepción, hora del evento, IP de origen, proceso, resultado, usuario y origen de autenticación.
- [ ] Diseñar una regla de **varios intentos fallidos** con umbral y ventana temporal; no asumir que el dispositivo emite esos mensajes hasta comprobarlo.
- [ ] Diseñar un caso de uso **autenticación desde IP no autorizada** a partir de lista controlada de orígenes.
- [ ] Documentar falsos positivos, severidad, evidencias, acciones de triaje y escalado.
- [ ] Evaluar SIEM de laboratorio solo cuando existan datos y casos de uso reproducibles.

## Indicadores de calidad

Cada nueva detección deberá incluir: objetivo, fuente de datos, evento de ejemplo anonimizado, lógica, procedimiento de prueba, resultado reproducible y limitaciones.
