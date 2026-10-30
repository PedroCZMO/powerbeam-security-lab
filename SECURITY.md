# Seguridad y divulgación responsable

Este repositorio documenta un laboratorio **propio y autorizado** de aprendizaje Blue Team. No invita a escanear, administrar ni explotar dispositivos ajenos.

## Exclusiones de publicación

No incluir:

- Backups originales exportados de airOS (pueden contener configuración sensible).
- Contraseñas, claves privadas, tokens, cookies de sesión o capturas de la interfaz de administración sin revisar.
- Capturas PCAP originales, registros sin anonimizar, identificadores MAC/serie o direcciones públicas.
- Información que permita acceder de forma no autorizada al equipo.

El `.gitignore` reduce errores, pero **no sustituye** la revisión de cada archivo. Antes de publicar revisar `git status`, `git diff --cached` y la lista de archivos preparados; no usar `git add .` sobre carpetas con material privado.

## Contexto de riesgo

El equipo observado utiliza firmware y algoritmos heredados; se emplea en un entorno de laboratorio controlado. La presencia de servicios abiertos desde la estación de pruebas **no implica** que estén accesibles desde Internet.

## Limitaciones

Las configuraciones de ejemplo requieren adaptación. `rsyslog` recibe Syslog mediante UDP, un protocolo sin cifrado ni garantía de entrega; restringir el origen en firewall y mantenerlo en una red de confianza. No utilizar estas reglas sin evaluación adicional en producción.
