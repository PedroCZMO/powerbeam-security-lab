# PowerBeam Security Lab

**🇪🇸 Español** | [🇬🇧 English](README.md)

[![Python Tests](https://github.com/PedroCZMO/powerbeam-security-lab/actions/workflows/python-tests.yml/badge.svg?branch=main)](https://github.com/PedroCZMO/powerbeam-security-lab/actions/workflows/python-tests.yml)

**Laboratorio personal de Blue Team / SOC L1** · Ubiquiti PowerBeam PBE-M5-400 · Ubuntu · Python · Syslog · systemd

> **Estado actualizado: 9 de noviembre de 2026.** Laboratorio personal de aprendizaje sobre equipo propio y red controlada. Los ejercicios SOC-001 y SOC-002 se documentan con evidencias reales; **482 pruebas locales superadas (06/11)** y **527 pruebas superadas en GitHub Actions (09/11)**. No es un SOC de producción ni una auditoría formal.

## El proyecto en 30 segundos

PowerBeam Security Lab recibe eventos de una antena Ubiquiti real, los conserva en Ubuntu y ejecuta detectores de comportamiento sospechoso. Dos versiones del monitor (V1 y V3) permiten comparar resultados; un tercer componente comprueba periódicamente la salud de la infraestructura.

| Evidencia | Resultado comprobado |
| --- | --- |
| Recepción de registros | Syslog real de `192.168.1.20` a Ubuntu por **UDP/5514** |
| Detecciones | **SOC-001** (múltiples fallos) y **SOC-002** (fallos seguidos de éxito) |
| Simulacro SOC-002 | **2 fallos + 1 éxito**; V1 y V3 produjeron la misma alerta |
| Pruebas automatizadas | **527 pruebas superadas** en [GitHub Actions](https://github.com/PedroCZMO/powerbeam-security-lab/actions/runs/42616190256) (09/11/2026); **482** superadas localmente (06/11/2026) |
| Automatización | Monitores V1/V3 cada **5 min** y Health Check cada **10 min** mediante `systemd` |
| Supervisión | Estado de servicios y temporizadores, socket UDP, actividad reciente e ICMP |
| Investigación SOC | [SOC-001: cinco fallos SSH reales](docs/42-pb-pt-002-investigacion-soc-001-2026-11-06.md) · [SOC-002: fallos seguidos de éxito](docs/26-investigacion-soc-002-2026-11-04.md) |

**Caso destacado para entrevistas SOC L1:** [PB-PT-002: cinco fallos SSH reales desde Kali, detectados por V1 y V3 y cerrados tras investigación](docs/42-pb-pt-002-investigacion-soc-001-2026-11-06.md). [Leer este caso en inglés](docs/42-pb-pt-002-soc-001-investigation.en.md).

## Arquitectura

```text
                 RED LOCAL CONTROLADA

 Ubiquiti PowerBeam PBE-M5-400                Ubuntu / estación de análisis
 airOS 6.1.11 (XW)                            192.168.1.10
 192.168.1.20                                     |
       |                                          |
       +------------- Syslog UDP/5514 ----------> rsyslog
                                                  |
                                    /var/log/powerbeam/powerbeam.log
                                                  |
                           +----------------------+---------------------+
                           |                      |                     |
                     logrotate              Monitor V1             Monitor V3
                 14 rotaciones               Python                Python
                     / compresión          SOC-001/002            SOC-001/002
                           |                      |                     |
                     Retención              alertas JSONL          alertas JSONL

                  Health Check (systemd cada 10 minutos)
                  ├─ rsyslog, temporizadores y ejecución V1/V3
                  ├─ socket local UDP/5514
                  ├─ último mensaje observado en los registros
                  ├─ respuesta ICMP de la antena
                  └─ informe JSON → journald
```

Las direcciones son **privadas (RFC 1918)**. Esta topología representa la red del laboratorio; no demuestra exposición a Internet.

## Casos de uso de detección

| Regla | Condición configurada | Qué permite observar |
| --- | --- | --- |
| **SOC-001** | Al menos **5 autenticaciones fallidas en 5 minutos** | Posible patrón de fuerza bruta; no confirma un ataque |
| **SOC-002** | Al menos **2 fallos seguidos de una autenticación correcta en 5 minutos** | Secuencia de acceso que merece revisión |

Los detectores procesan eventos de autenticación de la antena. **V1** realiza el análisis por lotes; **V3** utiliza procesamiento incremental con un estado propio y continúa como implementación experimental. Los resultados de ambos se compararon en SOC-002 y en el ejercicio Purple Team SOC-001 del 06/11/2026, sin compartir sus archivos de alertas.

### Ejemplo real: SOC-002, 04/11/2026

```text
11:00:06 CET  Bad password attempt for 'ubnt' from 192.168.1.10
11:00:20 CET  Bad password attempt for 'ubnt' from 192.168.1.10
11:00:25 CET  Password auth succeeded for 'ubnt' from 192.168.1.10
```

La secuencia duró **19,318 segundos** y activó la alerta `SOC-002-2ad9ffcb5b5d0b58`, con severidad de regla `medium`. V1 y V3 registraron el mismo identificador y los mismos campos relevantes. **Fue una prueba autorizada, no una intrusión confirmada.** [Ver análisis y evidencias](docs/26-investigacion-soc-002-2026-11-04.md).

## Supervisión y automatización

`powerbeam-health.service` se ejecuta como usuario restringido `powerbeam-monitor`; su temporizador se activó y ejecutó automáticamente por primera vez el **04/11/2026 a las 12:34:01 CET**. Los informes se registran en `journald`.

| Componente | Unidad systemd | Cadencia observada/configurada |
| --- | --- | --- |
| Detector V1 | `powerbeam-monitor.timer` | Aproximadamente cada 5 minutos |
| Detector V3 | `powerbeam-monitor-v3.timer` | Aproximadamente cada 5 minutos |
| Supervisor | `powerbeam-health.timer` | Aproximadamente cada 10 minutos |

El Health Check distingue entre **infraestructura local operativa**, **conectividad ICMP** y **actividad reciente en los logs**. Sin una señal periódica fiable emitida por el dispositivo, `ingestion_status` permanece en `UNKNOWN`: ni un puerto UDP abierto ni una respuesta ICMP prueban ingestión continua.

Para conocer su configuración, despliegue y limitaciones: [Health Check con systemd](docs/25-despliegue-health-check-systemd.md).

## Cómo revisar el laboratorio

**Ejecutar las pruebas automatizadas** desde la raíz del repositorio:

```bash
python3 -m unittest discover -s tests -q
```

Resultados verificados: **482 pruebas, OK** en Ubuntu (06/11/2026) y **527 pruebas, OK** en [GitHub Actions (Python 3.12)](https://github.com/PedroCZMO/powerbeam-security-lab/actions/runs/42616190256) (09/11/2026). Los tests son offline; no requieren el dispositivo.

**Consultar los temporizadores** en la máquina donde está instalado el laboratorio:

```bash
systemctl list-timers --all --no-pager | grep powerbeam
```

**Consultar los informes del supervisor:**

```bash
sudo journalctl -u powerbeam-health.service -n 70 --no-pager
```

**Ejecutar el Health Check directamente** en la instalación descrita:

```bash
sudo -u powerbeam-monitor /usr/bin/python3 -B \
  /opt/powerbeam-monitor-v3/scripts/health_check.py \
  --inspect-log-activity --fresh-minutes 30 --check-antenna-icmp
```

Estos comandos de observación requieren una instalación previa y permisos adecuados. **No basta con clonar el repositorio para disponer del dispositivo ni de sus registros.** Consulta la documentación de despliegue antes de aplicar configuraciones.

## Hallazgos iniciales y cronología

| Fecha | Hito respaldado por el laboratorio |
| --- | --- |
| **29/10/2026** | Reconocimiento local: SSH (22/TCP), HTTP (80/TCP), HTTPS (443/TCP); Telnet (23/TCP) cerrado. Revisión de SSH y del certificado TLS. |
| **29–30/10/2026** | Centralización de syslog, permisos restrictivos, persistencia y rotación de registros con `logrotate`. |
| **01–04/11/2026** | Desarrollo y comprobación de detecciones SOC, ejecución paralela de V1/V3 y pruebas de robustez. |
| **04/11/2026** | Simulacro SOC-002 con eventos reales, Health Check automatizado y **129 pruebas automatizadas** superadas. |
| **04/11/2026** | Publicación del [informe de investigación SOC-002](docs/26-investigacion-soc-002-2026-11-04.md). |
| **06/11/2026** | [Ejercicio PB-PT-002](docs/42-pb-pt-002-investigacion-soc-001-2026-11-06.md): cinco fallos SSH reales desde Kali; una SOC-001 idéntica en V1/V3; cierre `reviewed` y **482 pruebas** superadas en CI. |
| **09/11/2026** | [Dashboard SOC local](docs/43-dia14-soc-dashboard-local.md): vista HTML privada de métricas agregadas; **527 pruebas** superadas en CI. |

**Riesgos de configuración observados durante el reconocimiento:** algoritmos SSH heredados y certificado HTTPS autofirmado caducado el **28/03/2024**. Son hallazgos de configuración, **no evidencia de explotación**. [Ver hallazgos y recomendaciones](docs/05-hallazgos-y-recomendaciones.md).

## Documentación técnica

| Documento | Contenido |
| --- | --- |
| [01 · Reconocimiento](docs/01-reconocimiento.md) | Puertos, servicios y observaciones técnicas |
| [02 · Centralización de Syslog](docs/02-centralizacion-syslog.md) | Recepción, permisos y flujo de registros |
| [03 · Sincronización horaria](docs/03-sincronizacion-horaria.md) | Chrony en Ubuntu y comprobaciones pendientes |
| [04 · Rotación y retención](docs/04-rotacion-y-retencion.md) | Configuración y validaciones de `logrotate` |
| [05 · Hallazgos y recomendaciones](docs/05-hallazgos-y-recomendaciones.md) | Riesgos detectados y mitigaciones propuestas |
| [06 · Evidencias y validación](docs/06-evidencias-y-validacion.md) | Resultados iniciales y alcance de las pruebas |
| [07 · Roadmap inicial](docs/07-roadmap.md) | Plan de trabajo original; consultar el estado actual en este README |
| [21 · Observabilidad](docs/21-observabilidad-health-check-fase1.md) | Primera fase del Health Check |
| [22 · HEALTH-004](docs/22-health004-receptor-udp.md) | Comprobación del receptor UDP |
| [23 · HEALTH-005](docs/23-health005-ultima-recepcion-observada.md) | Última recepción observada en los registros |
| [24 · HEALTH-006](docs/24-health006-conectividad-icmp.md) | Conectividad ICMP de la antena |
| [25 · Despliegue systemd](docs/25-despliegue-health-check-systemd.md) | Servicio, temporizador y validación real |
| [26 · Investigación SOC-002](docs/26-investigacion-soc-002-2026-11-04.md) | Caso práctico de análisis de alerta y evidencias |
| [41 · Kali y telemetría SSH](docs/41-dia13-topologia-kali-ubiquiti-telemetria-ssh.md) | Topología de pruebas y negociación SSH documentada |
| [42 · Investigación SOC-001](docs/42-pb-pt-002-investigacion-soc-001-2026-11-06.md) | Cinco fallos reales desde Kali; correlación y reconocimiento |
| [43 · Dashboard SOC local](docs/43-dia14-soc-dashboard-local.md) | Vista HTML de solo lectura desde métricas agregadas, sin red ni credenciales |
| [44 · Navegación histórica SOC](docs/44-dia15-navegacion-historica-dashboard.md) | Histórico HTML autocontenido por fecha con colores semánticos, sin servidor ni JavaScript |
| [26 EN · SOC-002](docs/26-soc-002-investigation.en.md) | Investigación SOC-002 en inglés |
| [42 EN · SOC-001](docs/42-pb-pt-002-soc-001-investigation.en.md) | Investigación Purple Team en inglés |

## Configuraciones y evidencias publicables

- [`configs/30-powerbeam.conf.example`](configs/30-powerbeam.conf.example): ejemplo reconstruido de rsyslog; **no es un volcado literal** de la configuración real.
- [`configs/logrotate-powerbeam.conf`](configs/logrotate-powerbeam.conf): regla de rotación basada en la configuración comprobada.
- [`configs/chrony-snippet.conf.example`](configs/chrony-snippet.conf.example): fragmento orientativo; **no constituye evidencia de aplicación**.
- [`evidencias/evento-sanitizado.txt`](evidencias/evento-sanitizado.txt): muestra anonimizada e ilustrativa basada en un evento observado.
- [`scripts/health_check.py`](scripts/health_check.py): comprobaciones de salud y conectividad.
- [`systemd/powerbeam-health.service`](systemd/powerbeam-health.service) y [`systemd/powerbeam-health.timer`](systemd/powerbeam-health.timer): automatización del Health Check.

## Alcance, seguridad y trabajo pendiente

Este proyecto se desarrolla **exclusivamente en equipos propios o autorizados**. No se publican contraseñas, respaldos de airOS, claves privadas, capturas completas de tráfico ni registros originales completos. El transporte Syslog UDP no proporciona cifrado ni garantía de entrega: debe permanecer dentro de una red aislada o protegida. Ver [`SECURITY.md`](SECURITY.md).

Límites que seguimos documentando:

- El reloj de recepción de Ubuntu estaba sincronizado mediante NTP; la marca incluida por la antena difería aproximadamente una hora. **La configuración y sincronización NTP del dispositivo requieren validación independiente**; no se interpreta automáticamente como avería.
- `ingestion_status=UNKNOWN` mientras no exista una señal periódica fiable; la ausencia de registros puede ser inactividad normal.
- V3 continúa como monitor incremental **experimental**, aunque se haya validado frente a V1 en el caso SOC-002.
- Una alerta **SOC-001/SOC-002** es un indicador para investigar, no prueba por sí sola de un ataque, ni de compromiso del equipo.
- El laboratorio todavía no incluye notificaciones externas del Health Check, un SIEM completo ni garantías propias de producción.

**Estado:** laboratorio SOC personal **operativo y en desarrollo**. Última validación documentada: **09/11/2026**.
