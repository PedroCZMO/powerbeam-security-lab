# Día 2 — Sincronización horaria (Chrony)

**Fecha:** 30/10/2026

## Objetivo

Facilitar la correlación de logs entre el equipo de red y la estación de análisis. Para un SOC, una hora inconsistente altera la línea temporal de incidentes.

## Evidencias confirmadas en Ubuntu

- `chrony` instalado y servicio operativo; antes se utilizaba `systemd-timesyncd`.
- El servicio NTP escuchaba en `192.168.1.10:123/UDP`.
- `chronyc tracking` indicó sincronización, **stratum 3**, estado **Leap status: Normal** y dispersión de raíz cercana a **0,005955316 s**.

Estas verificaciones corresponden al **servidor Ubuntu**, no prueban la sincronización del PowerBeam con él.

## Pendiente: NTP en el dispositivo

En un registro recibido a las **11:31:44 +01:00**, el mensaje interno del dispositivo indicaba **10:31:44**. La diferencia de una hora podría deberse a UTC frente a hora local, a zona horaria o a un reloj mal configurado. **No está confirmada su causa.**

Para cerrar esta fase hay que:

1. Comprobar servidor NTP configurado en el PowerBeam y su estado de sincronización.
2. Comparar la hora real del dispositivo con la del receptor, indicando zona horaria de ambos.
3. Emitir un nuevo evento y documentar si las marcas temporales representan el mismo instante.
4. Registrar capturas o salidas **anonimizadas** que acrediten el resultado.

## Comandos de inspección de Ubuntu

```bash
systemctl status chrony --no-pager
chronyc tracking
sudo ss -lunp | grep ':123'
```

El fragmento [`configs/chrony-snippet.conf.example`](../configs/chrony-snippet.conf.example) es solo orientativo. No sustituye una copia de `/etc/chrony/chrony.conf` ni refleja necesariamente el ajuste final aplicado.

**Estado: parcialmente validado (servidor Ubuntu: sí; PowerBeam: pendiente).**
