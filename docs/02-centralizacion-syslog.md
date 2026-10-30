# Día 1 — Centralización y persistencia de Syslog

**Fecha:** 29/10/2026 (validación de persistencia el 30/10/2026)

## Objetivo

Enviar los eventos del PowerBeam a un host Ubuntu para conservar evidencias de administración sin depender únicamente de la memoria o interfaz del dispositivo.

```text
PowerBeam (192.168.1.20) --UDP/5514--> Ubuntu (192.168.1.10)
                                            rsyslog
                                               |
                                   /var/log/powerbeam/powerbeam.log
```

## Configuración y alcance de las pruebas

- Receptor: `rsyslog` sobre Ubuntu; destino `192.168.1.10:5514/UDP`.
- Filtro por IP de origen del PowerBeam para separar eventos del laboratorio.
- Salida persistente en `/var/log/powerbeam/powerbeam.log`.
- Directorio con propiedad `syslog:syslog`, permisos `750`; archivo con propiedad `syslog:syslog`, permisos `640`.
- Se recibieron eventos **reales** generados por el equipo, incluyendo una autenticación correcta en el servicio `httpd`.
- Se comprobó la persistencia del montaje/servicios tras reiniciar la estación al comienzo del Día 2.

El archivo [`configs/30-powerbeam.conf.example`](../configs/30-powerbeam.conf.example) es una **reconstrucción basada en la arquitectura acordada**, no una copia obtenida del `/etc/rsyslog.d/` de la máquina. Para reflejar exactamente el despliegue, cotejarlo antes de copiarlo.

## Verificación local sugerida

Estos comandos permiten repetir las comprobaciones sin modificar archivos:

```bash
sudo rsyslogd -N1
sudo ss -lunp | grep ':5514'
sudo systemctl status rsyslog --no-pager
sudo ls -ld /var/log/powerbeam
sudo ls -l /var/log/powerbeam/powerbeam.log
sudo tail -F /var/log/powerbeam/powerbeam.log
```

El `ss` del receptor y el `tail` deben interpretarse junto con un **evento real de PowerBeam**. La ausencia temporal de mensajes no equivale a una avería si el emisor está inactivo.

## Consideraciones de seguridad

UDP/5514 no cifra el tráfico, no autentica criptográficamente el remitente y puede perder mensajes. Mantenerlo en una red de confianza y restringir el acceso en UFW a la IP del dispositivo. No se publica una regla UFW como «aplicada» porque no tenemos confirmación textual de la regla exacta.

**Siguiente paso:** [Rotación y retención](04-rotacion-y-retencion.md).
