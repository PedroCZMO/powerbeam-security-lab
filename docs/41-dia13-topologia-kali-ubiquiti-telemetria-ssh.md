# Día 13 — Laboratorio Red Team / Blue Team: Kali, PowerBeam y telemetría SSH

**Proyecto:** PowerBeam Security Lab  
**Fecha del ejercicio:** 2026-11-06 (Europe/Madrid)  
**Estado:** Topología y atribución de IP verificadas; primera telemetría SSH recibida; autenticación **no alcanzada**.  
**Naturaleza:** Laboratorio propio y pruebas autorizadas, sin explotación ni fuerza bruta.

## 1. Objetivo y alcance

Preparar una VM Kali Linux como estación Red Team independiente del Ubuntu que ejecuta el SOC; comprobar que la antena Ubiquiti PowerBeam recibe la IP real de Kali como origen; y verificar si la antena remite al SOC eventos de una conexión SSH.

**Activo bajo evaluación:** Ubiquiti PowerBeam (`192.168.1.20`) — plano de administración TCP/22.  
**Alcance de estas comprobaciones:** red y negociación SSH. **No** se han ejecutado intentos de contraseña, explotación ni pruebas de denegación de servicio.

## 2. Topología verificada

| Nodo / interfaz | Dirección IPv4 | Uso |
| --- | --- | --- |
| Ubuntu anfitrión — `wlo1` | `192.168.0.15/24` | Red doméstica / Internet |
| Ubuntu anfitrión — `enp2s0` | `192.168.1.10/24` | Segmento PowerBeam y receptor SOC |
| Ubiquiti PowerBeam | `192.168.1.20` | Activo protegido |
| Kali VM — `eth0` | `10.0.2.15/24` | Adaptador 1 de VirtualBox, NAT; ruta por defecto `10.0.2.2` |
| Kali VM — `eth1` | `192.168.1.30/24` | Adaptador 2 de VirtualBox, puente sobre `enp2s0` |

El servidor `rsyslog` del anfitrión escuchaba en `192.168.1.10:5514/UDP` y los temporizadores `powerbeam-monitor`, `powerbeam-monitor-v3`, `powerbeam-health` y `powerbeam-alert-queue` aparecían `active`. El anfitrión devolvía `net.ipv4.ip_forward = 0`. **Esto no certifica por sí solo aislamiento total de la red**; deben conservarse las limitaciones de alcance y configuración al realizar nuevas pruebas.

## 3. Configuración de Kali Linux

La VM reconoció las dos NIC mediante `ip -br link` y `lspci`. Antes del ajuste, `eth1` aparecía en NetworkManager obteniendo configuración IP por DHCP, pero sin dirección IPv4.

**Comprobación previa de dirección libre desde Ubuntu:**

```text
sudo arping -D -I enp2s0 -c 3 192.168.1.30
Sent 3 probes (3 broadcast(s))
Received 0 response(s)
```

Esta comprobación no detectó un conflicto ARP en ese momento; **no garantiza** que la dirección no esté reservada en otro equipo apagado.

**Configuración aplicada en Kali** al perfil `Conexión cableada 1` asociado a `eth1`:

```bash
sudo nmcli connection modify "Conexión cableada 1" \
  ipv4.method manual \
  ipv4.addresses 192.168.1.30/24 \
  ipv4.gateway "" \
  ipv4.never-default yes \
  ipv4.dns "" \
  ipv6.method disabled

sudo nmcli connection up "Conexión cableada 1" ifname eth1
```

NetworkManager confirmó `Conexión activada con éxito`.

**Validación posterior en Kali:**

```text
ip -br -4 address
lo    UNKNOWN  127.0.0.1/8
eth0  UP       10.0.2.15/24
eth1  UP       192.168.1.30/24

ip -4 route
default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100
192.168.1.0/24 dev eth1 proto kernel scope link src 192.168.1.30 metric 101

ip route get 192.168.1.20
192.168.1.20 dev eth1 src 192.168.1.30 uid 1000
```

**Resultado:** Kali mantiene Internet por NAT y dirige el tráfico hacia la antena por `eth1` sin usar NAT.

## 4. Evidencia de atribución de IP

Se abrió en Ubuntu una captura limitada a un paquete TCP destinado al SSH de la antena:

```bash
sudo tcpdump -ni enp2s0 -c 1 \
  'tcp and dst host 192.168.1.20 and dst port 22'
```

Desde Kali se realizó únicamente una prueba de conectividad TCP:

```bash
nc -nvz -w 3 192.168.1.20 22
```

**Antes del segundo adaptador:** la captura mostraba el origen traducido a `192.168.1.10` (anfitrión Ubuntu).  
**Después del segundo adaptador:**

```text
2026-11-06 13:10:16 +01:00
IP 192.168.1.30.32882 > 192.168.1.20.22: Flags [S]
```

**Conclusión verificada:** la conexión del equipo Red Team llega al segmento PowerBeam con IP de origen `192.168.1.30`, distinta de la IP del SOC `192.168.1.10`.

## 5. Pruebas SSH y registros de la antena

### Prueba A — Cliente SSH con configuración predeterminada

Comando ejecutado desde Kali:

```bash
ssh \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o NumberOfPasswordPrompts=1 \
  -o ConnectTimeout=5 \
  ubnt@192.168.1.20
```

**Respuesta de Kali:**

```text
Unable to negotiate with 192.168.1.20 port 22:
no matching host key type found. Their offer: ssh-rsa,ssh-dss
```

**Registros syslog recibidos en Ubuntu:**

```text
2026-11-06T13:13:45.928677+01:00 source=192.168.1.20 <86>Nov  6 12:13:45 dropbear[862]: Child connection from 192.168.1.30:45976
2026-11-06T13:13:45.931490+01:00 source=192.168.1.20 <86>Nov  6 12:13:45 dropbear[862]: Exit before auth: No matching algo hostkey
```

### Prueba B — Compatibilidad `ssh-rsa` limitada a una conexión

Comando ejecutado desde Kali:

```bash
ssh \
  -o HostKeyAlgorithms=+ssh-rsa \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o NumberOfPasswordPrompts=1 \
  -o ConnectTimeout=5 \
  ubnt@192.168.1.20
```

**Respuesta de Kali:**

```text
Connection reset by 192.168.1.20 port 22
```

**Registros syslog recibidos en Ubuntu:**

```text
2026-11-06T13:16:31.846407+01:00 source=192.168.1.20 <86>Nov  6 12:16:31 dropbear[863]: Child connection from 192.168.1.30:38486
2026-11-06T13:16:31.849395+01:00 source=192.168.1.20 <86>Nov  6 12:16:31 dropbear[863]: Exit before auth: No matching algo hostkey
```

**Lectura de resultados:** en ambas pruebas Dropbear identificó la dirección de Kali y registró un fallo de negociación **antes de autenticación**. Permitir `ssh-rsa` para la segunda conexión no logró completar la negociación. **No apareció una solicitud de contraseña ni se observó un intento fallido de contraseña.** Por tanto, estas pruebas **no validan ni deben incrementar** los contadores de SOC-001/SOC-002 (autenticación).

Nota horaria: las líneas están fechadas por rsyslog en `+01:00`, mientras que el mensaje embebido del dispositivo presenta otra hora. Para correlación, conservar ambas fuentes y validar sincronización horaria más adelante.

## 6. Hallazgos y límites

| ID | Observación / hallazgo | Evidencia | Estado |
| --- | --- | --- | --- |
| RTBT-001 | Kali y SOC tienen IP de origen diferenciada hacia la antena | Ruta de Kali y `tcpdump` | **Verificado** |
| RTBT-002 | El puerto SSH de la antena es alcanzable desde Kali | `nc` al 22/TCP | **Verificado** |
| RTBT-003 | La antena envía por syslog conexiones SSH y fallos previos a autenticación | Dos pares de eventos Dropbear | **Verificado** |
| RTBT-004 | La negociación de claves de host con el cliente moderno no completó; oferta `ssh-rsa,ssh-dss` | Salida de Kali y Dropbear | **Observado, pendiente de investigación** |
| RTBT-005 | No se conoce todavía la visibilidad de errores de contraseña por SSH en este escenario | No se alcanzó autenticación | **No evaluado** |

La oferta de algoritmos heredados es una cuestión de compatibilidad y una posible debilidad de configuración que conviene investigar, **no una explotación demostrada**. No activar opciones criptográficas inseguras de forma global ni alterar el firmware o la configuración de producción sin una evaluación y copia de seguridad previas.

**Límites de detección:** disponer de syslog no implica observar todo el tráfico o todos los intentos de ataque. Las pruebas realizadas no demuestran detección de escaneos, autenticaciones fallidas ni explotación. No se ha verificado una alerta automática específica para los eventos `Exit before auth`.

## 7. Seguridad, evidencia y cierre de la sesión

- No se compartieron contraseñas, claves privadas, tokens ni archivos de configuración sensibles.
- No se ejecutaron ataques de fuerza bruta, cambios en la antena ni pruebas de denegación de servicio.
- La captura de `tcpdump` fue una observación efímera del encabezado TCP; los fragmentos de terminal documentados aquí **no constituyen un archivo PCAP conservado ni prueban cadena de custodia formal**.
- Los registros originales permanecen en `/var/log/powerbeam/powerbeam.log` bajo los controles actuales del SOC; este documento contiene extractos.
- No se modificaron las reglas SOC, los temporizadores systemd ni los detectores durante estas comprobaciones.

## 8. Punto de reanudación / siguientes acciones

1. Verificar fecha/hora, zona horaria y versión de firmware de la antena antes de atribuir causas a la negociación SSH.
2. Examinar de forma no intrusiva los algoritmos SSH anunciados y los ajustes de administración disponibles; no activar algoritmos obsoletos globalmente.
3. Determinar por qué `HostKeyAlgorithms=+ssh-rsa` siguió terminando con `No matching algo hostkey` (cliente, Dropbear o política del dispositivo).
4. Diseñar **una** prueba de autenticación autorizada que llegue a solicitar contraseña, limitando intentos y protegiendo el acceso administrativo.
5. Contrastar eventos observados con `auth_detector` y reglas SOC-001/SOC-002; no reinterpretar errores de negociación como fallos de contraseña.
6. Evaluar más adelante telemetría adicional para eventos que no queden reflejados en syslog (por ejemplo, escaneos), con un punto real de observación del tráfico.
7. Planificar hardening y una repetición de las pruebas, sin tocar todavía la configuración de la antena.

**Estado al cerrar:** topología Red Team/Blue Team funcional, origen de Kali identificado, dos eventos previos a autenticación recibidos en el SOC, autenticación SSH todavía pendiente de evaluar.
