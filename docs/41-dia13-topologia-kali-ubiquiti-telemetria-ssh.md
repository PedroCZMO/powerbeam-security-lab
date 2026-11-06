# Día 13 — Laboratorio Red Team / Blue Team: Kali, PowerBeam y telemetría SSH

**Proyecto:** PowerBeam Security Lab  
**Fecha del ejercicio:** 2026-11-06 (Europe/Madrid)  
**Estado:** Topología y atribución de IP verificadas; telemetría SSH recibida; negociación SSH y fase de oferta de métodos de autenticación **alcanzadas**. Ninguna autenticación completada ni contraseña probada.
**Naturaleza:** Laboratorio propio y pruebas autorizadas, sin explotación ni fuerza bruta.

## 1. Objetivo y alcance

Preparar una VM Kali Linux como estación Red Team independiente del Ubuntu que ejecuta el SOC; comprobar que la antena Ubiquiti PowerBeam recibe la IP real de Kali como origen; y verificar si la antena remite al SOC eventos de una conexión SSH.

**Activo bajo evaluación:** Ubiquiti PowerBeam (`192.168.1.20`) — plano de administración TCP/22.  
**Alcance de estas comprobaciones:** red, negociación SSH y comprobación de métodos de autenticación disponibles. **No** se han ejecutado intentos de contraseña, explotación ni pruebas de denegación de servicio.

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

### Prueba C — Diagnóstico con OpenSSH 10.6 y registro de la negociación (13:26 h)

**Versión del cliente:** `OpenSSH_10.6p1 Debian-1`, OpenSSL `3.6.5`.

La consulta `ssh -G -o HostKeyAlgorithms=+ssh-rsa ubnt@192.168.1.20` confirmó que la propuesta efectiva del cliente **sí contenía** `ssh-rsa`, además de métodos modernos de intercambio de claves.

Se ejecutó desde Kali una conexión de diagnóstico con `-vvv`, `HostKeyAlgorithms=+ssh-rsa`, `BatchMode=yes`, `PreferredAuthentications=none`, autenticación por contraseña y clave desactivada, y `ConnectTimeout=5`. No se introdujeron credenciales.

**Tramos determinantes de la salida del cliente:**

```text
Remote protocol version 2.0, remote software version dropbear
SSH2_MSG_KEXINIT sent
SSH2_MSG_KEXINIT received
peer server KEXINIT proposal
KEX algorithms: curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
host key algorithms: ssh-rsa,ssh-dss
kex: algorithm: curve25519-sha256
kex: host key algorithm: ssh-rsa
kex: server->client cipher: aes128-ctr MAC: hmac-sha2-256 compression: none
kex: client->server cipher: aes128-ctr MAC: hmac-sha2-256 compression: none
expecting SSH2_MSG_KEX_ECDH_REPLY
Connection closed by 192.168.1.20 port 22
```

**Telemetría correlacionada en el SOC:**

```text
2026-11-06T13:26:16.527995+01:00 source=192.168.1.20 <86>Nov  6 12:26:16 dropbear[864]: Child connection from 192.168.1.30:52800
2026-11-06T13:26:16.532472+01:00 source=192.168.1.20 <86>Nov  6 12:26:16 dropbear[864]: Exit before auth: No matching algo hostkey
```

**Interpretación precisa:** el cliente y el servidor anunciaron algoritmos coincidentes y el cliente **seleccionó** `curve25519-sha256` + `ssh-rsa`, pero la negociación **no terminó**: se cerró antes de recibir `SSH2_MSG_KEX_ECDH_REPLY`. El mensaje de Dropbear apunta a un fallo interno de selección/uso de algoritmo de clave de host **desde la perspectiva del servidor**. Todavía no está demostrada la causa: no puede afirmarse que falte la clave privada RSA, que sea un fallo de firmware o que el cliente sea el responsable.

**Conclusión de detección:** tercer evento previo a autenticación observado desde la IP Red Team `192.168.1.30`. **No hubo acceso ni fallo de contraseña**, así que no debe contabilizarse como SOC-001/SOC-002.

**Contraste realizado:** la prueba D siguiente restringió `HostKeyAlgorithms` a `ssh-rsa` (sin `+`) y sí completó el intercambio de claves. No fue necesario habilitar `ssh-dss` ni modificar la configuración de Dropbear.

### Prueba D — Algoritmo de host explícito `ssh-rsa` (13:31 h)

La prueba restringió **solo esta conexión** al algoritmo de host `ssh-rsa`. Se desactivó la autenticación interactiva mediante `BatchMode=yes` y se evitó introducir contraseñas.

```bash
ssh -vv \
  -o HostKeyAlgorithms=ssh-rsa \
  -o BatchMode=yes \
  -o PreferredAuthentications=none \
  -o PubkeyAuthentication=no \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o ConnectTimeout=5 \
  ubnt@192.168.1.20
```

**Evidencia decisiva de Kali:**

```text
kex: algorithm: curve25519-sha256
kex: host key algorithm: ssh-rsa
kex: server->client cipher: aes128-ctr MAC: hmac-sha2-256 compression: none
kex: client->server cipher: aes128-ctr MAC: hmac-sha2-256 compression: none
SSH2_MSG_KEX_ECDH_REPLY received
Server host key: ssh-rsa SHA256:mRuQdbn6n+nSQPb+Es5vFxJnTcci9f+nNq0Ro2ZWuDE
Host key verification failed.
```

**Eventos recibidos por el SOC:**

```text
2026-11-06T13:31:45.962410+01:00 source=192.168.1.20 <86>Nov  6 12:31:45 dropbear[865]: Child connection from 192.168.1.30:48998
2026-11-06T13:31:46.747868+01:00 source=192.168.1.20 <86>Nov  6 12:31:46 dropbear[865]: Exit before auth: Exited normally
```

**Interpretación:** esta vez Kali **recibió** la respuesta al intercambio de claves y la clave pública RSA del servidor. El cliente se detuvo **en la verificación de la identidad de la clave de host**, porque no había un registro de confianza previo en `known_hosts` y se utilizó `BatchMode=yes` (sin interacción). No hubo intento de contraseña ni autenticación. La diferencia entre `HostKeyAlgorithms=+ssh-rsa` (falló en este escenario) y `HostKeyAlgorithms=ssh-rsa` (avanzó hasta recibir la clave) es un resultado empírico, **no prueba por sí sola la causa interna en Dropbear**. No desactivar `StrictHostKeyChecking` de forma indiscriminada; verificar la huella digital mediante una fuente confiable antes de establecer confianza.

**Continuación realizada:** la prueba E aceptó interactivamente la clave de host mediante confianza en el primer uso (TOFU), sin verificación independiente; alcanzó la oferta de métodos de autenticación del servidor. La contraseña no se intentó.

### Prueba E — Primera confianza de clave de host y llegada a la fase de autenticación (13:38 h)

Kali repitió la conexión restringiendo el algoritmo de clave de host a `ssh-rsa` y habilitando **solo la confirmación interactiva de identidad del servidor**. Las autenticaciones por contraseña, clave pública y teclado interactivo permanecieron desactivadas.

```bash
ssh -v \
  -o HostKeyAlgorithms=ssh-rsa \
  -o StrictHostKeyChecking=ask \
  -o BatchMode=no \
  -o PreferredAuthentications=none \
  -o PubkeyAuthentication=no \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o ConnectTimeout=5 \
  ubnt@192.168.1.20
```

**Evidencia clave del cliente Kali:**

```text
kex: algorithm: curve25519-sha256
kex: host key algorithm: ssh-rsa
SSH2_MSG_KEX_ECDH_REPLY received
Server host key: ssh-rsa SHA256:mRuQdbn6n+nSQPb+Es5vFxJnTcci9f+nNq0Ro2ZWuDE
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.1.20' (RSA) to the list of known hosts.
SSH2_MSG_NEWKEYS sent
SSH2_MSG_NEWKEYS received
SSH2_MSG_SERVICE_ACCEPT received
Authentications that can continue: publickey,password
No more authentication methods to try.
ubnt@192.168.1.20: Permission denied (publickey,password).
```

**Telemetría recibida en Ubuntu SOC:**

```text
2026-11-06T13:38:51.996610+01:00 source=192.168.1.20 <86>Nov  6 12:38:51 dropbear[867]: Child connection from 192.168.1.30:35112
2026-11-06T13:38:55.575442+01:00 source=192.168.1.20 <86>Nov  6 12:38:55 dropbear[867]: Exit before auth (user 'ubnt', 0 fails): Exited normally
```

**Interpretación:** en esta prueba se completó la negociación SSH y el cliente recibió los métodos de autenticación disponibles (`publickey,password`). La línea final `Permission denied` **no indica contraseña incorrecta**: ninguna modalidad de autenticación estaba habilitada en el cliente, y Dropbear registró inequívocamente `0 fails`. No hubo sesión de usuario ni acceso autenticado. **SOC-001 y SOC-002 no han sido validadas con esta prueba**.

La huella RSA se aceptó mediante **Trust On First Use (TOFU)** desde la red de laboratorio; no hay constancia de verificación independiente contra una fuente de confianza. Para un entorno empresarial, verificarla fuera de banda antes de establecer confianza. La advertencia de OpenSSH sobre ausencia de intercambio poscuántico también apareció; es una observación de compatibilidad con un servidor antiguo, **no evidencia de una intrusión**.

**Hallazgo útil para el SOC:** los eventos `Exit before auth` incluyen distintos motivos (algoritmo no compatible y salida normal), incluso en una sesión que alcanzó la oferta de métodos de autenticación; no deben clasificarse automáticamente como intentos fallidos de contraseña.

## 6. Hallazgos y límites

| ID | Observación / hallazgo | Evidencia | Estado |
| --- | --- | --- | --- |
| RTBT-001 | Kali y SOC tienen IP de origen diferenciada hacia la antena | Ruta de Kali y `tcpdump` | **Verificado** |
| RTBT-002 | El puerto SSH de la antena es alcanzable desde Kali | `nc` al 22/TCP | **Verificado** |
| RTBT-003 | La antena envía por syslog conexiones SSH y cierres previos a autenticación | Cinco pares de eventos Dropbear | **Verificado** |
| RTBT-004 | Oferta heredada de algoritmos de host `ssh-rsa,ssh-dss`; el intercambio de claves avanzó al forzar `ssh-rsa` | Pruebas A–D y syslog Dropbear | **Compatibilidad observada; endurecimiento pendiente** |
| RTBT-005 | No se conoce todavía la visibilidad de errores de contraseña por SSH en este escenario | No se realizó autenticación con contraseña; sí se llegó a la oferta de métodos | **No evaluado** |
| RTBT-006 | Kali recibió la clave RSA y la aceptó por TOFU; no se ha verificado de forma independiente | `SSH2_MSG_KEX_ECDH_REPLY received`, huella SHA256 y prueba E | **Confianza TOFU; verificación externa pendiente** |

La oferta de algoritmos heredados es una cuestión de compatibilidad y una posible debilidad de configuración que conviene investigar, **no una explotación demostrada**. No activar opciones criptográficas inseguras de forma global ni alterar el firmware o la configuración de producción sin una evaluación y copia de seguridad previas.

**Límites de detección:** disponer de syslog no implica observar todo el tráfico o todos los intentos de ataque. Las pruebas realizadas no demuestran detección de escaneos, fallos de contraseña ni explotación. No se ha verificado una alerta automática específica para los eventos `Exit before auth`.

## 7. Seguridad, evidencia y cierre de la sesión

- No se compartieron contraseñas, claves privadas, tokens ni archivos de configuración sensibles.
- No se ejecutaron ataques de fuerza bruta, cambios en la antena ni pruebas de denegación de servicio.
- La captura de `tcpdump` fue una observación efímera del encabezado TCP; los fragmentos de terminal documentados aquí **no constituyen un archivo PCAP conservado ni prueban cadena de custodia formal**.
- Los registros originales permanecen en `/var/log/powerbeam/powerbeam.log` bajo los controles actuales del SOC; este documento contiene extractos.
- No se modificaron las reglas SOC, los temporizadores systemd ni los detectores durante estas comprobaciones.

## 8. Punto de reanudación / siguientes acciones

1. Verificar independientemente la huella SSH RSA de la antena; Kali la aceptó por TOFU, no por una comprobación fuera de banda.
2. Verificar fecha/hora, zona horaria y versión exacta de firmware de la antena antes de proponer cambios.
3. Diseñar **una** prueba autorizada de contraseña incorrecta, con límites claros y sin automatizar intentos; confirmar que se genera un evento `0 fails` vs. `1 fail` y que el SOC lo interpreta correctamente.
4. Revisar las reglas SOC-001/SOC-002 existentes: no reinterpretar errores de negociación como fallos de contraseña y comprobar la cobertura específica de mensajes SSH de Dropbear.
5. Evaluar más adelante telemetría adicional para eventos que no queden reflejados en syslog (por ejemplo, escaneos), con un punto real de observación del tráfico.
6. Planificar hardening y una repetición de las pruebas, sin tocar todavía la configuración de la antena.

**Estado al cerrar:** topología Red Team/Blue Team funcional, IP de Kali correctamente atribuida, **cinco conexiones SSH registradas en syslog**, negociación SSH completada en pruebas D y E, y fase de autenticación alcanzada en la prueba E (**cero fallos reales de credenciales**). La verificación independiente de la clave de host y la prueba controlada de contraseña quedan pendientes.
