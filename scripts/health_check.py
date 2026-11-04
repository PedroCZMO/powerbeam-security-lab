#!/usr/bin/env python3
"""Salud operativa PowerBeam: consultas de solo lectura e ICMP opcional.

No inspecciona ni modifica checkpoints o alertas. El estado de ingestión
queda UNKNOWN mientras no exista una señal fiable de heartbeat.
Si se solicita, envía hasta dos ecos ICMP: no certifican entrega de syslog.
"""
import argparse
import gzip
import ipaddress
import json
import os
import re
import stat
import subprocess
import time
from datetime import datetime, timezone

RECEIPT_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\S+) source=(\d{1,3}(?:\.\d{1,3}){3})(?:\s|$)")
MAX_TAIL = 256 * 1024
MAX_GZIP_BYTES = 12 * 1024 * 1024
PING_STAT_RE = re.compile(r"(?m)^(\d+) packets transmitted,\s*(\d+) (?:packets )?received(?:,|$)")

PROPERTIES = (
    "LoadState", "ActiveState", "Result", "ExecMainStatus",
    "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic",
)


def read_unit(unit, timeout=5):
    """Lee propiedades con systemctl, sin invocar shell ni escribir estado."""
    try:
        result = subprocess.run(
            ["systemctl", "show", unit, "--no-pager", "--property=" + ",".join(PROPERTIES)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"No se pudo consultar {unit}: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError(f"systemctl falló para {unit}: {result.stderr.strip()}")
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if values.get("LoadState") != "loaded":
        raise RuntimeError(f"Unidad {unit} no cargada: {values.get('LoadState', 'desconocida')}")
    return values



def read_udp_listeners(timeout=5):
    """Devuelve los endpoints UDP escuchando según `ss` (no el proceso dueño).

    `-n` evita traducir puertos; `-l` solo sockets de escucha; `-u` solo UDP.
    No requiere sudo en un Ubuntu típico. No usamos `-p` porque el propietario
    puede quedar oculto para usuarios sin privilegios.
    """
    try:
        result = subprocess.run(
            ["ss", "-H", "-lun"], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"No se pudo consultar sockets UDP: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError(f"ss devolvió código {result.returncode}: {result.stderr.strip()}")
    endpoints = []
    for row in result.stdout.splitlines():
        fields = row.split()
        if len(fields) >= 5 and fields[0] in ("UNCONN", "ESTAB"):
            endpoints.append(fields[3])
    return endpoints


def _split_endpoint(endpoint):
    """Extrae dirección y puerto numérico de una columna Local Address:Port."""
    host, sep, port_str = endpoint.rpartition(":")
    if not sep or not port_str.isdecimal():
        return None
    return host.strip("[]"), int(port_str)


def check_udp_listener(endpoints, address="192.168.1.10", port=5514):
    """Comprueba enlace del receptor a la IP prevista, no entrega ni propiedad."""
    actual = []
    for ep in endpoints:
        parsed = _split_endpoint(ep)
        if parsed is not None and parsed[1] == port:
            actual.append(parsed[0])

    # Un wildcard implica exposición potencial a otras interfaces, incluso
    # cuando otra entrada aparezca ligada a la IP prevista.
    if any(host in ("0.0.0.0", "*", "::") for host in actual):
        return item("WARNING", f"UDP {port} usa dirección comodín; revisar exposición de interfaces (esperado {address}:{port})")
    if address in actual:
        return item("HEALTHY", f"Socket UDP presente en {address}:{port} (propietario y recepción no verificados)")
    if actual:
        return item("CRITICAL", f"No existe socket UDP en {address}:{port}; puerto {port} ligado a: {', '.join(actual)}")
    return item("CRITICAL", f"No se encontró socket UDP en {address}:{port}")



def check_antenna_icmp(address="192.168.1.20", timeout=8):
    """Observación ICMP puntual, sin privilegios ni modificaciones.

    Un ping positivo no certifica que el dispositivo envíe syslog.
    Un ping sin respuesta no prueba que el dispositivo esté desconectado.
    El resultado se mantiene al margen de overall_status (salud del colector).
    """
    try:
        destination = str(ipaddress.IPv4Address(address))
    except ipaddress.AddressValueError:
        return item("UNKNOWN", f"Dirección IPv4 no válida para ICMP: {address!r}")

    # Dos paquetes y un límite estricto. No ejecutar mediante shell.
    command = ["ping", "-n", "-c", "2", "-W", "2", "-w", "6", destination]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return item("UNKNOWN", f"No se pudo completar comprobación ICMP: {exc}")

    if result.returncode not in (0, 1):
        return item("UNKNOWN", f"ping terminó con error (código {result.returncode}); revisar conectividad y permisos")
    match = PING_STAT_RE.search(result.stdout)
    if match is None:
        return item("UNKNOWN", "ping no proporcionó estadísticas interpretables")
    sent, received = (int(x) for x in match.groups())
    if sent != 2 or not 0 <= received <= sent:
        return item("UNKNOWN", "ping devolvió contadores ICMP incoherentes")
    observation = {"packets_sent": sent, "packets_received": received,
                   "packet_loss_percent": round(100 * (sent - received) / sent, 1)}
    if result.returncode == 0 and received == sent:
        return {**item("HEALTHY", f"{destination} respondió a los dos ecos ICMP; no confirma syslog"), **observation}
    if received == 0:
        return {**item("WARNING", f"{destination} no respondió a ICMP; puede bloquear ping o existir un fallo de red"), **observation}
    if received < sent:
        return {**item("WARNING", f"{destination} respondió parcialmente a ICMP; posible pérdida de paquetes"), **observation}
    return item("UNKNOWN", "Resultado ICMP contradictorio; revisar ping")


def _last_lines(path, compressed=False):
    """Últimas líneas completas de un fichero, sin seguir symlinks.

    No altera archivos ni procesa un .gz de tamaño descomprimido ilimitado.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"No es un archivo regular: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            if compressed:
                tail = b""
                total = 0
                with gzip.GzipFile(fileobj=stream, mode="rb") as unpacked:
                    while True:
                        chunk = unpacked.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_GZIP_BYTES:
                            raise RuntimeError(f"Histórico comprimido supera el límite de análisis: {path}")
                        tail = (tail + chunk)[-MAX_TAIL:]
                trimmed = total > MAX_TAIL
            else:
                start = max(0, st.st_size - MAX_TAIL)
                stream.seek(start)
                tail = stream.read(MAX_TAIL)
                trimmed = start > 0
    finally:
        os.close(fd)
    if trimmed:
        # El primer fragmento puede empezar a mitad de una línea.
        tail = tail.partition(b"\n")[2]
    if not tail.endswith(b"\n"):
        # Nunca convertir una línea incompleta en prueba de recepción.
        tail = tail.rpartition(b"\n")[0] + (b"\n" if b"\n" in tail else b"")
    return tail.splitlines()


def read_last_received_timestamp(log_dir="/var/log/powerbeam", source_ip="192.168.1.20"):
    """Fecha de recepción más reciente registrada por rsyslog para la antena.

    Se consulta primero el archivo actual, después el .1 y luego los gzip,
    siguiendo el orden normal del logrotate configurado en el laboratorio.
    No usa la hora dentro del mensaje de la antena ni el mtime del fichero.
    """
    root = os.fspath(log_dir)
    for suffix in ("", ".1", *(f".{n}.gz" for n in range(2, 15))):
        path = os.path.join(root, "powerbeam.log" + suffix)
        try:
            lines = _last_lines(path, compressed=suffix.endswith(".gz"))
        except FileNotFoundError:
            continue
        except (OSError, EOFError, ValueError, RuntimeError) as exc:
            raise RuntimeError(f"No se pudo leer histórico {path}: {exc}") from exc
        for raw_line in reversed(lines):
            match = RECEIPT_RE.match(raw_line.decode("utf-8", errors="replace"))
            if not match or match.group(2) != source_ip:
                continue
            try:
                received = datetime.fromisoformat(match.group(1))
            except ValueError:
                continue
            if received.tzinfo is None or received.utcoffset() is None:
                continue
            return received.astimezone(timezone.utc)
    return None


def check_log_activity(log_dir="/var/log/powerbeam", source_ip="192.168.1.20",
                       fresh_minutes=30, now_utc=None, reader=read_last_received_timestamp):
    """Observación puntual: no demuestra que exista ingestión continua."""
    now_utc = now_utc or datetime.now(timezone.utc)
    if now_utc.tzinfo is None or now_utc.utcoffset() is None:
        raise ValueError("now_utc debe incluir zona horaria")
    try:
        timestamp = reader(log_dir, source_ip)
    except (OSError, RuntimeError, ValueError) as exc:
        return item("UNKNOWN", f"No se pudo observar la recepción: {exc}")
    if timestamp is None:
        return item("UNKNOWN", "No se encontró una marca válida de recepción de esta antena en los históricos disponibles")
    age = (now_utc - timestamp).total_seconds()
    if age < -60:
        return item("UNKNOWN", f"Marca de recepción futura; comprobar el reloj de Ubuntu: {timestamp.isoformat()}")
    data = {
        "observed_at": timestamp.isoformat(),
        "age_seconds": max(0, round(age, 1)),
    }
    if age <= fresh_minutes * 60:
        return {**item("HEALTHY", "Se observó un mensaje reciente de la antena; no equivale a heartbeat"), **data}
    return {**item("WARNING", "Último mensaje antiguo; podría ser inactividad normal, no prueba de desconexión"), **data}

def item(status, detail):
    return {"status": status, "detail": detail}


def check_active(unit, properties):
    if properties.get("ActiveState") == "active":
        return item("HEALTHY", f"{unit} activo")
    return item("CRITICAL", f"{unit} no está activo: {properties.get('ActiveState', 'desconocido')}")


def as_us(properties, field):
    try:
        return int(properties.get(field, "0"))
    except ValueError:
        return 0


def check_monitor(unit, properties, now_monotonic_us, max_age_seconds=900, max_runtime_seconds=120):
    """Un servicio oneshot inactivo tras finalizar con éxito es normal."""
    state = properties.get("ActiveState", "unknown")
    if state == "failed":
        return item("CRITICAL", f"{unit} en estado failed")

    start_us = as_us(properties, "ExecMainStartTimestampMonotonic")
    exit_us = as_us(properties, "ExecMainExitTimestampMonotonic")
    if state in ("activating", "active") and start_us > exit_us:
        elapsed = (now_monotonic_us - start_us) / 1_000_000
        if elapsed < -1:
            return item("WARNING", f"{unit}: reloj monotónico incoherente")
        if elapsed > max_runtime_seconds:
            return item("CRITICAL", f"{unit} lleva {elapsed:.0f}s en ejecución (límite {max_runtime_seconds}s)")
        return item("WARNING", f"{unit} en ejecución desde hace {max(0, elapsed):.0f}s; resultado pendiente")

    result = properties.get("Result", "")
    exit_code = properties.get("ExecMainStatus", "")
    if result not in ("success", ""):
        return item("CRITICAL", f"{unit} última ejecución fallida: Result={result}")
    if exit_code not in ("0", ""):
        return item("CRITICAL", f"{unit} última ejecución con ExecMainStatus={exit_code}")
    if state not in ("inactive", "active"):
        return item("WARNING", f"{unit}: estado inesperado {state}")
    if exit_us <= 0:
        return item("WARNING", f"{unit}: no consta una finalización comprobable")
    if result != "success" or exit_code != "0":
        return item("WARNING", f"{unit}: resultado de la última ejecución incompleto")

    age = (now_monotonic_us - exit_us) / 1_000_000
    if age < -1:
        return item("WARNING", f"{unit}: marca monotónica futura")
    if age > max_age_seconds:
        return item("CRITICAL", f"{unit}: última ejecución correcta hace {age:.0f}s (máx. {max_age_seconds}s)")
    return item("HEALTHY", f"{unit}: última ejecución correcta hace {max(0, age):.0f}s")


def collect(now_monotonic_us=None, max_age_seconds=900, max_runtime_seconds=120,
            reader=read_unit, udp_reader=read_udp_listeners,
            syslog_address="192.168.1.10", syslog_port=5514,
            inspect_log_activity=False, log_dir="/var/log/powerbeam",
            source_ip="192.168.1.20", fresh_minutes=30,
            log_reader=read_last_received_timestamp, wall_now=None,
            check_antenna=False, icmp_reader=check_antenna_icmp, icmp_address=None):
    if now_monotonic_us is None:
        now_monotonic_us = int(time.monotonic() * 1_000_000)
    units = {
        "rsyslog": ("rsyslog.service", "active"),
        "timer_v1": ("powerbeam-monitor.timer", "active"),
        "timer_v3": ("powerbeam-monitor-v3.timer", "active"),
        "monitor_v1": ("powerbeam-monitor.service", "oneshot"),
        "monitor_v3": ("powerbeam-monitor-v3.service", "oneshot"),
    }
    checks = {}
    for key, (unit, kind) in units.items():
        try:
            props = reader(unit)
            checks[key] = (check_active(unit, props) if kind == "active" else
                           check_monitor(unit, props, now_monotonic_us, max_age_seconds, max_runtime_seconds))
        except RuntimeError as exc:
            checks[key] = item("UNKNOWN", str(exc))

    try:
        checks["syslog_udp"] = check_udp_listener(udp_reader(), syslog_address, syslog_port)
    except RuntimeError as exc:
        checks["syslog_udp"] = item("UNKNOWN", str(exc))

    if inspect_log_activity:
        checks["log_activity"] = check_log_activity(
            log_dir, source_ip, fresh_minutes=fresh_minutes,
            reader=log_reader, now_utc=wall_now,
        )
    else:
        checks["log_activity"] = item(
            "UNKNOWN", "Inspección opcional no activada; usar --inspect-log-activity con permisos de lectura",
        )

    if check_antenna:
        try:
            checks["antenna_icmp"] = icmp_reader(icmp_address or source_ip)
        except (OSError, RuntimeError, ValueError) as exc:
            checks["antenna_icmp"] = item("UNKNOWN", f"Error observando ICMP: {exc}")
    else:
        checks["antenna_icmp"] = item("UNKNOWN", "Comprobación opcional desactivada; usar --check-antenna-icmp")

    # No confundimos un socket abierto con entrega de mensajes, ni un fichero
    # vacío o un checkpoint actualizado con recepción real.
    checks["log_ingestion"] = item(
        "UNKNOWN", "Sin heartbeat de la antena: no es posible confirmar ingestión continua ni avería solo por ausencia de eventos",
    )
    operational = [checks[name]["status"] for name in (*units, "syslog_udp")]
    overall = ("CRITICAL" if "CRITICAL" in operational else
               "WARNING" if "WARNING" in operational else
               "UNKNOWN" if "UNKNOWN" in operational else "HEALTHY")
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall,
        "ingestion_status": "UNKNOWN",
        "connectivity_status": checks["antenna_icmp"]["status"],
        "checks": checks,
        "note": "overall_status evalúa solo infraestructura local; ICMP y log_activity son señales independientes y no certifican ingestión continua",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Salud de PowerBeam Security Lab (sin escrituras; ICMP opcional)")
    parser.add_argument("--max-age-minutes", type=float, default=15.0)
    parser.add_argument("--max-runtime-seconds", type=float, default=120.0)
    parser.add_argument("--syslog-address", default="192.168.1.10",
                        help="IP local prevista para el receptor UDP (por defecto: 192.168.1.10)")
    parser.add_argument("--syslog-port", type=int, default=5514,
                        help="Puerto UDP local (por defecto: 5514)")
    parser.add_argument("--inspect-log-activity", action="store_true",
                        help="Consulta solo-lectura de la última marca de recepción de syslog")
    parser.add_argument("--log-dir", default="/var/log/powerbeam")
    parser.add_argument("--source-ip", default="192.168.1.20")
    parser.add_argument("--fresh-minutes", type=float, default=30.0)
    parser.add_argument("--check-antenna-icmp", action="store_true",
                        help="Envía hasta dos ecos ICMP a --source-ip para observar conectividad, sin confirmar syslog")
    args = parser.parse_args(argv)
    if args.max_age_minutes <= 0 or args.max_runtime_seconds <= 0 or args.fresh_minutes <= 0:
        parser.error("Los umbrales deben ser positivos")
    if not 1 <= args.syslog_port <= 65535:
        parser.error("El puerto UDP debe estar entre 1 y 65535")
    report = collect(max_age_seconds=args.max_age_minutes * 60,
                     max_runtime_seconds=args.max_runtime_seconds,
                     syslog_address=args.syslog_address, syslog_port=args.syslog_port,
                     inspect_log_activity=args.inspect_log_activity,
                     log_dir=args.log_dir, source_ip=args.source_ip,
                     fresh_minutes=args.fresh_minutes,
                     check_antenna=args.check_antenna_icmp)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return {"HEALTHY": 0, "WARNING": 1, "UNKNOWN": 1, "CRITICAL": 2}[report["overall_status"]]


if __name__ == "__main__":
    raise SystemExit(main())
