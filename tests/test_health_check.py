"""Pruebas del supervisor de salud sin tocar systemd ni los logs reales."""
import importlib.util
import pathlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "health_check.py"
spec = importlib.util.spec_from_file_location("health_check", SCRIPT)
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
NOW = 1_000_000_000


def service(**overrides):
    base = {
        "LoadState": "loaded", "ActiveState": "inactive", "Result": "success",
        "ExecMainStatus": "0", "ExecMainStartTimestampMonotonic": "900000000",
        "ExecMainExitTimestampMonotonic": "950000000",
    }
    base.update(overrides)
    return base


def healthy_udp_reader():
    return ["192.168.1.10:5514"]


def healthy_reader(unit):
    if unit.endswith(".timer") or unit == "rsyslog.service":
        return {"ActiveState": "active"}
    return service()


class HealthCheckTests(unittest.TestCase):
    def test_oneshot_inactivo_tras_exito_es_saludable(self):
        self.assertEqual(health.check_monitor("v1", service(), NOW)["status"], "HEALTHY")

    def test_oneshot_en_ejecucion_no_interpreta_status_cero_como_exito(self):
        props = service(ActiveState="activating", ExecMainStartTimestampMonotonic="990000000",
                        ExecMainExitTimestampMonotonic="0")
        result = health.check_monitor("v3", props, NOW)
        self.assertEqual(result["status"], "WARNING")
        self.assertIn("pendiente", result["detail"])

    def test_oneshot_encallado_es_critico(self):
        props = service(ActiveState="activating", ExecMainStartTimestampMonotonic="100000000",
                        ExecMainExitTimestampMonotonic="0")
        self.assertEqual(health.check_monitor("v3", props, NOW)["status"], "CRITICAL")

    def test_ultima_ejecucion_fallida_es_critica(self):
        props = service(Result="exit-code", ExecMainStatus="1")
        self.assertEqual(health.check_monitor("v1", props, NOW)["status"], "CRITICAL")

    def test_servicio_demasiado_antiguo_es_critico(self):
        props = service(ExecMainExitTimestampMonotonic="100000000")
        self.assertEqual(health.check_monitor("v1", props, NOW, max_age_seconds=300)["status"], "CRITICAL")

    def test_sin_ejecucion_previa_es_warning(self):
        props = service(ExecMainExitTimestampMonotonic="0")
        self.assertEqual(health.check_monitor("v1", props, NOW)["status"], "WARNING")

    def test_timer_inactivo_critico(self):
        self.assertEqual(health.check_active("v1.timer", {"ActiveState": "inactive"})["status"], "CRITICAL")

    def test_con_todo_sano_ingestion_sigue_desconocida(self):
        report = health.collect(now_monotonic_us=NOW, reader=healthy_reader, udp_reader=healthy_udp_reader)
        self.assertEqual(report["overall_status"], "HEALTHY")
        self.assertEqual(report["checks"]["log_ingestion"]["status"], "UNKNOWN")

    def test_error_de_consulta_es_unknown_no_excepcion(self):
        def reader(unit):
            if unit == "rsyslog.service":
                raise RuntimeError("dbus no disponible")
            return healthy_reader(unit)
        report = health.collect(now_monotonic_us=NOW, reader=reader, udp_reader=healthy_udp_reader)
        self.assertEqual(report["overall_status"], "UNKNOWN")

    def test_critico_prevalece_sobre_unknown(self):
        def reader(unit):
            if unit == "rsyslog.service":
                raise RuntimeError("dbus no disponible")
            if unit == "powerbeam-monitor.timer":
                return {"ActiveState": "inactive"}
            return healthy_reader(unit)
        report = health.collect(now_monotonic_us=NOW, reader=reader, udp_reader=healthy_udp_reader)
        self.assertEqual(report["overall_status"], "CRITICAL")

    def test_resultado_error_sin_codigo_de_salida_critico(self):
        props = service(Result="timeout", ExecMainStatus="0")
        self.assertEqual(health.check_monitor("v1", props, NOW)["status"], "CRITICAL")

    def test_monitor_estado_failed_critico(self):
        props = service(ActiveState="failed")
        self.assertEqual(health.check_monitor("v1", props, NOW)["status"], "CRITICAL")

    def test_udp_5514_en_ip_correcta_healthy(self):
        self.assertEqual(
            health.check_udp_listener(["192.168.1.10:5514"])["status"], "HEALTHY"
        )

    def test_udp_sin_listener_es_critical(self):
        self.assertEqual(health.check_udp_listener([])["status"], "CRITICAL")

    def test_udp_en_ip_distinta_es_critical(self):
        self.assertEqual(
            health.check_udp_listener(["127.0.0.1:5514"])["status"], "CRITICAL"
        )

    def test_udp_en_puerto_distinto_es_critical(self):
        self.assertEqual(
            health.check_udp_listener(["192.168.1.10:514"])["status"], "CRITICAL"
        )

    def test_udp_wildcard_ipv4_warning(self):
        self.assertEqual(
            health.check_udp_listener(["0.0.0.0:5514"])["status"], "WARNING"
        )

    def test_udp_wildcard_ipv6_warning(self):
        self.assertEqual(
            health.check_udp_listener(["[::]:5514"])["status"], "WARNING"
        )

    def test_udp_wildcard_prevalece_a_bind_concreto(self):
        self.assertEqual(
            health.check_udp_listener(["192.168.1.10:5514", "0.0.0.0:5514"])["status"], "WARNING"
        )

    def test_ss_solo_consulta_udp_y_extrae_endpoints(self):
        result = SimpleNamespace(returncode=0, stderr="", stdout=(
            "UNCONN 0 0 192.168.1.10:5514 0.0.0.0:*\n"
            "UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*\n"
        ))
        with patch.object(health.subprocess, "run", return_value=result) as mock_run:
            endpoints = health.read_udp_listeners()
        self.assertEqual(endpoints, ["192.168.1.10:5514", "127.0.0.1:5353"])
        self.assertEqual(mock_run.call_args.args[0], ["ss", "-H", "-lun"])

    def test_fallo_en_ss_resulta_unknown(self):
        def unavailable():
            raise RuntimeError("ss no disponible")
        report = health.collect(now_monotonic_us=NOW, reader=healthy_reader,
                                udp_reader=unavailable)
        self.assertEqual(report["checks"]["syslog_udp"]["status"], "UNKNOWN")
        self.assertEqual(report["overall_status"], "UNKNOWN")

    def test_udp_ausente_cambia_estado_general_critical_pero_no_ingestion(self):
        report = health.collect(now_monotonic_us=NOW, reader=healthy_reader,
                                udp_reader=lambda: [])
        self.assertEqual(report["checks"]["syslog_udp"]["status"], "CRITICAL")
        self.assertEqual(report["overall_status"], "CRITICAL")
        self.assertEqual(report["ingestion_status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
