"""Pruebas de HEALTH-006 con ping simulado: nunca contactan la antena."""
import importlib.util
import pathlib
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "health_check.py"
spec = importlib.util.spec_from_file_location("health_health006", SCRIPT)
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
NOW = 1_000_000_000


def ping_result(received=2, rc=0, transmitted=2, stderr=""):
    return SimpleNamespace(
        returncode=rc, stderr=stderr,
        stdout=f"PING 192.168.1.20 (192.168.1.20) 56(84) bytes of data.\n"
               f"--- 192.168.1.20 ping statistics ---\n"
               f"{transmitted} packets transmitted, {received} received, "
               f"{round((transmitted - received) / transmitted * 100):.0f}% packet loss, time 1000ms\n",
    )


def healthy_reader(unit):
    if unit == "rsyslog.service" or unit.endswith(".timer"):
        return {"ActiveState": "active"}
    return {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0",
            "ExecMainExitTimestampMonotonic": "950000000",
            "ExecMainStartTimestampMonotonic": "900000000"}


class AntennaICMPTests(unittest.TestCase):
    def test_ping_dos_de_dos_healthy(self):
        with patch.object(health.subprocess, "run", return_value=ping_result()):
            result = health.check_antenna_icmp()
        self.assertEqual(result["status"], "HEALTHY")
        self.assertEqual(result["packets_received"], 2)
        self.assertEqual(result["packet_loss_percent"], 0)
        self.assertIn("no confirma syslog", result["detail"])

    def test_ping_uno_de_dos_warning(self):
        with patch.object(health.subprocess, "run", return_value=ping_result(1, 0)):
            result = health.check_antenna_icmp()
        self.assertEqual(result["status"], "WARNING")
        self.assertEqual(result["packet_loss_percent"], 50)

    def test_ping_cero_de_dos_warning_no_critical(self):
        with patch.object(health.subprocess, "run", return_value=ping_result(0, 1)):
            result = health.check_antenna_icmp()
        self.assertEqual(result["status"], "WARNING")
        self.assertIn("bloquear", result["detail"])

    def test_ping_error_del_ejecutable_es_unknown(self):
        with patch.object(health.subprocess, "run", return_value=ping_result(0, 2)):
            self.assertEqual(health.check_antenna_icmp()["status"], "UNKNOWN")

    def test_ping_no_disponible_es_unknown(self):
        with patch.object(health.subprocess, "run", side_effect=FileNotFoundError("no existe ping")):
            result = health.check_antenna_icmp()
        self.assertEqual(result["status"], "UNKNOWN")

    def test_ping_timeout_es_unknown(self):
        with patch.object(health.subprocess, "run", side_effect=subprocess.TimeoutExpired(["ping"], 8)):
            self.assertEqual(health.check_antenna_icmp()["status"], "UNKNOWN")

    def test_ping_resultado_sin_estadisticas_es_unknown(self):
        with patch.object(health.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="ping ...", stderr="")):
            self.assertEqual(health.check_antenna_icmp()["status"], "UNKNOWN")

    def test_ping_resultado_incoherente_es_unknown(self):
        with patch.object(health.subprocess, "run", return_value=ping_result(3, 0)):
            self.assertEqual(health.check_antenna_icmp()["status"], "UNKNOWN")

    def test_ping_direccion_invalida_nunca_llama_ejecutable(self):
        with patch.object(health.subprocess, "run") as fake:
            result = health.check_antenna_icmp("--no-me-busques")
        self.assertEqual(result["status"], "UNKNOWN")
        fake.assert_not_called()

    def test_ping_sin_shell_dos_paquetes_timeout_y_lenguaje_estable(self):
        with patch.object(health.subprocess, "run", return_value=ping_result()) as fake:
            health.check_antenna_icmp("192.168.1.20")
        command = fake.call_args.args[0]
        kwargs = fake.call_args.kwargs
        self.assertEqual(command, ["ping", "-n", "-c", "2", "-W", "2", "-w", "6", "192.168.1.20"])
        self.assertEqual(kwargs["timeout"], 8)
        self.assertEqual(kwargs["env"]["LC_ALL"], "C")
        self.assertNotIn("shell", kwargs)

    def test_collect_por_defecto_no_hace_ping(self):
        fake = Mock(side_effect=AssertionError("ping no debe ejecutarse"))
        report = health.collect(now_monotonic_us=NOW, reader=healthy_reader,
                                udp_reader=lambda: ["192.168.1.10:5514"], icmp_reader=fake)
        fake.assert_not_called()
        self.assertEqual(report["connectivity_status"], "UNKNOWN")
        self.assertEqual(report["overall_status"], "HEALTHY")

    def test_collect_icmp_healthy_no_equivale_a_ingestion(self):
        fake = Mock(return_value=health.item("HEALTHY", "dos respuestas"))
        report = health.collect(now_monotonic_us=NOW, reader=healthy_reader,
                                udp_reader=lambda: ["192.168.1.10:5514"], check_antenna=True,
                                icmp_reader=fake)
        fake.assert_called_once_with("192.168.1.20")
        self.assertEqual(report["connectivity_status"], "HEALTHY")
        self.assertEqual(report["ingestion_status"], "UNKNOWN")
        self.assertEqual(report["overall_status"], "HEALTHY")

    def test_collect_icmp_warning_no_critica_infraestructura(self):
        report = health.collect(now_monotonic_us=NOW, reader=healthy_reader,
                                udp_reader=lambda: ["192.168.1.10:5514"], check_antenna=True,
                                icmp_reader=lambda _: health.item("WARNING", "sin respuesta"))
        self.assertEqual(report["checks"]["antenna_icmp"]["status"], "WARNING")
        self.assertEqual(report["overall_status"], "HEALTHY")
        self.assertEqual(report["ingestion_status"], "UNKNOWN")

    def test_collect_icmp_error_desconocido_no_mata_el_supervisor(self):
        def impossible(_):
            raise RuntimeError("sin permiso para ping")
        report = health.collect(now_monotonic_us=NOW, reader=healthy_reader,
                                udp_reader=lambda: ["192.168.1.10:5514"], check_antenna=True,
                                icmp_reader=impossible)
        self.assertEqual(report["connectivity_status"], "UNKNOWN")
        self.assertEqual(report["overall_status"], "HEALTHY")

    def test_critical_infraestructura_prevalece_a_ping_positivo(self):
        report = health.collect(now_monotonic_us=NOW, reader=healthy_reader,
                                udp_reader=lambda: [], check_antenna=True,
                                icmp_reader=lambda _: health.item("HEALTHY", "responde"))
        self.assertEqual(report["connectivity_status"], "HEALTHY")
        self.assertEqual(report["overall_status"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
