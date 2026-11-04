"""Pruebas de observación syslog en directorios aislados, sin tocar logs reales."""
import gzip
import importlib.util
import pathlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "health_check.py"
spec = importlib.util.spec_from_file_location("health_phase3", SCRIPT)
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
SOURCE = "192.168.1.20"
OTHER = "192.168.1.33"
NOW = datetime(2026, 11, 4, 11, 20, tzinfo=timezone.utc)


def record(at, src=SOURCE, raw_time="Mar 28 11:11:33"):
    return (f"{at.isoformat()} source={src} <14>{raw_time} httpd[864]: "
            "Password auth succeeded for 'ubnt' from 192.168.1.10\n").encode()


class LogActivityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def write(self, suffix, payload):
        path = self.root / ("powerbeam.log" + suffix)
        path.write_bytes(payload)
        return path

    def test_reciente_se_basa_en_recepcion_no_en_reloj_antena(self):
        self.write("", record(NOW - timedelta(minutes=2)))
        result = health.check_log_activity(self.root, SOURCE, 30, now_utc=NOW)
        self.assertEqual(result["status"], "HEALTHY")
        self.assertEqual(result["age_seconds"], 120)
        self.assertIn("heartbeat", result["detail"])

    def test_antiguo_warning_no_critical(self):
        self.write("", record(NOW - timedelta(hours=2)))
        result = health.check_log_activity(self.root, SOURCE, 30, now_utc=NOW)
        self.assertEqual(result["status"], "WARNING")
        self.assertEqual(result["age_seconds"], 7200)

    def test_ip_diferente_no_es_evidencia(self):
        self.write("", record(NOW, OTHER))
        result = health.check_log_activity(self.root, SOURCE, 30, now_utc=NOW)
        self.assertEqual(result["status"], "UNKNOWN")

    def test_sin_registros_unknown(self):
        self.assertEqual(health.check_log_activity(self.root, now_utc=NOW)["status"], "UNKNOWN")

    def test_rotacion_uno_con_archivo_actual_vacio(self):
        self.write("", b"")
        self.write(".1", record(NOW - timedelta(minutes=3)))
        result = health.check_log_activity(self.root, SOURCE, 30, now_utc=NOW)
        self.assertEqual(result["status"], "HEALTHY")

    def test_historico_comprimido_con_archivos_raw_vacios(self):
        self.write("", b"")
        self.write(".1", b"")
        with gzip.open(self.root / "powerbeam.log.2.gz", "wb") as stream:
            stream.write(record(NOW - timedelta(minutes=15)))
        result = health.check_log_activity(self.root, SOURCE, 30, now_utc=NOW)
        self.assertEqual(result["status"], "HEALTHY")

    def test_symlink_rechazado_sin_leer_destino(self):
        dest = self.root / "other.txt"
        dest.write_bytes(record(NOW))
        (self.root / "powerbeam.log").symlink_to(dest)
        result = health.check_log_activity(self.root, SOURCE, 30, now_utc=NOW)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("No se pudo", result["detail"])

    def test_archivo_gzip_corrupto_sin_silenciar_error(self):
        self.write(".2.gz", b"no es un gzip")
        result = health.check_log_activity(self.root, SOURCE, 30, now_utc=NOW)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("No se pudo", result["detail"])

    def test_gzip_demasiado_grande_falla_conservadoramente(self):
        with gzip.open(self.root / "powerbeam.log.2.gz", "wb") as stream:
            stream.write(b"X" * (health.MAX_GZIP_BYTES + 1024))
        result = health.check_log_activity(self.root, SOURCE, 30, now_utc=NOW)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("límite", result["detail"])

    def test_futura_61s_unknown(self):
        self.write("", record(NOW + timedelta(minutes=2)))
        self.assertEqual(health.check_log_activity(self.root, now_utc=NOW)["status"], "UNKNOWN")

    def test_linea_incompleta_no_cuenta(self):
        self.write("", record(NOW).rstrip(b"\n"))
        self.assertEqual(health.check_log_activity(self.root, now_utc=NOW)["status"], "UNKNOWN")

    def test_permisos_denegados_devuelve_unknown(self):
        with patch.object(health, "read_last_received_timestamp", side_effect=PermissionError("sin ACL")) as fake:
            result = health.check_log_activity(self.root, now_utc=NOW, reader=fake)
        self.assertEqual(result["status"], "UNKNOWN")

    def test_collect_distingue_senal_reciente_de_ingestion_continua(self):
        def reader(unit):
            if unit == "rsyslog.service" or unit.endswith(".timer"):
                return {"ActiveState": "active"}
            return {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0",
                    "ExecMainExitTimestampMonotonic": "950000000", "ExecMainStartTimestampMonotonic": "900000000"}
        report = health.collect(
            now_monotonic_us=1000000000, wall_now=NOW, reader=reader,
            udp_reader=lambda: ["192.168.1.10:5514"], inspect_log_activity=True,
            log_dir=self.root, log_reader=lambda *args: NOW - timedelta(minutes=2),
        )
        self.assertEqual(report["checks"]["log_activity"]["status"], "HEALTHY")
        self.assertEqual(report["ingestion_status"], "UNKNOWN")
        self.assertEqual(report["overall_status"], "HEALTHY")

    def test_estado_general_no_se_degrada_por_silencio_de_antena(self):
        def reader(unit):
            if unit == "rsyslog.service" or unit.endswith(".timer"):
                return {"ActiveState": "active"}
            return {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0",
                    "ExecMainExitTimestampMonotonic": "950000000", "ExecMainStartTimestampMonotonic": "900000000"}
        report = health.collect(
            now_monotonic_us=1000000000, wall_now=NOW, reader=reader,
            udp_reader=lambda: ["192.168.1.10:5514"], inspect_log_activity=True,
            log_dir=self.root, log_reader=lambda *args: NOW - timedelta(hours=8),
        )
        self.assertEqual(report["checks"]["log_activity"]["status"], "WARNING")
        self.assertEqual(report["overall_status"], "HEALTHY")


if __name__ == "__main__":
    unittest.main()
