"""Pruebas offline del monitor integrado. Sin red ni dispositivo físico."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from security_monitor import analyze, append_unique  # noqa: E402


def event(seconds, message, ip="192.0.2.10"):
    return (
        f"2026-10-30T12:{seconds}+01:00 source=192.0.2.20 "
        f"<14>Oct 30 11:22:17 httpd[1234]: {message} from {ip}\n"
    )


BAD = "Bad password attempt for 'testuser'"
UNKNOWN = "Login attempt for nonexistent user"
OK = "Password auth succeeded for 'testuser'"


class MonitorTests(unittest.TestCase):
    def test_soc002_reproduce_secuencia_real(self):
        alerts, counts = analyze([event("22:17", UNKNOWN), event("22:35", BAD), event("22:45", OK)])
        self.assertEqual([a["rule_id"] for a in alerts], ["SOC-002"])
        self.assertEqual(counts["auth_events"], 3)
        self.assertEqual(alerts[0]["failed_attempts"], 2)

    def test_soc001_cinco_fallos_sin_exito(self):
        alerts, counts = analyze([event(f"0{i}:00", BAD) for i in range(5)])
        self.assertEqual([a["rule_id"] for a in alerts], ["SOC-001"])
        self.assertEqual(counts["SOC-002"], 0)

    def test_ambas_reglas_en_mismo_lote(self):
        logs = [event(f"0{i}:00", BAD) for i in range(5)] + [event("04:30", OK)]
        alerts, counts = analyze(logs)
        self.assertEqual({a["rule_id"] for a in alerts}, {"SOC-001", "SOC-002"})
        self.assertEqual(counts["successful"], 1)

    def test_un_fallo_y_exito_no_alertan(self):
        alerts, counts = analyze([event("00:00", BAD), event("00:20", OK)])
        self.assertEqual(alerts, [])
        self.assertEqual(counts["auth_events"], 2)

    def test_eventos_ajenos_sin_alerta(self):
        alerts, counts = analyze(["linea desconocida\n"])
        self.assertEqual(alerts, [])
        self.assertEqual(counts["lines_read"], 1)
        self.assertEqual(counts["auth_events"], 0)

    def test_alertas_ordenadas_y_ids_estables(self):
        lines = [event("22:45", OK), event("22:17", UNKNOWN), event("22:35", BAD)]
        alerts, _ = analyze(lines)
        backwards, _ = analyze(list(reversed(lines)))
        self.assertEqual(alerts, backwards)
        self.assertTrue(alerts[0]["alert_id"].startswith("SOC-002-"))

    def test_deduplicacion_jsonl_y_permiso_archivo(self):
        alerts, _ = analyze([event("22:17", UNKNOWN), event("22:35", BAD), event("22:45", OK)])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "alerts" / "alerts.jsonl"
            self.assertEqual(append_unique(alerts, out), 1)
            self.assertEqual(append_unique(alerts, out), 0)
            rows = [json.loads(line) for line in out.read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_ip"], "192.0.2.10")
            if os.name == "posix":
                self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_jsonl_corrupto_falla_sin_sobrescribir(self):
        alerts, _ = analyze([event("22:17", UNKNOWN), event("22:35", BAD), event("22:45", OK)])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "alerts.jsonl"
            out.write_text("{INVALID JSON\n")
            with self.assertRaises(ValueError):
                append_unique(alerts, out)
            self.assertEqual(out.read_text(), "{INVALID JSON\n")


if __name__ == "__main__":
    unittest.main()
