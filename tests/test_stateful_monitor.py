"""Pruebas del prototipo, sin conectarlo al dispositivo ni a systemd."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import stateful_monitor as monitor

SRC = "192.0.2.10"

def line(minute, kind, ip=SRC, seconds=0):
    stamp = f"2026-11-01T21:{minute:02d}:{seconds:02d}+01:00"
    if kind == "bad":
        msg = f"Bad password attempt for 'testuser' from {ip}"
    elif kind == "unknown":
        msg = f"Login attempt for nonexistent user from {ip}"
    else:
        msg = f"Password auth succeeded for 'testuser' from {ip}"
    return f"{stamp} source=192.0.2.20 httpd[100]: {msg}\n"

class StateMonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.file = self.logs / "powerbeam.log"
        self.file.write_text("", encoding="utf-8")
        self.state = self.root / "private" / "state.json"
        self.alerts = self.root / "private" / "alerts.jsonl"

    def write(self, *lines):
        with self.file.open("a", encoding="utf-8") as handle:
            handle.writelines(lines)

    def read_alerts(self):
        if not self.alerts.exists():
            return []
        return [json.loads(line) for line in self.alerts.read_text().splitlines()]

    def test_soc002_cruza_dos_ejecuciones(self):
        self.write(line(0, "bad"), line(1, "unknown"))
        self.assertEqual(monitor.run_once(self.logs, self.state, self.alerts)["soc002"], 0)
        self.write(line(2, "ok"))
        output = monitor.run_once(self.logs, self.state, self.alerts)
        self.assertEqual((output["lines"], output["soc002"], output["written"]), (1, 1, 1))
        self.assertEqual(self.read_alerts()[0]["failed_attempts"], 2)

    def test_reanalisis_no_duplica_ni_relee(self):
        self.write(line(0, "bad"), line(1, "unknown"), line(2, "ok"))
        self.assertEqual(monitor.run_once(self.logs, self.state, self.alerts)["written"], 1)
        self.assertEqual(monitor.run_once(self.logs, self.state, self.alerts)["lines"], 0)
        self.assertEqual(len(self.read_alerts()), 1)

    def test_soc001_cinco_fallos_entre_ejecuciones(self):
        self.write(*[line(m, "bad") for m in range(4)])
        self.assertEqual(monitor.run_once(self.logs, self.state, self.alerts)["soc001"], 0)
        self.write(line(4, "bad"))
        out = monitor.run_once(self.logs, self.state, self.alerts)
        self.assertEqual(out["soc001"], 1)
        self.assertEqual(self.read_alerts()[0]["rule_id"], "SOC-001")

    def test_cinco_minutos_se_respetan_entre_lotes(self):
        self.write(line(0, "bad"), line(1, "unknown"))
        monitor.run_once(self.logs, self.state, self.alerts)
        self.write(line(7, "ok"))
        self.assertEqual(monitor.run_once(self.logs, self.state, self.alerts)["soc002"], 0)

    def test_ips_distintas_no_se_correlacionan_entre_lotes(self):
        self.write(line(0, "bad"), line(1, "bad"))
        monitor.run_once(self.logs, self.state, self.alerts)
        self.write(line(2, "ok", "192.0.2.11"))
        self.assertEqual(monitor.run_once(self.logs, self.state, self.alerts)["soc002"], 0)

    def test_rotacion_rename_create(self):
        self.write(line(0, "bad"))
        monitor.run_once(self.logs, self.state, self.alerts)
        self.file.rename(self.logs / "powerbeam.log.1")
        self.file.write_text(line(1, "unknown") + line(2, "ok"), encoding="utf-8")
        out = monitor.run_once(self.logs, self.state, self.alerts)
        self.assertEqual((out["lines"], out["soc002"]), (2, 1))

    def test_linea_incompleta_no_avanza(self):
        pending = line(0, "bad")
        with self.file.open("a", encoding="utf-8") as handle:
            handle.write(pending[:-1])
        self.assertEqual(monitor.run_once(self.logs, self.state, self.alerts)["lines"], 0)
        with self.file.open("a", encoding="utf-8") as handle:
            handle.write("\n")
        self.assertEqual(monitor.run_once(self.logs, self.state, self.alerts)["lines"], 1)

    def test_checkpoint_corrupto_no_se_reinicia(self):
        self.state.parent.mkdir()
        self.state.write_text("{rota", encoding="utf-8")
        self.write(line(0, "bad"))
        with self.assertRaises(ValueError):
            monitor.run_once(self.logs, self.state, self.alerts)
        self.assertEqual(self.state.read_text(encoding="utf-8"), "{rota")

    def test_reintento_tras_fallo_de_checkpoint_no_duplica_alerta(self):
        self.write(line(0, "bad"), line(1, "unknown"), line(2, "ok"))
        original = monitor.save_checkpoint
        with patch.object(monitor, "save_checkpoint", side_effect=OSError("Disco falló")):
            with self.assertRaises(OSError):
                monitor.run_once(self.logs, self.state, self.alerts)
        self.assertEqual(len(self.read_alerts()), 1)
        self.assertFalse(self.state.exists())
        with patch.object(monitor, "save_checkpoint", side_effect=original):
            out = monitor.run_once(self.logs, self.state, self.alerts)
        self.assertEqual(out["written"], 0)
        self.assertEqual(len(self.read_alerts()), 1)
        self.assertEqual(monitor.run_once(self.logs, self.state, self.alerts)["lines"], 0)

    def test_con_gzip_se_detiene_para_no_perder_eventos(self):
        (self.logs / "powerbeam.log.1.gz").write_bytes(b"cualquiera")
        with self.assertRaisesRegex(ValueError, "NO procesa"):
            monitor.run_once(self.logs, self.state, self.alerts)
        self.assertFalse(self.state.exists())

    def test_evento_tardio_se_rechaza_y_no_avanza_cursor(self):
        self.write(line(2, "bad"))
        monitor.run_once(self.logs, self.state, self.alerts)
        first = self.state.read_text(encoding="utf-8")
        self.write(line(1, "unknown"))
        with self.assertRaisesRegex(ValueError, "eventos anteriores"):
            monitor.run_once(self.logs, self.state, self.alerts)
        self.assertEqual(self.state.read_text(encoding="utf-8"), first)

    def test_permiso_estado_y_alertas_600(self):
        self.write(line(0, "bad"), line(1, "unknown"), line(2, "ok"))
        monitor.run_once(self.logs, self.state, self.alerts)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.alerts.stat().st_mode & 0o777, 0o600)

if __name__ == "__main__":
    unittest.main()
