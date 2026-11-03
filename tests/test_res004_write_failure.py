"""RES-004: inyección controlada de fallos de escritura (v3, sin root/systemd)."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import stateful_monitor_v3 as monitor


def evento(minuto, tipo):
    mensaje = {
        "bad": "Bad password attempt for 'testuser' from 192.0.2.10",
        "unknown": "Login attempt for nonexistent user from 192.0.2.10",
        "ok": "Password auth succeeded for 'testuser' from 192.0.2.10",
    }[tipo]
    return (f"2026-11-03T11:{minuto:02d}:00+01:00 source=192.0.2.20 "
            f"httpd[100]: {mensaje}\n")


class WriteFailureTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.logs = base / "logs"
        self.logs.mkdir()
        self.log = self.logs / "powerbeam.log"
        self.state = base / "state-v3.json"
        self.alerts = base / "alerts-v3.jsonl"

    def run_monitor(self):
        return monitor.run_once(self.logs, self.state, self.alerts)

    def append(self, *rows):
        with self.log.open("a", encoding="utf-8") as handle:
            handle.writelines(rows)

    def read_alerts(self):
        if not self.alerts.exists():
            return []
        return [json.loads(line) for line in self.alerts.read_text(encoding="utf-8").splitlines()]

    def test_fallo_checkpoint_despues_de_alerta_no_duplica(self):
        self.append(evento(0, "bad"), evento(1, "unknown"), evento(2, "ok"))
        with patch.object(monitor, "save_checkpoint", side_effect=OSError("RES-004 simulado: sin espacio")):
            with self.assertRaisesRegex(OSError, "RES-004 simulado"):
                self.run_monitor()
        self.assertFalse(self.state.exists())
        original = self.read_alerts()
        self.assertEqual(len(original), 1)
        self.assertEqual(original[0]["rule_id"], "SOC-002")
        retry = self.run_monitor()
        self.assertEqual((retry["lines"], retry["soc002"], retry["written"]), (3, 1, 0))
        self.assertEqual(self.read_alerts(), original)
        self.assertEqual(self.run_monitor()["lines"], 0)

    def test_checkpoint_anterior_intacto_si_falla_actualizacion(self):
        self.append(evento(0, "bad"))
        self.assertEqual(self.run_monitor()["lines"], 1)
        before = self.state.read_bytes()
        self.append(evento(1, "unknown"), evento(2, "ok"))
        with patch.object(monitor, "save_checkpoint", side_effect=OSError("RES-004 fallo checkpoint")):
            with self.assertRaisesRegex(OSError, "RES-004 fallo checkpoint"):
                self.run_monitor()
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(len(self.read_alerts()), 1)
        retry = self.run_monitor()
        self.assertEqual((retry["lines"], retry["soc002"], retry["written"]), (2, 1, 0))
        self.assertNotEqual(self.state.read_bytes(), before)
        self.assertEqual(len(self.read_alerts()), 1)

    def test_fallo_escritura_alerta_no_avanza_checkpoint(self):
        self.append(evento(0, "bad"))
        self.run_monitor()
        before = self.state.read_bytes()
        self.append(evento(1, "unknown"), evento(2, "ok"))
        with patch.object(monitor, "append_unique", side_effect=OSError("RES-004 error JSONL")):
            with self.assertRaisesRegex(OSError, "RES-004 error JSONL"):
                self.run_monitor()
        self.assertEqual(self.state.read_bytes(), before)
        self.assertFalse(self.alerts.exists())
        retry = self.run_monitor()
        self.assertEqual((retry["lines"], retry["soc002"], retry["written"]), (2, 1, 1))

    def test_jsonl_corrupto_no_avanza_ni_sobrescribe(self):
        self.append(evento(0, "bad"))
        self.run_monitor()
        before = self.state.read_bytes()
        self.alerts.write_text('{"alert_id":', encoding="utf-8")
        self.append(evento(1, "unknown"), evento(2, "ok"))
        with self.assertRaisesRegex(ValueError, "JSONL inválido"):
            self.run_monitor()
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(self.alerts.read_text(encoding="utf-8"), '{"alert_id":')

    def test_fallo_sincronizacion_despues_de_append_reintenta(self):
        self.append(evento(0, "bad"), evento(1, "unknown"), evento(2, "ok"))
        with patch.object(monitor, "sync_directory", side_effect=OSError("RES-004 sync simulado")):
            with self.assertRaisesRegex(OSError, "RES-004 sync simulado"):
                self.run_monitor()
        self.assertFalse(self.state.exists())
        self.assertEqual(len(self.read_alerts()), 1)
        retry = self.run_monitor()
        self.assertEqual((retry["lines"], retry["written"]), (3, 0))
        self.assertEqual(len(self.read_alerts()), 1)


if __name__ == "__main__":
    unittest.main()
