"""RES-006: contexto y deduplicación conservados entre procesos v3 separados."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "stateful_monitor_v3.py"


def event(minute, kind):
    message = {
        "bad": "Bad password attempt for 'testuser' from 192.0.2.10",
        "unknown": "Login attempt for nonexistent user from 192.0.2.10",
        "ok": "Password auth succeeded for 'testuser' from 192.0.2.10",
    }[kind]
    return (f"2026-11-03T12:{minute:02d}:00+01:00 source=192.0.2.20 "
            f"httpd[100]: {message}\n")


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.log = self.logs / "powerbeam.log"
        self.state = self.root / "state-v3.json"
        self.alerts = self.root / "alerts-v3.jsonl"

    def run_cli(self, state=None, output=None):
        return subprocess.run([sys.executable, str(SCRIPT),
                               "--log-dir", str(self.logs),
                               "--state", str(state or self.state),
                               "--output", str(output or self.alerts)],
                              capture_output=True, text=True, timeout=10, cwd=ROOT)

    def append(self, *rows):
        with self.log.open("a", encoding="utf-8") as out:
            out.writelines(rows)

    def test_correlacion_entre_tres_procesos_y_sin_duplicados(self):
        self.append(event(0, "bad"))
        first = self.run_cli()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("Líneas nuevas: 1", first.stdout)
        self.assertFalse(self.alerts.exists())
        self.append(event(1, "unknown"))
        second = self.run_cli()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("Alertas SOC-002: 0", second.stdout)
        self.append(event(2, "ok"))
        third = self.run_cli()
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertIn("Líneas nuevas: 1", third.stdout)
        self.assertIn("Alertas SOC-002: 1", third.stdout)
        alerts_before = self.alerts.read_bytes()
        saved = [json.loads(row) for row in alerts_before.decode().splitlines()]
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["failed_attempts"], 2)
        self.assertEqual(saved[0]["source_ip"], "192.0.2.10")
        fourth = self.run_cli()
        self.assertEqual(fourth.returncode, 0, fourth.stderr)
        self.assertIn("Líneas nuevas: 0", fourth.stdout)
        self.assertIn("Alertas JSONL nuevas: 0", fourth.stdout)
        self.assertEqual(self.alerts.read_bytes(), alerts_before)

    def test_checkpoint_persiste_despues_de_finalizar_proceso(self):
        self.append(event(0, "bad"))
        self.assertEqual(self.run_cli().returncode, 0)
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(saved["version"], 3)
        self.assertEqual(saved["soc002_failures"]["192.0.2.10"],
                         ["2026-11-03T12:00:00+01:00"])
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o600)
        no_new = self.run_cli()
        self.assertEqual(no_new.returncode, 0, no_new.stderr)
        self.assertIn("Líneas nuevas: 0", no_new.stdout)
        self.assertEqual(json.loads(self.state.read_text())["soc002_failures"],
                         saved["soc002_failures"])

    def test_checkpoint_nuevo_no_hereda_contexto_de_otro(self):
        self.append(event(0, "bad"), event(1, "unknown"))
        self.assertEqual(self.run_cli().returncode, 0)
        # Usamos otro directorio con solo éxito y estado nuevo: no debe heredar fallos.
        other_logs = self.root / "otros_logs"
        other_logs.mkdir()
        (other_logs / "powerbeam.log").write_text(event(2, "ok"))
        other_state = self.root / "otro_estado-v3.json"
        other_alerts = self.root / "otras_alertas-v3.jsonl"
        only_success = subprocess.run([sys.executable, str(SCRIPT),
                                       "--log-dir", str(other_logs),
                                       "--state", str(other_state),
                                       "--output", str(other_alerts)],
                                      capture_output=True, text=True,
                                      timeout=10, cwd=ROOT)
        self.assertEqual(only_success.returncode, 0, only_success.stderr)
        self.assertIn("Alertas SOC-002: 0", only_success.stdout)
        self.assertFalse(other_alerts.exists())
        self.assertNotEqual(json.loads(other_state.read_text())["cursors"],
                            json.loads(self.state.read_text())["cursors"])


if __name__ == "__main__":
    unittest.main()
