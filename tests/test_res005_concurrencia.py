"""RES-005: bloqueo de checkpoint con procesos independientes (v3 experimental)."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
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


class ConcurrencyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.log = self.logs / "powerbeam.log"
        self.state = self.root / "state-v3.json"
        self.alerts = self.root / "alerts-v3.jsonl"

    def command(self):
        return [sys.executable, str(SCRIPT),
                "--log-dir", str(self.logs),
                "--state", str(self.state),
                "--output", str(self.alerts)]

    def launch(self):
        return subprocess.run(self.command(), capture_output=True,
                              text=True, timeout=10, cwd=ROOT)

    def test_bloqueo_externo_impide_crear_checkpoint_y_liberacion_reanuda(self):
        self.log.write_text(event(0, "bad"), encoding="utf-8")
        fd = os.open(str(self.state) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            blocked = self.launch()
            self.assertEqual(blocked.returncode, 1, blocked.stderr)
            self.assertIn("Ya hay otra ejecución", blocked.stderr)
            self.assertFalse(self.state.exists())
            self.assertFalse(self.alerts.exists())
        finally:
            os.close(fd)
        retried = self.launch()
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertIn("Líneas nuevas: 1", retried.stdout)
        self.assertTrue(self.state.exists())

    def test_checkpoint_existente_no_cambia_bajo_bloqueo(self):
        self.log.write_text(event(0, "bad"), encoding="utf-8")
        first = self.launch()
        self.assertEqual(first.returncode, 0, first.stderr)
        original = self.state.read_bytes()
        with self.log.open("a", encoding="utf-8") as out:
            out.write(event(1, "unknown") + event(2, "ok"))
        fd = os.open(str(self.state) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            blocked = self.launch()
            self.assertEqual(blocked.returncode, 1, blocked.stderr)
            self.assertEqual(self.state.read_bytes(), original)
            self.assertFalse(self.alerts.exists())
        finally:
            os.close(fd)
        retry = self.launch()
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertIn("Alertas SOC-002: 1", retry.stdout)
        saved = [json.loads(row) for row in self.alerts.read_text().splitlines()]
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["rule_id"], "SOC-002")

    def test_dos_monitores_reales_no_usan_checkpoint_simultaneamente(self):
        self.log.write_text(event(0, "bad"), encoding="utf-8")
        marker = self.root / "primero-tiene-lock"
        release = self.root / "liberar-primero"
        # Pausamos el primer monitor *después* de adquirir su bloqueo.
        code = ("import pathlib,sys,time\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "import stateful_monitor_v3 as monitor\n"
                "snapshot_original = monitor.snapshot\n"
                "def snapshot_lento(*args, **kwargs):\n"
                "    pathlib.Path(sys.argv[2]).write_text('ready')\n"
                "    end = time.monotonic() + 8\n"
                "    while not pathlib.Path(sys.argv[3]).exists():\n"
                "        if time.monotonic() > end: raise RuntimeError('timeout de prueba')\n"
                "        time.sleep(0.02)\n"
                "    return snapshot_original(*args, **kwargs)\n"
                "monitor.snapshot = snapshot_lento\n"
                "monitor.run_once(sys.argv[4],sys.argv[5],sys.argv[6])\n")
        worker = subprocess.Popen([sys.executable, "-c", code,
                                   str(ROOT / "scripts"), str(marker), str(release),
                                   str(self.logs), str(self.state), str(self.alerts)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, cwd=ROOT)
        try:
            deadline = time.monotonic() + 6
            while not marker.exists() and time.monotonic() < deadline:
                if worker.poll() is not None:
                    break
                time.sleep(0.02)
            self.assertTrue(marker.exists(), "El primer monitor no adquirió el bloqueo")
            second = self.launch()
            self.assertEqual(second.returncode, 1, second.stderr)
            self.assertIn("Ya hay otra ejecución", second.stderr)
            self.assertFalse(self.state.exists())
            release.touch()
            _, stderr = worker.communicate(timeout=8)
            self.assertEqual(worker.returncode, 0, stderr)
            self.assertTrue(self.state.exists())
            again = self.launch()
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertIn("Líneas nuevas: 0", again.stdout)
        finally:
            release.touch()
            if worker.poll() is None:
                worker.kill()
                worker.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
