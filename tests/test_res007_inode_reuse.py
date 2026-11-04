"""RES-007: regresiones ante reciclaje de inodos y logrotate delaycompress."""
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import stateful_monitor_v3 as monitor


def event(minute, kind):
    msg = {
        "bad": "Bad password attempt for 'ubnt' from 192.0.2.10",
        "unknown": "Login attempt for nonexistent user from 192.0.2.10",
        "ok": "Password auth succeeded for 'ubnt' from 192.0.2.10",
    }[kind]
    return (f"2026-11-03T11:{minute:02d}:00+01:00 source=192.0.2.20 "
            f"httpd[100]: {msg}\n").encode()


class InodeReuseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.logdir = self.root / "logs"
        self.logdir.mkdir()
        self.live = self.logdir / "powerbeam.log"
        self.state = self.root / "state.json"
        self.output = self.root / "alerts.jsonl"

    def run_monitor(self):
        return monitor.run_once(self.logdir, self.state, self.output)

    def simulate_recycled_inode(self, add_gzip=True, live_content=b""):
        """Fija dev:ino del raw NUEVO como cursor de un raw ANTIGUO.

        No depende de que el kernel recicle casualmente el inodo.
        """
        old_content = event(0, "bad")
        self.live.write_bytes(live_content)
        st = self.live.stat()
        ident = f"{st.st_dev}:{st.st_ino}"
        state = monitor.blank_state()
        state["cursors"] = {ident: len(old_content)}
        state["raw_prefixes"] = {
            ident: {"offset": len(old_content),
                    "sha256": hashlib.sha256(old_content).hexdigest()}
        }
        state["soc001_failures"] = {"192.0.2.10": ["2026-11-03T11:00:00+01:00"]}
        state["soc002_failures"] = {"192.0.2.10": ["2026-11-03T11:00:00+01:00"]}
        state["last_event_timestamp"] = "2026-11-03T11:00:00+01:00"
        monitor.save_checkpoint(self.state, state)
        if add_gzip:
            with gzip.open(self.logdir / "powerbeam.log.2.gz", "wb") as fd:
                fd.write(old_content)
        return ident

    def test_inodo_reutilizado_con_gzip_y_raw_vacio_no_duplica(self):
        ident = self.simulate_recycled_inode()
        result = self.run_monitor()
        self.assertEqual((result["lines"], result["written"]), (0, 0))
        saved = monitor.read_checkpoint(self.state)
        self.assertEqual(saved["cursors"][ident], 0)
        self.assertEqual(len(saved["gzip_seen"]), 1)
        self.assertEqual(self.run_monitor()["lines"], 0)

    def test_inodo_reutilizado_con_nuevos_eventos_preserva_soc002(self):
        self.simulate_recycled_inode(live_content=event(1, "unknown") + event(2, "ok"))
        result = self.run_monitor()
        self.assertEqual((result["lines"], result["soc002"], result["written"]), (2, 1, 1))
        self.assertEqual(self.run_monitor()["lines"], 0)
        alerts = [json.loads(x) for x in self.output.read_text().splitlines()]
        self.assertEqual((len(alerts), alerts[0]["failed_attempts"]), (1, 2))

    def test_inodo_reutilizado_sin_historico_falla_cerrado(self):
        self.simulate_recycled_inode(add_gzip=False)
        before = self.state.read_bytes()
        with self.assertRaisesRegex(ValueError, "inodo reutilizado sin histórico verificable"):
            self.run_monitor()
        self.assertEqual(self.state.read_bytes(), before)
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(shutil.which("logrotate"), "logrotate no disponible")
    def test_dos_rotaciones_reales_logrotate_delaycompress(self):
        self.live.write_bytes(event(0, "bad"))
        self.assertEqual(self.run_monitor()["lines"], 1)
        config = self.root / "logrotate.conf"
        config.write_text(f"""{self.live} {{
    daily
    rotate 14
    maxsize 10M
    missingok
    notifempty
    compress
    delaycompress
    create 0640
}}
""")
        status = self.root / "logrotate.status"
        def rotate():
            subprocess.run([shutil.which("logrotate"), "-f", "-s", str(status), str(config)],
                           check=True, capture_output=True, text=True)
        rotate()
        self.live.write_bytes(event(1, "unknown") + event(2, "ok"))
        result = self.run_monitor()
        self.assertEqual((result["lines"], result["soc002"], result["written"]), (2, 1, 1))
        rotate()
        self.assertTrue((self.logdir / "powerbeam.log.2.gz").exists())
        self.assertEqual(self.run_monitor()["lines"], 0)
        self.assertEqual(self.run_monitor()["written"], 0)
        self.assertEqual(len(self.output.read_text().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
