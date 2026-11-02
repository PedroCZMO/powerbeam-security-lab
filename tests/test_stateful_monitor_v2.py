"""Pruebas de la fase 3 con históricos .gz sintéticos y checkpoint nuevo."""
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import stateful_monitor_v2 as monitor


def event(minute, kind="bad", ip="192.0.2.10"):
    msg = {
        "bad": f"Bad password attempt for 'testuser' from {ip}",
        "unknown": f"Login attempt for nonexistent user from {ip}",
        "ok": f"Password auth succeeded for 'testuser' from {ip}",
    }[kind]
    return f"2026-11-01T21:{minute:02d}:00+01:00 source=192.0.2.20 httpd[100]: {msg}\n"


class GzipMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.active = self.logs / "powerbeam.log"
        self.active.write_text("", encoding="utf-8")
        self.state = self.root / "private" / "state-v2.json"
        self.alerts = self.root / "private" / "alerts-v2.jsonl"

    def run_monitor(self):
        return monitor.run_once(self.logs, self.state, self.alerts)

    def archive(self, name, content):
        path = self.logs / name
        with gzip.open(path, "wb") as fd:
            fd.write(content.encode())
        return path

    def alerts_json(self):
        if not self.alerts.exists():
            return []
        return [json.loads(s) for s in self.alerts.read_text().splitlines()]

    def test_lectura_inicial_gzip_raw_y_deduplicacion(self):
        self.archive("powerbeam.log.2.gz", event(0,"bad"))
        (self.logs/"powerbeam.log.1").write_text(event(1, "unknown"))
        self.active.write_text(event(2, "ok"))
        first = self.run_monitor()
        self.assertEqual((first["lines"], first["soc002"], first["written"]), (3, 1, 1))
        self.assertEqual((self.run_monitor()["lines"], len(self.alerts_json())), (0, 1))

    def test_gzip_posterior_a_raw_ya_consumido_no_duplica(self):
        self.active.write_text(event(0, "bad"))
        self.assertEqual(self.run_monitor()["lines"], 1)
        self.active.rename(self.logs / "powerbeam.log.1")
        self.active.write_text(event(1,"unknown"))
        self.assertEqual(self.run_monitor()["lines"], 1)
        text = (self.logs / "powerbeam.log.1").read_text()
        (self.logs / "powerbeam.log.1").unlink()
        self.archive("powerbeam.log.2.gz", text)
        result = self.run_monitor()
        self.assertEqual((result["lines"], result["written"]), (0, 0))

    def test_gzip_con_eventos_pendientes_tras_consumo_parcial(self):
        self.active.write_text(event(0,"bad"))
        self.run_monitor()
        rotated = self.logs/"powerbeam.log.1"
        self.active.rename(rotated)
        with rotated.open("a") as out:
            out.write(event(1,"unknown"))
        # logrotate crea el nuevo archivo antes de comprimir/borrar el viejo.
        self.active.write_text(event(2,"ok"))
        content = rotated.read_text()
        self.archive("powerbeam.log.2.gz", content)
        rotated.unlink()
        result = self.run_monitor()
        self.assertEqual((result["lines"], result["soc002"], result["written"]), (2,1,1))

    def test_rename_de_archivo_gzip_no_relee(self):
        archived = self.archive("powerbeam.log.2.gz", event(0,"bad"))
        self.assertEqual(self.run_monitor()["lines"], 1)
        archived.rename(self.logs/"powerbeam.log.3.gz")
        self.assertEqual(self.run_monitor()["lines"], 0)

    def test_gzip_corrupto_falla_sin_checkpoint(self):
        (self.logs / "powerbeam.log.2.gz").write_bytes(b"gzip invalid")
        with self.assertRaises((OSError, EOFError)):
            self.run_monitor()
        self.assertFalse(self.state.exists())

    def test_gzip_linea_parcial_falla_cerrado(self):
        self.archive("powerbeam.log.2.gz", event(0,"bad")[:-1])
        with self.assertRaisesRegex(ValueError, "incompleta"):
            self.run_monitor()
        self.assertFalse(self.state.exists())

    def test_truncado_raw_falla_sin_perder_estado(self):
        self.active.write_text(event(0,"bad"))
        self.run_monitor()
        before = self.state.read_bytes()
        self.active.write_text("nueva\n")
        with self.assertRaisesRegex(ValueError, "Truncado"):
            self.run_monitor()
        self.assertEqual(self.state.read_bytes(), before)

    def test_contenido_raw_modificado_falla(self):
        self.active.write_text(event(0,"bad"))
        self.run_monitor()
        before = self.state.read_bytes()
        changed = event(0,"ok")
        self.active.write_text(changed)
        with self.assertRaisesRegex(ValueError, "contenido ya leído"):
            self.run_monitor()
        self.assertEqual(before, self.state.read_bytes())

    def test_estado_v1_no_se_acepta(self):
        self.state.parent.mkdir()
        self.state.write_text(json.dumps({"version": 1}))
        with self.assertRaisesRegex(ValueError,"versión"):
            self.run_monitor()

    def test_gzip_llegado_tarde_detiene_proceso(self):
        self.active.write_text(event(2,"bad"))
        self.run_monitor()
        before = self.state.read_bytes()
        self.archive("powerbeam.log.3.gz", event(0,"unknown"))
        with self.assertRaisesRegex(ValueError,"anteriores"):
            self.run_monitor()
        self.assertEqual(before, self.state.read_bytes())

    def test_checkpoint_y_alertas_0600(self):
        self.archive("powerbeam.log.2.gz", event(0,"bad"))
        self.active.write_text(event(1,"unknown")+event(2,"ok"))
        self.run_monitor()
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.alerts.stat().st_mode & 0o777, 0o600)

    def test_reintento_checkpoint_no_duplica(self):
        self.active.write_text(event(0,"bad")+event(1,"unknown")+event(2,"ok"))
        with patch.object(monitor, "save_checkpoint", side_effect=OSError("falló")):
            with self.assertRaises(OSError):
                self.run_monitor()
        self.assertEqual(len(self.alerts_json()), 1)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.run_monitor()["written"], 0)
        self.assertEqual(self.run_monitor()["lines"], 0)

if __name__ == "__main__":
    unittest.main()
