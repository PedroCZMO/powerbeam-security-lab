"""Pruebas offline para el lector incremental aislado de Día 6."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from incremental_reader import read_state, save_state, snapshot_raw  # noqa: E402


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.logs = self.base / "logs"
        self.logs.mkdir()
        self.state = self.base / "alerts" / "state.json"
        self.active = self.logs / "powerbeam.log"

    def test_primera_lectura_y_lectura_siguiente_sin_novedades(self):
        self.active.write_text("primera\nsegunda\n")
        lines, cursors = snapshot_raw(self.logs, {})
        self.assertEqual(lines, ["primera\n", "segunda\n"])
        save_state(self.state, cursors)
        again, _ = snapshot_raw(self.logs, read_state(self.state))
        self.assertEqual(again, [])

    def test_solo_las_lineas_nuevas(self):
        self.active.write_text("a\n")
        _, cur = snapshot_raw(self.logs, {})
        with self.active.open("a") as stream:
            stream.write("b\nc\n")
        lines, _ = snapshot_raw(self.logs, cur)
        self.assertEqual(lines, ["b\n", "c\n"])

    def test_rename_create_de_logrotate(self):
        self.active.write_text("antes\n")
        _, cur = snapshot_raw(self.logs, {})
        with self.active.open("a") as stream:
            stream.write("ultimo antiguo\n")
        self.active.rename(self.logs / "powerbeam.log.1")
        self.active.write_text("nuevo\n")
        lines, _ = snapshot_raw(self.logs, cur)
        self.assertEqual(lines, ["ultimo antiguo\n", "nuevo\n"])

    def test_linea_incompleta_no_avanza_cursor(self):
        self.active.write_bytes(b"parcial")
        lines, cur = snapshot_raw(self.logs, {})
        self.assertEqual(lines, [])
        with self.active.open("ab") as stream:
            stream.write(b" final\n")
        lines, _ = snapshot_raw(self.logs, cur)
        self.assertEqual(lines, ["parcial final\n"])

    def test_archivo_comprimido_no_se_lee_en_esta_fase(self):
        import gzip
        with gzip.open(self.logs / "powerbeam.log.2.gz", "wt") as handle:
            handle.write("antiguo\n")
        self.active.write_text("nuevo\n")
        lines, _ = snapshot_raw(self.logs, {})
        self.assertEqual(lines, ["nuevo\n"])

    def test_estado_corrupto_falla_cerrado(self):
        self.state.parent.mkdir()
        self.state.write_text("{rota")
        with self.assertRaises(json.JSONDecodeError):
            read_state(self.state)

    def test_estado_atomico_y_permisos(self):
        save_state(self.state, {"1:2": 10})
        self.assertEqual(read_state(self.state), {"1:2": 10})
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)

    def test_sin_seguir_enlaces_simbolicos(self):
        elsewhere = self.base / "private.txt"
        elsewhere.write_text("secreto\n")
        self.active.symlink_to(elsewhere)
        with self.assertRaises(ValueError):
            snapshot_raw(self.logs, {})


if __name__ == "__main__":
    unittest.main()
