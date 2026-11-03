"""RES-003: prueba de regresión por histórico raw desaparecido (v3 experimental)."""
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import stateful_monitor_v3 as monitor


def evt(minute, kind):
    msg = {
        "bad": "Bad password attempt for 'testuser' from 192.0.2.10",
        "unknown": "Login attempt for nonexistent user from 192.0.2.10",
        "ok": "Password auth succeeded for 'testuser' from 192.0.2.10",
    }[kind]
    return f"2026-11-03T11:{minute:02d}:00+01:00 source=192.0.2.20 httpd[100]: {msg}\n"


class MissingRawTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.logs = root / 'logs'
        self.logs.mkdir()
        self.backup = root / 'respaldo'
        self.backup.mkdir()
        self.log = self.logs / 'powerbeam.log'
        self.state = root / 'state-v3.json'
        self.alerts = root / 'alerts-v3.jsonl'

    def run_monitor(self):
        return monitor.run_once(self.logs, self.state, self.alerts)

    def prepare_loss(self, append_pending=True):
        self.log.write_text(evt(0, 'bad'))
        self.run_monitor()
        before = self.state.read_bytes()
        if append_pending:
            with self.log.open('a') as f:
                f.write(evt(1, 'unknown'))
        self.log.rename(self.backup / 'powerbeam.log.1')
        self.log.write_text(evt(2, 'ok'))
        return before

    def test_historico_desaparecido_falla_y_checkpoint_inmutable(self):
        before = self.prepare_loss()
        with self.assertRaisesRegex(ValueError, 'RES-003'):
            self.run_monitor()
        self.assertEqual(self.state.read_bytes(), before)
        self.assertFalse(self.alerts.exists())

    def test_recuperacion_tras_restaurar_historico(self):
        before = self.prepare_loss()
        with self.assertRaises(ValueError):
            self.run_monitor()
        self.assertEqual(self.state.read_bytes(), before)
        (self.backup / 'powerbeam.log.1').rename(self.logs / 'powerbeam.log.1')
        result = self.run_monitor()
        self.assertEqual((result['lines'], result['soc002'], result['written']), (2, 1, 1))
        saved = [json.loads(line) for line in self.alerts.read_text().splitlines()]
        self.assertEqual([alert['rule_id'] for alert in saved], ['SOC-002'])
        self.assertEqual((self.run_monitor()['lines'], len(saved)), (0, 1))

    def test_historico_desaparecido_completo_tambien_falla_conservadoramente(self):
        before = self.prepare_loss(append_pending=False)
        with self.assertRaisesRegex(ValueError, 'RES-003'):
            self.run_monitor()
        self.assertEqual(self.state.read_bytes(), before)

    def test_gzip_reconciliado_admite_rotacion_real(self):
        self.log.write_text(evt(0, 'bad'))
        self.run_monitor()
        rotated = self.logs / 'powerbeam.log.1'
        self.log.rename(rotated)
        with rotated.open('a') as f:
            f.write(evt(1, 'unknown'))
        self.log.write_text(evt(2, 'ok'))
        with gzip.open(self.logs / 'powerbeam.log.2.gz', 'wb') as fd:
            fd.write(rotated.read_bytes())
        rotated.unlink()
        result = self.run_monitor()
        self.assertEqual((result['lines'], result['soc002'], result['written']), (2, 1, 1))
        self.assertEqual(self.run_monitor()['lines'], 0)
        # Retención posterior: ya reconciliado, no hay cursor raw huérfano.
        (self.logs / 'powerbeam.log.2.gz').unlink()
        self.assertEqual(self.run_monitor()['lines'], 0)

    def test_gzip_ajeno_no_oculta_historico_perdido(self):
        before = self.prepare_loss()
        with gzip.open(self.logs / 'powerbeam.log.2.gz', 'wb') as fd:
            fd.write(evt(0, 'unknown').encode())
        with self.assertRaisesRegex(ValueError, 'RES-003'):
            self.run_monitor()
        self.assertEqual(self.state.read_bytes(), before)

    def test_gzip_inicial_sin_raw_previo_se_procesa(self):
        self.log.write_text(evt(2, 'ok'))
        with gzip.open(self.logs / 'powerbeam.log.2.gz', 'wb') as fd:
            fd.write((evt(0, 'bad') + evt(1, 'unknown')).encode())
        result = self.run_monitor()
        self.assertEqual((result['lines'], result['soc002'], result['written']), (3, 1, 1))

    def test_v2_no_se_acepta_como_checkpoint_v3(self):
        self.state.write_text(json.dumps({'version': 2}))
        with self.assertRaisesRegex(ValueError, 'versión'):
            self.run_monitor()


if __name__ == '__main__':
    unittest.main()
