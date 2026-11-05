"""Day 11 - preview tests; only local TemporaryDirectory data, no SMTP."""
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import alert_queue as q
import alert_notifier as n


def item(aid, rule='SOC-002', severity='medium'):
    return {'alert_id': aid, 'rule_id': rule, 'severity': severity,
            'source_ip': '192.0.2.10', 'timestamp': '2026-11-05T10:00:00+01:00'}


class NotifierPreviewTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.src = self.dir / 'alerts.jsonl'
        self.state = self.dir / 'private' / 'state.json'
        self.src.write_text(json.dumps(item('HIST-001')) + '\n', encoding='utf-8')
        q.run('bootstrap', self.src, self.state)

    def enqueue(self, *items):
        with self.src.open('a', encoding='utf-8') as out:
            for a in items:
                out.write(json.dumps(a) + '\n')
        q.run('scan', self.src, self.state)

    def view(self, **kw):
        return n.preview(self.state, source=self.src, **kw)

    def test_empty_queue(self):
        self.assertEqual(self.view()['messages'], [])

    def test_historical_ignored(self):
        self.assertEqual(self.view()['pending_total'], 0)

    def test_single_alert(self):
        self.enqueue(item('SOC-002-NEW'))
        self.assertEqual(self.view()['messages'][0]['alert_id'], 'SOC-002-NEW')

    def test_two_alerts(self):
        self.enqueue(item('NEW-1'), item('NEW-2'))
        self.assertEqual(self.view()['previewed'], 2)

    def test_queue_order_retained(self):
        self.enqueue(item('NEW-1'), item('NEW-2'))
        self.assertEqual([m['alert_id'] for m in self.view()['messages']], ['NEW-1', 'NEW-2'])

    def test_limit(self):
        self.enqueue(item('NEW-1'), item('NEW-2'))
        self.assertEqual(self.view(max_alerts=1)['previewed'], 1)

    def test_remaining(self):
        self.enqueue(item('NEW-1'), item('NEW-2'))
        self.assertEqual(self.view(max_alerts=1)['remaining'], 1)

    def test_severity_in_subject(self):
        self.enqueue(item('NEW-1', 'SOC-001', 'high'))
        self.assertIn('HIGH SOC-001', self.view()['messages'][0]['subject'])

    def test_id_in_subject(self):
        self.enqueue(item('NEW-1'))
        self.assertIn('NEW-1', self.view()['messages'][0]['subject'])

    def test_body_contains_evidence_fields(self):
        self.enqueue(item('NEW-1'))
        body = self.view()['messages'][0]['body']
        self.assertIn('192.0.2.10', body)
        self.assertIn('2026-11-05T10:00:00+01:00', body)

    def test_no_claim_of_compromise(self):
        self.enqueue(item('NEW-1'))
        self.assertIn('no demuestra', self.view()['messages'][0]['body'])

    def test_no_ack_on_preview(self):
        self.enqueue(item('NEW-1'))
        self.assertEqual(self.view()['acknowledged'], 0)
        self.assertEqual(q.run('status', self.src, self.state)['pending'], 1)

    def test_no_state_modified(self):
        self.enqueue(item('NEW-1'))
        before = self.state.read_bytes()
        self.view()
        self.assertEqual(self.state.read_bytes(), before)

    def test_no_source_modified(self):
        self.enqueue(item('NEW-1'))
        before = self.src.read_bytes()
        self.view()
        self.assertEqual(self.src.read_bytes(), before)

    def test_preview_repeatable(self):
        self.enqueue(item('NEW-1'))
        self.assertEqual(self.view(), self.view())

    def test_ack_removed_from_previews(self):
        self.enqueue(item('NEW-1'))
        q.run('ack', self.src, self.state, alert_id='NEW-1', reason='reviewed')
        self.assertEqual(self.view()['previewed'], 0)

    def test_max_alerts_reject_zero(self):
        with self.assertRaises(ValueError):
            self.view(max_alerts=0)

    def test_max_alerts_reject_gt_50(self):
        with self.assertRaises(ValueError):
            self.view(max_alerts=51)

    def test_preview_does_not_read_source(self):
        self.enqueue(item('NEW-1'))
        self.src.unlink()
        self.assertEqual(self.view()['previewed'], 1)

    def test_cli_json(self):
        self.enqueue(item('NEW-1'))
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = n.main(['preview', '--source', str(self.src), '--state', str(self.state)])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(stdout.getvalue())['previewed'], 1)

    def test_cli_missing_state_errors_cleanly(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = n.main(['preview', '--source', str(self.src), '--state', str(self.dir / 'missing.json')])
        self.assertEqual(rc, 1)
        self.assertIn('ERROR:', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
