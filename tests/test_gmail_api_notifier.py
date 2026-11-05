"""Offline Gmail API dispatch tests: no network, no Gmail account, no secrets."""
import base64
from email import message_from_bytes
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import alert_queue
import gmail_api_notifier as mod


class GmailApiNotifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'alerts.jsonl'
        self.state = self.root / 'state.json'
        self.source.write_text(
            json.dumps({'alert_id': 'HIST-1', 'rule_id': 'SOC-002', 'severity': 'medium',
                        'source_ip': '192.0.2.10', 'timestamp': '2026-11-05T11:00:00+01:00'}) + '\n',
            encoding='utf8')
        alert_queue.run('bootstrap', self.source, self.state)
        self.token = self.root / 'token.json'
        self.save_token({'token': 'fake-test-token', 'scopes': [mod.gmail_oauth_authorize.SCOPE]})

    def save_token(self, value):
        self.token.write_text(json.dumps(value), encoding='utf8')
        self.token.chmod(0o600)

    def add_alert(self, aid='SIM-1'):
        with self.source.open('a', encoding='utf8') as out:
            out.write(json.dumps({'alert_id': aid, 'rule_id': 'SOC-001', 'severity': 'high',
                                  'source_ip': '192.0.2.11', 'timestamp': '2026-11-05T12:00:00+01:00'}) + '\n')
        alert_queue.run('scan', self.source, self.state)

    def dispatch(self, sender=None, max_alerts=1):
        return mod.dispatch(self.state, sender or (lambda msg: 'mock-gmail-id'),
                            source=self.source, sender='pedroczmo23@gmail.com',
                            recipient='pedroczmo23@gmail.com', max_alerts=max_alerts)

    def test_token_regular_600(self):
        self.assertEqual(mod.token_data(self.token)['token'], 'fake-test-token')

    def test_token_rejects_world_readable(self):
        self.token.chmod(0o644)
        with self.assertRaises(ValueError): mod.token_data(self.token)

    def test_token_rejects_symlink(self):
        alias = self.root / 'alias.json'
        alias.symlink_to(self.token)
        with self.assertRaises(OSError): mod.token_data(alias)

    def test_token_rejects_wrong_scope(self):
        self.save_token({'token': 'fake', 'scopes': ['https://example.org/read']})
        with self.assertRaises(ValueError): mod.token_data(self.token)

    def test_token_rejects_nonjson(self):
        self.token.write_text('garbage')
        with self.assertRaises(ValueError): mod.token_data(self.token)

    def test_token_rejects_missing_token(self):
        self.save_token({'scopes': [mod.gmail_oauth_authorize.SCOPE]})
        with self.assertRaises(ValueError): mod.token_data(self.token)

    def test_api_encoded_mime_message(self):
        service = Mock()
        service.users.return_value.messages.return_value.send.return_value.execute.return_value = {'id': 'gmail-123'}
        self.add_alert()
        msg = mod.smtp_notifier.make_email(
            alert_queue.run('status', self.source, self.state)['pending_alerts'][0],
            'pedroczmo23@gmail.com', 'pedroczmo23@gmail.com')
        gmail_id = mod.send_email_with_service(service, msg)
        self.assertEqual(gmail_id, 'gmail-123')
        request_args = service.users.return_value.messages.return_value.send.call_args.kwargs
        self.assertEqual(request_args['userId'], 'me')
        parsed = message_from_bytes(base64.urlsafe_b64decode(request_args['body']['raw']))
        self.assertEqual(parsed['To'], 'pedroczmo23@gmail.com')
        self.assertIn('SOC-001', parsed['Subject'])
        self.assertEqual(parsed['X-PowerBeam-Alert-ID'], 'SIM-1')

    def test_api_missing_id_treated_as_error(self):
        service = Mock()
        service.users.return_value.messages.return_value.send.return_value.execute.return_value = {}
        with self.assertRaises(ValueError):
            mod.send_email_with_service(service, mod.smtp_notifier.make_email(
                {'alert_id':'SIM-1', 'rule_id':'SOC-001', 'severity':'high',
                 'source_ip':'192.0.2.11','timestamp':'2026-11-05T12:00:00+01:00'},
                'pedroczmo23@gmail.com','pedroczmo23@gmail.com'))

    def test_no_pending_never_calls_sender(self):
        sender = Mock()
        result = self.dispatch(sender)
        self.assertEqual(result['accepted_by_gmail_api'], 0)
        sender.assert_not_called()

    def test_success_acknowledges(self):
        self.add_alert()
        result = self.dispatch()
        self.assertEqual(result['accepted_by_gmail_api'], 1)
        self.assertEqual(result['acknowledged'], 1)
        self.assertEqual(result['pending_total'], 0)
        self.assertFalse(result['needs_reconciliation'])
        self.assertEqual(alert_queue.run('status', self.source, self.state)['acknowledged'], 1)

    def test_duplicate_send_prevented_after_ack(self):
        self.add_alert()
        sender = Mock(return_value='gmail-1')
        self.dispatch(sender)
        self.dispatch(sender)
        sender.assert_called_once()

    def test_failure_keeps_pending(self):
        self.add_alert()
        def failing(_):
            raise ConnectionError('fake problem')
        result = self.dispatch(failing)
        self.assertEqual(result['acknowledged'], 0)
        self.assertEqual(result['pending_total'], 1)
        self.assertTrue(result['needs_reconciliation'])
        self.assertEqual(result['error']['stage'], 'gmail_api')
        self.assertNotIn('fake problem', json.dumps(result))

    def test_retry_after_known_preacceptance_failure(self):
        self.add_alert()
        self.dispatch(lambda _: (_ for _ in ()).throw(ConnectionError('test')))
        result = self.dispatch()
        self.assertEqual(result['acknowledged'], 1)

    def test_no_response_id_keeps_pending(self):
        self.add_alert()
        result = self.dispatch(lambda msg: None)
        self.assertEqual(result['accepted_by_gmail_api'], 0)
        self.assertEqual(result['pending_total'], 1)
        self.assertTrue(result['needs_reconciliation'])

    def test_invalid_address_rejected_before_send(self):
        self.add_alert()
        with self.assertRaises(ValueError):
            mod.dispatch(self.state, lambda _: 'id', source=self.source,
                         sender='bad\nTo:other@x.com', recipient='test@example.com')

    def test_max_alerts_outside_range(self):
        with self.assertRaises(ValueError): self.dispatch(max_alerts=0)
        with self.assertRaises(ValueError): self.dispatch(max_alerts=11)

    def test_source_unchanged_by_delivery(self):
        self.add_alert()
        before = self.source.read_bytes()
        self.dispatch()
        self.assertEqual(self.source.read_bytes(), before)

    def test_two_alerts_limited_to_one(self):
        self.add_alert('SIM-1')
        self.add_alert('SIM-2')
        result = self.dispatch()
        self.assertEqual(result['accepted_by_gmail_api'], 1)
        self.assertEqual(result['pending_total'], 1)

    def test_cli_empty_queue_does_not_open_token_or_network(self):
        with patch.object(mod, 'gmail_sender') as send_factory:
            code = mod.main(['send', '--state', str(self.state), '--source', str(self.source),
                             '--sender', 'pedroczmo23@gmail.com', '--recipient', 'pedroczmo23@gmail.com',
                             '--token', str(self.root / 'nonexistent.json'), '--confirm-live-send', 'YES'])
        self.assertEqual(code, 0)
        send_factory.assert_not_called()

    def test_cli_requires_explicit_yes(self):
        with self.assertRaises(SystemExit) as caught:
            mod.main(['send','--state',str(self.state),'--source',str(self.source),
                      '--sender','pedroczmo23@gmail.com','--recipient','pedroczmo23@gmail.com'])
        self.assertEqual(caught.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
