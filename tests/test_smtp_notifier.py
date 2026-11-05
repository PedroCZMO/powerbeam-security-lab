"""Day 11 phase 8. All mail servers are mocks: zero SMTP network traffic."""
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import smtplib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import alert_queue as queue
import smtp_notifier as n


SENDER = 'soc@example.org'
RECIPIENT = 'analyst@example.org'


def alert(aid):
    return {'alert_id': aid, 'rule_id': 'SOC-002', 'severity': 'medium',
            'source_ip': '192.0.2.10', 'timestamp': '2026-11-05T10:00:00+01:00'}


class FakeSMTP:
    instances = []

    def __init__(self, *args, **kwargs):
        self.actions = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def ehlo(self):
        self.actions.append('ehlo')

    def starttls(self, **kwargs):
        self.actions.append('starttls')

    def login(self, username, password):
        self.actions.append('login')

    def send_message(self, msg):
        self.actions.append('send_message')
        return {}


class SMTPNotifierTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.src = self.dir / 'alerts.jsonl'
        self.state = self.dir / 'private' / 'state.json'
        self.src.write_text(json.dumps(alert('HIST-1')) + '\n', encoding='utf-8')
        queue.run('bootstrap', self.src, self.state)
        self.sent = []

    def enqueue(self, *ids):
        with self.src.open('a', encoding='utf-8') as out:
            for aid in ids:
                out.write(json.dumps(alert(aid)) + '\n')
        queue.run('scan', self.src, self.state)

    def success(self, msg):
        self.sent.append(msg)

    def dispatch(self, **kwargs):
        return n.dispatch(self.state, kwargs.pop('send', self.success),
                          source=self.src, sender=SENDER,
                          recipient=RECIPIENT, **kwargs)

    def test_empty_no_mail(self):
        result = self.dispatch()
        self.assertEqual((result['accepted_by_smtp'], self.sent), (0, []))

    def test_single_accepted_ack(self):
        self.enqueue('SOC-NEW-1')
        result = self.dispatch()
        self.assertEqual((result['accepted_by_smtp'], result['acknowledged']), (1, 1))
        self.assertEqual(queue.run('status', self.src, self.state)['pending'], 0)

    def test_second_dispatch_no_duplicate(self):
        self.enqueue('SOC-NEW-1')
        self.dispatch()
        self.dispatch()
        self.assertEqual(len(self.sent), 1)

    def test_two_messages(self):
        self.enqueue('SOC-NEW-1', 'SOC-NEW-2')
        self.assertEqual(self.dispatch()['acknowledged'], 2)
        self.assertEqual(len(self.sent), 2)

    def test_max_one(self):
        self.enqueue('SOC-NEW-1', 'SOC-NEW-2')
        self.assertEqual(self.dispatch(max_alerts=1)['pending_total'], 1)

    def test_failure_leaves_pending(self):
        self.enqueue('SOC-NEW-1')
        def fail(_):
            raise smtplib.SMTPException('simulated failure')
        result = self.dispatch(send=fail)
        self.assertEqual(result['error']['stage'], 'smtp')
        self.assertEqual(result['pending_total'], 1)
        self.assertEqual(result['acknowledged'], 0)

    def test_retry_after_failure(self):
        self.enqueue('SOC-NEW-1')
        self.dispatch(send=lambda _: (_ for _ in ()).throw(ConnectionError()))
        self.assertEqual(self.dispatch()['acknowledged'], 1)

    def test_partial_success(self):
        self.enqueue('SOC-NEW-1', 'SOC-NEW-2')
        counter = [0]
        def fail_second(msg):
            counter[0] += 1
            if counter[0] == 2:
                raise smtplib.SMTPException('simulated')
        result = self.dispatch(send=fail_second)
        self.assertEqual(result['acknowledged_ids'], ['SOC-NEW-1'])
        self.assertEqual(result['pending_total'], 1)

    def test_ack_reason_delivered(self):
        self.enqueue('SOC-NEW-1')
        self.dispatch()
        state = queue.read_state(self.state)
        self.assertEqual(state['acknowledged'][0]['reason'], 'delivered')

    def test_original_alert_source_unchanged(self):
        self.enqueue('SOC-NEW-1')
        prior = self.src.read_bytes()
        self.dispatch()
        self.assertEqual(self.src.read_bytes(), prior)

    def test_message_content(self):
        self.enqueue('SOC-NEW-1')
        self.dispatch()
        mail = self.sent[0]
        self.assertEqual(mail['To'], RECIPIENT)
        self.assertIn('SOC-NEW-1', mail['Subject'])
        self.assertIn('192.0.2.10', mail.get_content())
        self.assertNotIn('password', mail.as_string().lower())

    def test_invalid_email_header_rejected(self):
        for bad in ('a@example.org\r\nBcc:bad@evil.org', 'Name <a@example.org>', 'two@example.org,b@example.org', 'invalid'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                n.make_email(alert('A'), bad, RECIPIENT)

    def test_only_tls_modes_allowed(self):
        with self.assertRaises(ValueError):
            n.smtp_sender(host='smtp.example.org', port=25, tls_mode='plain',
                          username='user', password='secret')

    @patch.object(n.smtplib, 'SMTP_SSL', FakeSMTP)
    def test_smtp_ssl_uses_login_and_send(self):
        FakeSMTP.instances.clear()
        sender = n.smtp_sender(host='smtp.example.org', port=465, tls_mode='ssl',
                               username='user', password='secret')
        sender(n.make_email(alert('A'), SENDER, RECIPIENT))
        self.assertEqual(FakeSMTP.instances[-1].actions, ['login', 'send_message'])

    @patch.object(n.smtplib, 'SMTP', FakeSMTP)
    def test_starttls_before_login(self):
        FakeSMTP.instances.clear()
        sender = n.smtp_sender(host='smtp.example.org', port=587, tls_mode='starttls',
                               username='user', password='secret')
        sender(n.make_email(alert('A'), SENDER, RECIPIENT))
        self.assertEqual(FakeSMTP.instances[-1].actions,
                         ['ehlo', 'starttls', 'ehlo', 'login', 'send_message'])

    def test_refused_recipient_fails(self):
        class RefusingSMTP(FakeSMTP):
            def send_message(self, msg):
                return {'analyst@example.org': (550, b'failed')}
        with patch.object(n.smtplib, 'SMTP_SSL', RefusingSMTP):
            sender = n.smtp_sender(host='smtp.example.org', port=465, tls_mode='ssl',
                                   username='user', password='secret')
            with self.assertRaises(smtplib.SMTPRecipientsRefused):
                sender(n.make_email(alert('A'), SENDER, RECIPIENT))

    def test_password_private_file(self):
        path = self.dir / 'secret'
        path.write_text('dummy-secret\n', encoding='utf-8')
        path.chmod(0o600)
        self.assertEqual(n.read_password(path), 'dummy-secret')

    def test_password_rejects_world_readable(self):
        path = self.dir / 'secret'
        path.write_text('dummy-secret', encoding='utf-8')
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            n.read_password(path)

    def test_password_refuses_symlinks(self):
        path = self.dir / 'secret'
        path.write_text('dummy-secret', encoding='utf-8')
        path.chmod(0o600)
        alias = self.dir / 'link'
        alias.symlink_to(path)
        with self.assertRaises(OSError):
            n.read_password(alias)

    def test_cli_empty_queue_no_credentials_or_network(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = n.main(['send', '--state', str(self.state), '--source', str(self.src),
                         '--sender', SENDER, '--recipient', RECIPIENT,
                         '--smtp-host', 'smtp.example.org', '--smtp-port', '587',
                         '--tls-mode', 'starttls', '--smtp-user', 'user',
                         '--password-file', str(self.dir / 'nonexistent'),
                         '--confirm-live-send', 'YES'])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(stdout.getvalue())['accepted_by_smtp'], 0)

    def test_ack_error_needs_reconciliation(self):
        self.enqueue('SOC-NEW-1')
        original = queue.run
        def failing_ack(command, *args, **kwargs):
            if command == 'ack':
                raise OSError('simulated save failure')
            return original(command, *args, **kwargs)
        with patch.object(n.alert_queue, 'run', side_effect=failing_ack):
            result = self.dispatch()
        self.assertEqual(result['accepted_by_smtp'], 1)
        self.assertEqual(result['acknowledged'], 0)
        self.assertTrue(result['needs_reconciliation'])
        self.assertEqual(queue.run('status', self.src, self.state)['pending'], 1)


if __name__ == '__main__':
    unittest.main()
