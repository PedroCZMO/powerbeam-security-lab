"""Offline tests. No Google connections, no mail and no secret material emitted."""
import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import oauth_health
import oauth_remote_health as mod


class OAuthRemoteHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.token = self.root / 'token.json'
        self.data = {
            'token': 'SECRET_ACCESS', 'refresh_token': 'SECRET_REFRESH',
            'client_id': 'SECRET_ID', 'client_secret': 'SECRET_CLIENT',
            'token_uri': mod.TRUSTED_TOKEN_URI,
            'scopes': [oauth_health.SCOPE],
            'expiry': '2026-01-01T00:00:00Z',
        }
        self.save()

    def save(self):
        self.token.write_text(json.dumps(self.data), encoding='utf-8')
        self.token.chmod(0o600)

    def check(self, fn=lambda _: True):
        return mod.check(self.token, refresher=fn)

    def test_refresh_success(self):
        r = self.check()
        self.assertEqual(r['health_status'], 'HEALTHY')
        self.assertEqual(r['remote_authorization'], 'ACCEPTED')

    def test_expired_access_does_not_block_refresh(self):
        self.assertEqual(self.check()['access_token_state'], 'EXPIRED')
        self.assertEqual(self.check()['health_status'], 'HEALTHY')

    def test_no_secret_in_report(self):
        r = json.dumps(self.check())
        self.assertNotIn('SECRET_', r)
        self.assertNotIn('refresh_token', r.replace('refresh_token_expiry', ''))

    def test_no_file_changes(self):
        previous = self.token.read_bytes()
        self.check()
        self.assertEqual(previous, self.token.read_bytes())

    def test_no_email(self):
        self.assertEqual(self.check()['emails_sent'], 0)

    def test_missing_token_rejects_without_network(self):
        self.token.unlink()
        called = []
        r = self.check(lambda _: called.append(True))
        self.assertEqual(r['health_status'], 'CRITICAL')
        self.assertEqual(r['remote_authorization'], 'NOT_CHECKED')
        self.assertFalse(called)

    def test_invalid_file_permissions_no_network(self):
        self.token.chmod(0o644)
        called = []
        r = self.check(lambda _: called.append(True))
        self.assertEqual(r['health_status'], 'CRITICAL')
        self.assertFalse(called)

    def test_missing_scope_no_network(self):
        self.data['scopes'] = []
        self.save()
        called = []
        r = self.check(lambda _: called.append(True))
        self.assertEqual(r['health_status'], 'CRITICAL')
        self.assertFalse(called)

    def test_missing_refresh_token_no_network(self):
        self.data.pop('refresh_token')
        self.save()
        called = []
        r = self.check(lambda _: called.append(True))
        self.assertEqual(r['health_status'], 'CRITICAL')
        self.assertFalse(called)

    def test_untrusted_token_uri_blocks_network(self):
        self.data['token_uri'] = 'https://evil.invalid/refresh'
        self.save()
        called = []
        r = self.check(lambda _: called.append(True))
        self.assertEqual(r['error_code'], 'UNTRUSTED_TOKEN_ENDPOINT')
        self.assertFalse(called)

    def test_refresh_error_keeps_secrets_hidden(self):
        def fail(_):
            raise mod.ProbeFailure('REFRESH_FAILED')
        r = self.check(fail)
        self.assertEqual(r['error_code'], 'REFRESH_FAILED')
        self.assertEqual(r['health_status'], 'CRITICAL')
        self.assertEqual(r['remote_authorization'], 'FAILED')

    def test_transport_error_is_degraded(self):
        def fail(_):
            raise mod.ProbeFailure('TRANSPORT_ERROR')
        self.assertEqual(self.check(fail)['health_status'], 'DEGRADED')

    def test_missing_google_libraries_is_degraded(self):
        def fail(_):
            raise mod.ProbeFailure('GOOGLE_LIBRARIES_MISSING')
        self.assertEqual(self.check(fail)['error_code'], 'GOOGLE_LIBRARIES_MISSING')

    def test_false_refresh_result_is_rejected(self):
        r = self.check(lambda _: False)
        self.assertEqual(r['error_code'], 'INVALID_REFRESH_RESULT')

    def test_unexpected_exception_redacted(self):
        def fail(_):
            raise RuntimeError('SECRET_CLIENT')
        r = self.check(fail)
        self.assertEqual(r['error_code'], 'UNEXPECTED_REFRESH_FAILURE')
        self.assertNotIn('SECRET_CLIENT', json.dumps(r))

    def test_cli_confirmation_required(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as caught:
                mod.main(['--token', str(self.token)])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('required', err.getvalue())

    def test_cli_success_no_secret(self):
        with patch.object(mod, 'check', return_value={
                'health_status':'HEALTHY', 'remote_authorization':'ACCEPTED',
                'emails_sent':0, 'token_modified':False}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = mod.main(['--online', 'YES', '--token', str(self.token)])
        self.assertEqual(code, 0)
        self.assertNotIn('SECRET_', out.getvalue())

    def test_cli_error_code_nonzero(self):
        with patch.object(mod, 'check', return_value={
                'health_status':'DEGRADED', 'error_code':'TRANSPORT_ERROR'}):
            with contextlib.redirect_stdout(io.StringIO()):
                code = mod.main(['--online', 'YES', '--token', str(self.token)])
        self.assertEqual(code, 1)

    def test_probe_rejects_invalid_error_code(self):
        with self.assertRaises(ValueError):
            mod.ProbeFailure('secret token error')

    def test_refresh_callable_does_not_mutate_file(self):
        def fake_refresh(token):
            token['token'] = 'CHANGED_IN_MEMORY'
            return True
        original = self.token.read_bytes()
        self.assertEqual(self.check(fake_refresh)['health_status'], 'HEALTHY')
        self.assertEqual(self.token.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
