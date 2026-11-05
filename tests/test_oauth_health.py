"""Offline regression tests: no network, token refreshing or mail sending."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import oauth_health as mod

NOW = datetime(2026, 11, 5, 18, 0, tzinfo=timezone.utc)


class OAuthHealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.token = self.root / 'oauth.json'
        self.data = {
            'token': 'SECRET_ACCESS',
            'refresh_token': 'SECRET_REFRESH',
            'client_id': 'SECRET_CLIENT_ID',
            'client_secret': 'SECRET_CLIENT',
            'token_uri': 'https://oauth2.googleapis.com/token',
            'scopes': [mod.SCOPE],
            'expiry': '2026-11-05T19:00:00Z',
        }
        self.save()

    def save(self, data=None):
        self.token.write_text(json.dumps(self.data if data is None else data), encoding='utf8')
        self.token.chmod(0o600)

    def check(self):
        return mod.inspect(self.token, now=NOW)

    def test_ready(self):
        report = self.check()
        self.assertEqual(report['local_status'], 'READY_LOCAL')
        self.assertEqual(report['access_token_state'], 'VALID')

    def test_expired_access_with_refresh_ready_local(self):
        self.data['expiry'] = '2026-11-05T17:00:00Z'
        self.save()
        report = self.check()
        self.assertEqual(report['local_status'], 'READY_LOCAL')
        self.assertEqual(report['access_token_state'], 'EXPIRED')

    def test_expiring_soon(self):
        self.data['expiry'] = '2026-11-05T18:04:59Z'
        self.save()
        self.assertEqual(self.check()['access_token_state'], 'EXPIRING_SOON')

    def test_expiry_naive_utc(self):
        self.data['expiry'] = '2026-11-05T19:00:00'
        self.save()
        self.assertEqual(self.check()['access_token_state'], 'VALID')

    def test_expiry_offset(self):
        self.data['expiry'] = '2026-11-05T20:00:00+01:00'
        self.save()
        self.assertEqual(self.check()['access_token_state'], 'VALID')

    def test_missing_expiry_warning(self):
        self.data.pop('expiry')
        self.save()
        self.assertEqual(self.check()['local_status'], 'WARNING')

    def test_invalid_expiry(self):
        self.data['expiry'] = 'NOT-A-DATE'
        self.save()
        self.assertEqual(self.check()['error_code'], 'INVALID_EXPIRY')

    def test_no_refresh_but_access_valid_warning(self):
        self.data.pop('refresh_token')
        self.save()
        self.assertEqual(self.check()['local_status'], 'WARNING')

    def test_no_refresh_and_expired_critical(self):
        self.data.pop('refresh_token')
        self.data['expiry'] = '2026-11-05T16:00:00Z'
        self.save()
        self.assertEqual(self.check()['local_status'], 'CRITICAL')

    def test_missing_client_secret_warning(self):
        self.data.pop('client_secret')
        self.save()
        self.assertEqual(self.check()['local_status'], 'WARNING')

    def test_missing_scope(self):
        self.data['scopes'] = []
        self.save()
        self.assertEqual(self.check()['error_code'], 'MISSING_GMAIL_SEND_SCOPE')

    def test_corrupt_json(self):
        self.token.write_text('{broken', encoding='utf8')
        self.assertEqual(self.check()['error_code'], 'INVALID_JSON')

    def test_non_dict_json(self):
        self.save(data=['fake'])
        self.assertEqual(self.check()['error_code'], 'INVALID_JSON')

    def test_missing_file(self):
        self.token.unlink()
        self.assertEqual(self.check()['error_code'], 'NOT_FOUND')

    def test_world_readable_file_rejected(self):
        self.token.chmod(0o644)
        self.assertEqual(self.check()['error_code'], 'INSECURE_FILE')

    def test_world_traversable_directory_rejected(self):
        self.root.chmod(0o755)
        self.addCleanup(lambda: self.root.chmod(0o700) if self.root.exists() else None)
        self.assertEqual(self.check()['error_code'], 'INSECURE_DIRECTORY')

    def test_symlink_file_rejected(self):
        link = self.root / 'alias.json'
        link.symlink_to(self.token)
        self.assertEqual(mod.inspect(link, now=NOW)['error_code'], 'UNREADABLE_OR_SYMLINK')

    def test_symlink_parent_rejected(self):
        link = self.root.parent / (self.root.name + '_link')
        link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(link.unlink)
        self.assertEqual(mod.inspect(link / self.token.name, now=NOW)['error_code'], 'UNREADABLE_OR_SYMLINK')

    def test_secret_values_never_in_report(self):
        report = json.dumps(self.check())
        for secret in ('SECRET_ACCESS', 'SECRET_REFRESH', 'SECRET_CLIENT_ID', 'SECRET_CLIENT'):
            self.assertNotIn(secret, report)

    def test_read_only(self):
        before = self.token.read_bytes()
        report = self.check()
        self.assertEqual(before, self.token.read_bytes())
        self.assertFalse(report['token_modified'])
        self.assertEqual(report['emails_sent'], 0)

    def test_cli_status_zero_and_output_redacted(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            rc = mod.main(['--token', str(self.token)])
        self.assertEqual(rc, 0)
        self.assertNotIn('SECRET_ACCESS', stream.getvalue())

    def test_cli_error_exit_two(self):
        self.token.unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mod.main(['--token', str(self.token)]), 2)

    def test_timezone_required_for_fixed_clock(self):
        with self.assertRaises(ValueError):
            mod.inspect(self.token, now=datetime(2026, 11, 5, 18))

    def test_no_network_imports_required(self):
        self.assertFalse(any('token' in k for k in self.check() if k in {'token', 'refresh_token', 'client_secret'}))
        self.assertEqual(self.check()['remote_authorization'], 'NOT_CHECKED')

if __name__ == '__main__':
    unittest.main()
