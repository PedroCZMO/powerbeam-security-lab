"""Offline unit tests: no Google login or external requests."""
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/gmail_oauth_authorize.py'
spec = importlib.util.spec_from_file_location('gmail_oauth_authorize', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OAuthAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.client = self.root / 'client.json'
        self.example = {'installed': {'client_id': 'fake-id', 'client_secret': 'fake-secret', 'auth_uri': 'https://example.org/auth', 'token_uri': 'https://example.org/token'}}
        self.write(self.example)

    def write(self, obj):
        self.client.write_text(json.dumps(obj), encoding='utf-8')
        os.chmod(self.client, 0o600)

    def test_scope_is_send_only(self):
        self.assertEqual(module.SCOPE, 'https://www.googleapis.com/auth/gmail.send')

    def test_valid_desktop_json(self):
        self.assertTrue(module.validate_client_file(self.client))

    def test_web_client_rejected(self):
        self.write({'web': self.example['installed']})
        with self.assertRaises(ValueError): module.validate_client_file(self.client)

    def test_missing_secret_rejected(self):
        self.write({'installed': {'client_id': 'fake-id'}})
        with self.assertRaises(ValueError): module.validate_client_file(self.client)

    def test_invalid_json_rejected(self):
        self.client.write_text('{oops', encoding='utf-8')
        with self.assertRaises(ValueError): module.validate_client_file(self.client)

    def test_world_readable_rejected(self):
        os.chmod(self.client, 0o644)
        with self.assertRaises(ValueError): module.validate_client_file(self.client)

    def test_symlink_rejected(self):
        sym = self.root / 'link.json'
        sym.symlink_to(self.client)
        with self.assertRaises(ValueError): module.validate_client_file(sym)

    def test_private_directory_permissions(self):
        folder = self.root / 'a/b'
        module.private_directory(folder)
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)

    def test_token_saved_600(self):
        target = self.root / 'state/token.json'
        module.save_private_token(target, 'fake-token')
        self.assertEqual(target.read_text(), 'fake-token')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_token_atomic_overwrite(self):
        target = self.root / 'state/token.json'
        module.save_private_token(target, 'old')
        module.save_private_token(target, 'new')
        self.assertEqual(target.read_text(), 'new')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_token_symlink_rejected(self):
        target = self.root / 'state/token.json'
        target.parent.mkdir()
        other = self.root / 'other.txt'
        other.write_text('safe')
        target.symlink_to(other)
        with self.assertRaises(ValueError): module.save_private_token(target, 'token')
        self.assertEqual(other.read_text(), 'safe')

    def test_private_directory_symlink_rejected(self):
        real = self.root / 'real'
        real.mkdir()
        sym = self.root / 'alias'
        sym.symlink_to(real)
        with self.assertRaises(ValueError): module.private_directory(sym)


if __name__ == '__main__':
    unittest.main()
