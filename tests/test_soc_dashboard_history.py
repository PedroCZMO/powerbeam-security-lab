"""Unit tests for the offline SOC HTML history index."""
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import soc_dashboard
import soc_dashboard_history as mod


def mock_report(day):
    return ('<!doctype html><meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'">'
            '<title>PowerBeam Security Lab — SOC Dashboard</title>'
            '<div class="meta">Informe de eventos: <strong>' + day +
            '</strong><br></div>')


def put_private(path, text):
    soc_dashboard.save_private_html(path, text)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        os.chmod(self.base, 0o700)

    def test_01_discover_two_real_cases(self):
        put_private(self.base / "index.html", mock_report("2026-11-06"))
        put_private(self.base / "2026-11-04.html", mock_report("2026-11-04"))
        self.assertEqual(mod.discover_reports(self.base),
                         [("2026-11-06", "index.html"),
                          ("2026-11-04", "2026-11-04.html")])

    def test_02_index_contains_both_links_and_no_network(self):
        html = mod.render_index([("2026-11-06", "index.html"),
                                 ("2026-11-04", "2026-11-04.html")],
                                generated_at=datetime(2026, 11, 9, tzinfo=timezone.utc))
        self.assertIn('href="index.html"', html)
        self.assertIn('href="2026-11-04.html"', html)
        self.assertIn("default-src 'none'", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<script", html.lower())

    def test_03_empty_reports_rejected(self):
        with self.assertRaises(mod.DashboardError):
            mod.discover_reports(self.base)

    def test_04_mismatched_filename_rejected(self):
        put_private(self.base / "2026-11-04.html", mock_report("2026-11-06"))
        with self.assertRaises(mod.DashboardError):
            mod.discover_reports(self.base)

    def test_05_reject_symlink_report(self):
        put_private(self.base / "actual.html", mock_report("2026-11-06"))
        (self.base / "index.html").symlink_to(self.base / "actual.html")
        with self.assertRaises(OSError):
            mod.discover_reports(self.base)

    def test_06_reject_overly_permissive_html(self):
        target = self.base / "index.html"
        put_private(target, mock_report("2026-11-06"))
        os.chmod(target, 0o644)
        with self.assertRaises(mod.DashboardError):
            mod.discover_reports(self.base)

    def test_07_reject_overly_permissive_directory(self):
        os.chmod(self.base, 0o755)
        with self.assertRaises(mod.DashboardError):
            mod.discover_reports(self.base)

    def test_08_reject_forged_html(self):
        put_private(self.base / "index.html", '<strong>2026-11-04</strong>')
        with self.assertRaises(mod.DashboardError):
            mod.discover_reports(self.base)

    def test_09_reject_unsafe_dates(self):
        for date_value in ("2026-02-30", "2026-11-04\" onclick=\"a", "not-a-date"):
            with self.subTest(value=date_value):
                with self.assertRaises(mod.DashboardError):
                    mod.render_index([(date_value, "index.html")])

    def test_10_reject_bad_filename(self):
        with self.assertRaises(mod.DashboardError):
            mod.render_index([("2026-11-06", "../evil.html")])

    def test_11_duplicate_same_day_deduplicated(self):
        put_private(self.base / "index.html", mock_report("2026-11-06"))
        put_private(self.base / "2026-11-06.html", mock_report("2026-11-06"))
        self.assertEqual(mod.discover_reports(self.base),
                         [("2026-11-06", "2026-11-06.html")])

    def test_12_end_to_end_cli_private_index(self):
        put_private(self.base / "index.html", mock_report("2026-11-06"))
        put_private(self.base / "2026-11-04.html", mock_report("2026-11-04"))
        with patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            self.assertEqual(mod.main(["--dir", str(self.base)]), 0)
        dest = self.base / "historico.html"
        self.assertIn('"reports": 2', output.getvalue())
        self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
        self.assertIn('href="2026-11-04.html"', dest.read_text(encoding="utf-8"))

    def test_13_invalid_report_never_overwrites_index(self):
        put_private(self.base / "index.html", "invalid")
        put_private(self.base / "historico.html", "old index")
        with patch.object(sys, "stderr", new_callable=io.StringIO):
            self.assertEqual(mod.main(["--dir", str(self.base)]), 2)
        self.assertEqual((self.base / "historico.html").read_text(), "old index")

    def test_14_ignores_unrelated_html_and_files(self):
        put_private(self.base / "index.html", mock_report("2026-11-06"))
        put_private(self.base / "other.html", "untrusted")
        (self.base / "LEEME-PRIMERO.txt").write_text("private")
        self.assertEqual(mod.discover_reports(self.base),
                         [("2026-11-06", "index.html")])

    def test_15_reject_large_report(self):
        put_private(self.base / "index.html", mock_report("2026-11-06") +
                    "x" * (mod.MAX_REPORT_BYTES + 1))
        with self.assertRaises(mod.DashboardError):
            mod.discover_reports(self.base)


if __name__ == "__main__":
    unittest.main()
