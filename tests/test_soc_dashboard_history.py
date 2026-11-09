"""Regression tests for portal-safe, self-contained SOC history viewer."""
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
    rule = "SOC-002" if day == "2026-11-04" else "SOC-001"
    return soc_dashboard.render_dashboard({
        "component": "powerbeam_soc_daily",
        "report_status": "READY",
        "inspection": "LOCAL_READ_ONLY",
        "report_date": day,
        "timezone": "Europe/Madrid",
        "activity": {
            "alerts_event_date": 1,
            "alerts_by_rule": {"SOC-001": int(rule == "SOC-001"),
                               "SOC-002": int(rule == "SOC-002"), "other": 0},
            "alerts_by_severity": {"informational": 0, "low": 0, "medium": 1,
                                   "high": 0, "critical": 0},
            "acknowledged_on_date": 0 if day == "2026-11-04" else 1,
        },
        "pending_now": {
            "total": 0,
            "by_severity": {key: 0 for key in soc_dashboard.SEVERITIES},
            "oldest_event_age_minutes": None,
            "status": "HEALTHY",
        },
        "health": {
            "detection": "HEALTHY", "alert_queue": "HEALTHY",
            "backlog": "HEALTHY", "oauth_local": "READY_LOCAL",
            "oauth_remote": "NOT_CHECKED",
            "notification_delivery": "NOT_AUTOMATED",
        },
        "emails_sent": 0, "tokens_modified": False, "notes": [],
    }, generated_at=datetime(2026, 11, 9, tzinfo=timezone.utc))


def put_private(path, text):
    soc_dashboard.save_private_html(path, text)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        os.chmod(self.base, 0o700)

    def reports(self):
        put_private(self.base / "index.html", mock_report("2026-11-06"))
        put_private(self.base / "2026-11-04.html", mock_report("2026-11-04"))
        return mod.discover_reports(self.base)

    def test_01_discover_two_real_cases(self):
        reports = self.reports()
        self.assertEqual([(a, b) for a, b, _ in reports],
                         [("2026-11-06", "index.html"),
                          ("2026-11-04", "2026-11-04.html")])

    def test_02_self_contained_index_renders_two_dates(self):
        index = mod.render_index(self.reports(),
                                 generated_at=datetime(2026, 11, 9, tzinfo=timezone.utc))
        self.assertIn("2026-11-06", index)
        self.assertIn("2026-11-04", index)
        self.assertEqual(index.count('<details class="card">'), 2)
        self.assertIn("Ver métricas agregadas", index)
        self.assertNotIn('href="index.html"', index)
        self.assertNotIn('href="2026-11-04.html"', index)

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
        for value in ("2026-02-30", '2026-11-04" onclick="x', "not-a-date"):
            with self.subTest(value=value):
                with self.assertRaises(mod.DashboardError):
                    mod.render_index([(value, "index.html",
                                       mod._extract_summary(mock_report("2026-11-06")))])

    def test_10_reject_bad_filename(self):
        summary = mod._extract_summary(mock_report("2026-11-06"))
        with self.assertRaises(mod.DashboardError):
            mod.render_index([("2026-11-06", "../evil.html", summary)])

    def test_11_duplicate_same_day_prefers_dated_filename(self):
        put_private(self.base / "index.html", mock_report("2026-11-06"))
        put_private(self.base / "2026-11-06.html", mock_report("2026-11-06"))
        self.assertEqual([(d, f) for d, f, _ in mod.discover_reports(self.base)],
                         [("2026-11-06", "2026-11-06.html")])

    def test_12_end_to_end_cli_private_index(self):
        self.reports()
        with patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            self.assertEqual(mod.main(["--dir", str(self.base)]), 0)
        dest = self.base / "historico.html"
        html = dest.read_text(encoding="utf-8")
        self.assertIn('"reports": 2', output.getvalue())
        self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
        self.assertIn('SOC-001', html)
        self.assertIn('SOC-002', html)
        self.assertIn('<details class="card">', html)
        self.assertNotIn('href="index.html"', html)

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
        self.assertEqual([(d, f) for d, f, _ in mod.discover_reports(self.base)],
                         [("2026-11-06", "index.html")])

    def test_15_reject_large_report(self):
        put_private(self.base / "index.html", mock_report("2026-11-06") +
                    "x" * (mod.MAX_REPORT_BYTES + 1))
        with self.assertRaises(mod.DashboardError):
            mod.discover_reports(self.base)

    def test_16_summaries_from_real_html_are_correct(self):
        rows = {d: summary for d, _, summary in self.reports()}
        self.assertEqual(rows["2026-11-06"]["rules"]["SOC-001"], 1)
        self.assertEqual(rows["2026-11-06"]["ack"], 1)
        self.assertEqual(rows["2026-11-04"]["rules"]["SOC-002"], 1)
        self.assertEqual(rows["2026-11-04"]["ack"], 0)
        self.assertEqual(rows["2026-11-04"]["pending"], 0)
        self.assertEqual(rows["2026-11-06"]["health"]["Motor de detección"],
                         "HEALTHY")

    def test_17_discard_unknown_and_secret_html(self):
        original = mock_report("2026-11-06")
        forged = original.replace("</body>",
                                  "<p>SECRET_TOKEN_DO_NOT_SHOW 192.0.2.99</p></body>")
        put_private(self.base / "index.html", forged)
        rendered = mod.render_index(mod.discover_reports(self.base))
        self.assertNotIn("SECRET_TOKEN_DO_NOT_SHOW", rendered)
        self.assertNotIn("192.0.2.99", rendered)

    def test_18_reject_inconsistent_daily_metrics(self):
        corrupted = mock_report("2026-11-06").replace(
            '<span class="bar-value">1</span>',
            '<span class="bar-value">2</span>', 1)
        put_private(self.base / "index.html", corrupted)
        with self.assertRaises(mod.DashboardError):
            mod.discover_reports(self.base)

    def test_19_no_network_and_no_sibling_file_dependency(self):
        html = mod.render_index(self.reports())
        self.assertIn("default-src 'none'", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<script", html.lower())
        self.assertNotIn("<iframe", html.lower())
        self.assertNotIn("href=", html.lower())
        self.assertIn("<summary>", html)

    def test_20_bad_direct_summary_is_rejected(self):
        summary = mod._extract_summary(mock_report("2026-11-06"))
        summary["health"]["Motor de detección"] = '<script>malicious()</script>'
        with self.assertRaises(mod.DashboardError):
            mod.render_index([("2026-11-06", "index.html", summary)])


    def test_21_health_states_have_distinct_semantic_tones(self):
        expected = {
            "HEALTHY": "healthy",
            "READY_LOCAL": "ready-local",
            "WARNING": "warning",
            "CRITICAL": "critical",
            "UNKNOWN": "unverified",
            "NOT_CHECKED": "unverified",
            "NOT_AUTOMATED": "unverified",
        }
        for value, tone in expected.items():
            with self.subTest(value=value):
                self.assertEqual(mod._status_tone(value), tone)

    def test_22_unverified_states_never_get_healthy_color(self):
        html = mod.render_index(self.reports())
        self.assertIn('class="state healthy">HEALTHY</strong>', html)
        self.assertIn('class="state ready-local">READY_LOCAL</strong>', html)
        self.assertIn('class="state unverified">NOT_CHECKED</strong>', html)
        self.assertIn('class="state unverified">NOT_AUTOMATED</strong>', html)
        self.assertNotIn('class="state healthy">NOT_CHECKED', html)
        self.assertNotIn('class="state healthy">NOT_AUTOMATED', html)

    def test_23_warn_and_critical_use_distinct_styles(self):
        summary = mod._extract_summary(mock_report("2026-11-06"))
        summary["health"]["Motor de detección"] = "WARNING"
        summary["health"]["Cola de alertas"] = "CRITICAL"
        html = mod.render_index([("2026-11-06", "index.html", summary)])
        self.assertIn('class="state warning">WARNING</strong>', html)
        self.assertIn('class="state critical">CRITICAL</strong>', html)
        self.assertIn('.state.warning{color:#f6c26b}', html)
        self.assertIn('.state.critical{color:#ff8192}', html)

    def test_24_unknown_future_status_is_neutral(self):
        summary = mod._extract_summary(mock_report("2026-11-06"))
        summary["health"]["OAuth remoto"] = "FUTURE_CODE"
        html = mod.render_index([("2026-11-06", "index.html", summary)])
        self.assertIn('class="state unverified">FUTURE_CODE</strong>', html)

    def test_25_state_color_is_not_sole_indicator(self):
        html = mod.render_index(self.reports())
        # Status text remains visible; CSS only adds a supporting visual cue.
        self.assertIn("NOT_CHECKED</strong>", html)
        self.assertIn("NOT_AUTOMATED</strong>", html)
        self.assertIn("READY_LOCAL</strong>", html)
        self.assertNotIn("<script", html.lower())
        self.assertNotIn("https://", html)


if __name__ == "__main__":
    unittest.main()
