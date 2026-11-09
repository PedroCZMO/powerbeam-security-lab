"""Offline tests for the privacy-preserving local SOC dashboard."""
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import soc_dashboard as mod

STAMP = datetime(2026, 11, 9, 11, 21, tzinfo=timezone.utc)


def sample():
    return {
        "component": "powerbeam_soc_daily",
        "report_status": "READY",
        "inspection": "LOCAL_READ_ONLY",
        "report_date": "2026-11-06",
        "timezone": "Europe/Madrid",
        "activity": {
            "alerts_event_date": 1,
            "alerts_by_rule": {"SOC-001": 1, "SOC-002": 0, "other": 0},
            "alerts_by_severity": {"informational": 0, "low": 0,
                                   "medium": 1, "high": 0, "critical": 0},
            "acknowledged_on_date": 1,
        },
        "pending_now": {
            "total": 0,
            "by_severity": {key: 0 for key in mod.SEVERITIES},
            "oldest_event_age_minutes": None,
            "status": "HEALTHY",
        },
        "health": {
            "detection": "HEALTHY", "alert_queue": "HEALTHY",
            "backlog": "HEALTHY", "oauth_local": "READY_LOCAL",
            "oauth_remote": "NOT_CHECKED",
            "notification_delivery": "NOT_AUTOMATED",
        },
        "emails_sent": 0, "tokens_modified": False,
        "notes": ["example"],
    }


class DashboardTests(unittest.TestCase):
    def test_01_valid_real_shape(self):
        data = mod.validate_report(sample())
        self.assertEqual((data["daily"], data["pending"], data["ack_on_date"]), (1, 0, 1))

    def test_02_local_offline_markup(self):
        html = mod.render_dashboard(sample(), generated_at=STAMP)
        self.assertIn("<!doctype html>", html)
        self.assertIn("2026-11-06", html)
        self.assertIn("SOC-001", html)
        self.assertIn("2026-11-09 11:21 UTC", html)
        self.assertIn("default-src 'none'", html)
        self.assertNotIn("<script", html.lower())
        self.assertNotIn("https://", html)

    def test_03_source_extra_secrets_not_rendered(self):
        r = sample()
        r["token"] = "SHOULD_NOT_LEAK"
        r["source_ip"] = "192.0.2.99"
        r["notes"] = ["PRIVATE_FULL_LOG_CONTENT"]
        html = mod.render_dashboard(r, generated_at=STAMP)
        for secret in ("SHOULD_NOT_LEAK", "192.0.2.99", "PRIVATE_FULL_LOG_CONTENT"):
            self.assertNotIn(secret, html)

    def test_04_reject_boolean_count(self):
        r = sample(); r["activity"]["alerts_event_date"] = True
        with self.assertRaises(mod.DashboardError):
            mod.validate_report(r)

    def test_05_reject_conflicting_totals(self):
        r = sample(); r["activity"]["alerts_by_rule"]["SOC-002"] = 1
        with self.assertRaises(mod.DashboardError):
            mod.validate_report(r)

    def test_06_reject_conflicting_severity(self):
        r = sample(); r["activity"]["alerts_by_severity"]["medium"] = 0
        with self.assertRaises(mod.DashboardError):
            mod.validate_report(r)

    def test_07_reject_conflicting_pending(self):
        r = sample(); r["pending_now"]["total"] = 1
        with self.assertRaises(mod.DashboardError):
            mod.validate_report(r)

    def test_08_reject_wrong_timezone(self):
        r = sample(); r["timezone"] = "UTC"
        with self.assertRaises(mod.DashboardError):
            mod.validate_report(r)

    def test_09_reject_missing_health_key(self):
        r = sample(); del r["health"]["detection"]
        with self.assertRaises(mod.DashboardError):
            mod.validate_report(r)

    def test_10_reject_untrusted_markup_in_health(self):
        r = sample(); r["health"]["detection"] = "<script>alert(1)</script>"
        with self.assertRaises(mod.DashboardError):
            mod.validate_report(r)

    def test_11_reject_non_ready_and_mutated_token(self):
        for key, value in (("report_status", "UNKNOWN"), ("tokens_modified", True),
                           ("emails_sent", 1), ("inspection", "WRITABLE")):
            with self.subTest(key=key):
                r = sample(); r[key] = value
                with self.assertRaises(mod.DashboardError):
                    mod.validate_report(r)

    def test_12_zero_alerts_renders(self):
        r = sample()
        r["activity"]["alerts_event_date"] = 0
        r["activity"]["alerts_by_rule"]["SOC-001"] = 0
        r["activity"]["alerts_by_severity"]["medium"] = 0
        self.assertIn("Por regla de detección", mod.render_dashboard(r, generated_at=STAMP))

    def test_13_ack_today_can_exceed_alerts_today(self):
        r = sample(); r["activity"]["acknowledged_on_date"] = 4
        self.assertEqual(mod.validate_report(r)["ack_on_date"], 4)

    def test_14_private_output_and_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            target = Path(directory) / "index.html"
            mod.save_private_html(target, "first")
            mod.save_private_html(target, "updated")
            self.assertEqual(target.read_text(), "updated")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_15_reject_world_readable_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            with self.assertRaises(mod.DashboardError):
                mod.save_private_html(Path(directory) / "index.html", "no")
            self.assertFalse((Path(directory) / "index.html").exists())

    def test_16_invalid_input_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            target = Path(directory) / "index.html"
            target.write_text("previous", encoding="utf-8")
            r = sample(); r["activity"]["alerts_event_date"] = -1
            with patch.object(sys, "stdin", io.StringIO(json.dumps(r))):
                with patch.object(sys, "stderr", new_callable=io.StringIO):
                    self.assertEqual(mod.main(["--output", str(target)]), 2)
            self.assertEqual(target.read_text(), "previous")

    def test_17_cli_success(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            target = Path(directory) / "index.html"
            with patch.object(sys, "stdin", io.StringIO(json.dumps(sample()))):
                with patch.object(sys, "stdout", new_callable=io.StringIO) as out:
                    self.assertEqual(mod.main(["--output", str(target)]), 0)
            self.assertIn('"status": "CREATED"', out.getvalue())
            self.assertIn("Security Operations Dashboard", target.read_text())

    def test_18_reject_excessive_input(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            target = Path(directory) / "index.html"
            with patch.object(sys, "stdin", io.StringIO("x" * (mod.MAX_INPUT + 1))):
                with patch.object(sys, "stderr", new_callable=io.StringIO):
                    self.assertEqual(mod.main(["--output", str(target)]), 2)
            self.assertFalse(target.exists())

    def test_19_reject_invalid_json_constant(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            target = Path(directory) / "index.html"
            with patch.object(sys, "stdin", io.StringIO('{"component":NaN}')):
                with patch.object(sys, "stderr", new_callable=io.StringIO):
                    self.assertEqual(mod.main(["--output", str(target)]), 2)

    def test_20_no_external_data_fields(self):
        r = sample()
        r["health"]["surprise"] = "EXTRA"
        html = mod.render_dashboard(r, generated_at=STAMP)
        self.assertNotIn("EXTRA", html)


if __name__ == "__main__":
    unittest.main()
