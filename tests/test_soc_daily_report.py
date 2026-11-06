"""Presentation under regular user, validation of aggregate-only trust boundary."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import soc_daily_metrics
import soc_daily_report as mod

NOW = datetime(2026, 11, 6, 11, 30, tzinfo=timezone.utc)


def safe_metrics():
    return soc_daily_metrics.aggregate(
        [], {"schema_version": 1, "seen_alert_ids": ["IGNORED"], "pending": []},
        report_date="2026-11-06", tz=ZoneInfo("Europe/Madrid"), now=NOW)


def fake_infra(_token):
    return {"detection_status": "HEALTHY", "alert_queue_status": "HEALTHY",
            "oauth_local": "READY_LOCAL", "remote_authorization": "ACCEPTED"}


class DailyReportTests(unittest.TestCase):
    def test_01_valid_input(self):
        self.assertEqual(mod.clean_daily_metrics(safe_metrics())["alerts_on_date"], 0)

    def test_02_missing_source_contract(self):
        data = safe_metrics(); data["source_scope"] = "V3_ONLY"
        self.assertIsNone(mod.clean_daily_metrics(data))

    def test_03_bad_count_not_accepted(self):
        data = safe_metrics(); data["alerts_on_date"] = 1
        self.assertIsNone(mod.clean_daily_metrics(data))

    def test_04_boolean_count_rejected(self):
        data = safe_metrics(); data["alerts_by_rule"]["SOC-001"] = True
        self.assertIsNone(mod.clean_daily_metrics(data))

    def test_05_untrusted_backlog_rejected(self):
        data = safe_metrics(); data["backlog"]["pending_total"] = 3
        self.assertIsNone(mod.clean_daily_metrics(data))

    def test_06_bad_ack_count_rejected(self):
        data = safe_metrics(); data["acknowledged_on_date"] = 3
        self.assertIsNone(mod.clean_daily_metrics(data))

    def test_07_bad_generated_at(self):
        data = safe_metrics(); data["generated_at"] = "not-a-date"
        self.assertIsNone(mod.clean_daily_metrics(data))

    def test_08_extra_secrets_stripped(self):
        data = safe_metrics()
        data["token"] = "SUPER_SECRET"
        data["source_ip"] = "192.0.2.21"
        cleaned = mod.clean_daily_metrics(data)
        self.assertNotIn("SECRET", json.dumps(cleaned))
        self.assertNotIn("192.0.2.21", json.dumps(cleaned))

    def test_09_empty_stdin_unknown(self):
        self.assertIsNone(mod.read_daily_stdin(io.StringIO("")))

    def test_10_large_stdin_unknown(self):
        self.assertIsNone(mod.read_daily_stdin(io.StringIO("X" * (mod.MAX_STDIN_BYTES+3))))

    def test_11_report_separate_health(self):
        report = mod.build_report(mod.clean_daily_metrics(safe_metrics()),
                                  resilience_reader=fake_infra)
        self.assertEqual(report["health"]["detection"], "HEALTHY")
        self.assertEqual(report["health"]["notification_delivery"], "NOT_AUTOMATED")
        self.assertEqual(report["pending_now"]["total"], 0)

    def test_12_text_contains_real_distinctions(self):
        report = mod.build_report(mod.clean_daily_metrics(safe_metrics()),
                                  resilience_reader=fake_infra)
        text = mod.as_text(report)
        self.assertIn("SOC-001", text)
        self.assertIn("TODAS LAS FECHAS", text)
        self.assertIn("NOT_AUTOMATED", text)

    def test_13_fail_closed_on_missing_metrics(self):
        report = mod.build_report(None)
        self.assertEqual(report["report_status"], "UNKNOWN")
        self.assertNotIn("HEALTHY", mod.as_text(report))

    def test_14_no_raw_info_ever_emitted(self):
        data = safe_metrics(); data["raw_alerts"] = [{"source_ip": "192.0.2.32", "alert_id": "PRIVATE-001"}]
        m = mod.clean_daily_metrics(data)
        result = mod.build_report(m, resilience_reader=fake_infra, token="/token/PRIVATE")
        out = mod.as_text(result) + json.dumps(result)
        self.assertNotIn("192.0.2.32", out)
        self.assertNotIn("PRIVATE-001", out)
        self.assertNotIn("/token/PRIVATE", out)

    def test_15_cli_json_with_mocked_services(self):
        data = json.dumps(safe_metrics())
        report = mod.build_report(mod.clean_daily_metrics(safe_metrics()), resilience_reader=fake_infra)
        with patch("sys.stdin", io.StringIO(data)), \
             patch("soc_daily_report.build_report", return_value=report), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            code = mod.main(["--daily-stdin", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["report_status"], "READY")

    def test_16_cli_reject_invalid_payload(self):
        with patch("sys.stdin", io.StringIO("malformed SECRET")), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            code = mod.main(["--daily-stdin"])
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET", out.getvalue())


if __name__ == "__main__":
    unittest.main()
