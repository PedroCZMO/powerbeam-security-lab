"""40 regression tests for PowerBeam Phase 8: private SOC V1 archive trends."""
import copy
from datetime import date, datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import soc_snapshot_archive as archive
import soc_trends as trends

UTC_NOW = datetime(2026, 11, 6, 11, 0, tzinfo=timezone.utc)


def raw_daily(day, total=0, soc001=0, soc002=None, acknowledgements=0):
    soc002 = total - soc001 if soc002 is None else soc002
    other = total - soc001 - soc002
    return {
        "component": "powerbeam_soc_daily", "report_status": "READY",
        "inspection": "LOCAL_READ_ONLY", "report_date": day,
        "timezone": "Europe/Madrid", "emails_sent": 0, "tokens_modified": False,
        "activity": {"alerts_event_date": total, "acknowledged_on_date": acknowledgements,
                     "alerts_by_rule": {"SOC-001": soc001, "SOC-002": soc002, "other": other},
                     "alerts_by_severity": {"informational": 0, "low": 0,
                                            "medium": total, "high": 0, "critical": 0}},
        "pending_now": {"total": 0, "by_severity": {
            "informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
            "oldest_event_age_minutes": None, "status": "HEALTHY"},
        "health": {"detection": "HEALTHY", "alert_queue": "HEALTHY",
                   "backlog": "HEALTHY", "oauth_local": "READY_LOCAL",
                   "oauth_remote": "NOT_CHECKED", "notification_delivery": "NOT_AUTOMATED"},
    }


def snapshot(day, total=0, *, at=UTC_NOW, soc001=0, ack=0):
    return archive.build_snapshot(
        archive.minimize_report(raw_daily(day, total, soc001=soc001,
                                          acknowledgements=ack)), now=at)


class SocTrendsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="pb-trends-")
        self.addCleanup(tmp.cleanup)
        self.parent = Path(tmp.name)
        self.parent.chmod(0o700)
        self.directory = self.parent / "reports"
        self.start = date(2026, 11, 4)
        self.end = date(2026, 11, 5)

    def add(self, day, total=0, *, at=UTC_NOW, soc001=0, ack=0):
        s = snapshot(day, total, at=at, soc001=soc001, ack=ack)
        return archive.save_snapshot(s, self.directory, now=at)

    def run_compare(self, start=None, end=None, now=UTC_NOW):
        start = start or self.start
        end = end or self.end
        return trends.compare(trends.read_archive(self.directory, start, end),
                              start=start, end=end, now=now)

    def test_01_two_historical_days_complete(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        result = self.run_compare()
        self.assertEqual(result["coverage_status"], "COMPLETE_SNAPSHOTS")

    def test_02_real_soc002_case_rule_counts(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        self.assertEqual(self.run_compare()["days"][0]["by_rule"]["SOC-002"], 1)

    def test_03_genuine_zero_not_missing(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        row = self.run_compare()["days"][1]
        self.assertEqual((row["status"], row["alerts_total"]), ("RECORDED", 0))

    def test_04_missing_day_is_null_not_zero(self):
        self.add("2026-11-04", 1)
        row = self.run_compare()["days"][1]
        self.assertEqual(row["status"], "MISSING_SNAPSHOT")
        self.assertIsNone(row["alerts_total"])

    def test_05_missing_day_incomplete_and_period_null(self):
        self.add("2026-11-04", 1)
        report = self.run_compare()
        self.assertEqual(report["coverage_status"], "INCOMPLETE_SNAPSHOTS")
        self.assertIsNone(report["period_total_alerts"])

    def test_06_complete_period_sum(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 4)
        self.assertEqual(self.run_compare()["period_total_alerts"], 5)

    def test_07_increase_absolute(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 4)
        row = self.run_compare()["days"][1]
        self.assertEqual((row["trend"], row["change_from_previous_day"]), ("INCREASE", 3))

    def test_08_decrease_absolute(self):
        self.add("2026-11-04", 5)
        self.add("2026-11-05", 2)
        row = self.run_compare()["days"][1]
        self.assertEqual((row["trend"], row["change_from_previous_day"]), ("DECREASE", -3))

    def test_09_unchanged(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 1)
        self.assertEqual(self.run_compare()["days"][1]["trend"], "UNCHANGED")

    def test_10_zero_baseline_percentage_is_undefined(self):
        self.add("2026-11-04", 0)
        self.add("2026-11-05", 1)
        row = self.run_compare()["days"][1]
        self.assertIsNone(row["change_percent"])
        self.assertEqual(row["change_from_previous_day"], 1)

    def test_11_nonzero_baseline_percentage(self):
        self.add("2026-11-04", 4)
        self.add("2026-11-05", 2)
        self.assertEqual(self.run_compare()["days"][1]["change_percent"], -50.0)

    def test_12_missing_day_change_not_comparable(self):
        self.add("2026-11-05", 2)
        row = self.run_compare()["days"][1]
        self.assertEqual(row["trend"], "NOT_COMPARABLE")
        self.assertIsNone(row["change_from_previous_day"])

    def test_13_peak_with_tied_days(self):
        self.add("2026-11-04", 3)
        self.add("2026-11-05", 3)
        result = self.run_compare()
        self.assertEqual(result["peak_days_recorded"], ["2026-11-04", "2026-11-05"])

    def test_14_soc001_counts_preserved(self):
        self.add("2026-11-04", 4, soc001=3)
        self.add("2026-11-05", 0)
        self.assertEqual(self.run_compare()["days"][0]["by_rule"]["SOC-001"], 3)

    def test_15_severity_counts_preserved(self):
        self.add("2026-11-04", 4)
        self.add("2026-11-05", 0)
        self.assertEqual(self.run_compare()["days"][0]["by_severity"]["medium"], 4)

    def test_16_acknowledgement_count_preserved(self):
        self.add("2026-11-04", 1, ack=1)
        self.add("2026-11-05", 0)
        self.assertEqual(self.run_compare()["days"][0]["acknowledged_on_date"], 1)

    def test_17_later_snapshot_selected(self):
        old = UTC_NOW - timedelta(minutes=10)
        self.add("2026-11-04", 1, at=old)
        self.add("2026-11-04", 2, at=UTC_NOW)
        self.add("2026-11-05", 0)
        self.assertEqual(self.run_compare()["days"][0]["alerts_total"], 2)

    def test_18_changed_snapshot_marks_revision(self):
        self.add("2026-11-04", 1, at=UTC_NOW - timedelta(seconds=5))
        self.add("2026-11-04", 2, at=UTC_NOW)
        self.add("2026-11-05", 0)
        row = self.run_compare()["days"][0]
        self.assertTrue(row["revisions_detected"])
        self.assertEqual(row["snapshot_count"], 2)

    def test_19_equal_snapshot_no_revision(self):
        self.add("2026-11-04", 1, at=UTC_NOW - timedelta(minutes=2))
        self.add("2026-11-04", 1, at=UTC_NOW)
        self.add("2026-11-05", 0)
        self.assertFalse(self.run_compare()["days"][0]["revisions_detected"])

    def test_20_same_day_snapshot_partial(self):
        self.add("2026-11-05", 2, at=datetime(2026, 11, 5, 11, tzinfo=timezone.utc))
        self.add("2026-11-04", 1)
        result = self.run_compare()
        self.assertEqual(result["days"][1]["status"], "PARTIAL_AT_CAPTURE")
        self.assertIsNone(result["period_total_alerts"])

    def test_21_next_day_retrospective_complete(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 2)
        self.assertEqual(self.run_compare()["days"][1]["status"], "RECORDED")

    def test_22_health_not_relabelled_as_historical(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        self.assertNotIn("health_at_capture", json.dumps(self.run_compare()))

    def test_23_pending_not_mixed_into_trends(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        self.assertNotIn("pending_at_capture", json.dumps(self.run_compare()))

    def test_24_extra_secret_in_snapshot_never_emitted(self):
        name = self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        path = self.directory / name
        doc = json.loads(path.read_text())
        doc["secret"] = "SENSITIVE_TOKEN_192.0.2.44"
        path.write_text(json.dumps(doc))
        self.assertNotIn("SENSITIVE_TOKEN", json.dumps(self.run_compare()))

    def test_25_filename_capture_timestamp_mismatch(self):
        name = self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        path = self.directory / name
        doc = json.loads(path.read_text())
        doc["captured_at_utc"] = "2026-11-06T10:00:00Z"
        path.write_text(json.dumps(doc))
        with self.assertRaises(trends.TrendsError): self.run_compare()

    def test_26_wrong_snapshot_component(self):
        name = self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        path = self.directory / name
        doc = json.loads(path.read_text()); doc["component"] = "other"
        path.write_text(json.dumps(doc))
        with self.assertRaises(trends.TrendsError): self.run_compare()

    def test_27_inconsistent_counts_rejected(self):
        name = self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        path = self.directory / name
        doc = json.loads(path.read_text()); doc["activity_by_event_date_v1"]["alerts_total"] = 2
        path.write_text(json.dumps(doc))
        with self.assertRaises(trends.TrendsError): self.run_compare()

    def test_28_invalid_context_rejected(self):
        name = self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        path = self.directory / name
        doc = json.loads(path.read_text())
        doc["snapshot_context"] = "SAME_DAY_PARTIAL_ACTIVITY_WITH_CURRENT_STATE"
        path.write_text(json.dumps(doc))
        with self.assertRaises(trends.TrendsError): self.run_compare()

    def test_29_symlink_snapshot_rejected(self):
        name = self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        path = self.directory / name
        elsewhere = self.parent / "source.json"
        path.rename(elsewhere)
        path.symlink_to(elsewhere)
        with self.assertRaises(trends.TrendsError): self.run_compare()

    def test_30_group_readable_snapshot_rejected(self):
        name = self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        (self.directory / name).chmod(0o640)
        with self.assertRaises(trends.TrendsError): self.run_compare()

    def test_31_corrupt_json_rejected(self):
        name = self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        (self.directory / name).write_text("{corrupt 192.0.2.12 token}")
        with self.assertRaises(trends.TrendsError): self.run_compare()

    def test_32_oversized_snapshot_rejected(self):
        name = self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        (self.directory / name).write_text("A" * (trends.MAX_FILE_BYTES + 2))
        with self.assertRaises(trends.TrendsError): self.run_compare()

    def test_33_symlink_archive_directory_rejected(self):
        outside = self.parent / "actual"
        outside.mkdir(mode=0o700)
        self.directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(trends.TrendsError): self.run_compare()

    def test_34_missing_archive_returns_empty_not_zero(self):
        result = self.run_compare()
        self.assertEqual(result["days_missing"], 2)
        self.assertIsNone(result["period_total_alerts"])

    def test_35_cli_json_two_days(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            code = trends.main(["--start", "2026-11-04", "--end", "2026-11-05",
                                "--dir", str(self.directory), "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["period_total_alerts"], 1)

    def test_36_cli_text_zero_is_not_missing(self):
        self.add("2026-11-04", 1)
        self.add("2026-11-05", 0)
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            code = trends.main(["--start", "2026-11-04", "--end", "2026-11-05",
                                "--dir", str(self.directory)])
        self.assertEqual(code, 0)
        self.assertIn("2026-11-05", output.getvalue())
        self.assertIn("Cero alertas no demuestra", output.getvalue())

    def test_37_cli_invalid_day_redacted(self):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            code = trends.main(["--start", "BAD_PRIVATE_TOKEN", "--end", "2026-11-05",
                                "--dir", str(self.directory)])
        self.assertEqual(code, 2)
        self.assertNotIn("BAD_PRIVATE_TOKEN", output.getvalue())

    def test_38_cli_future_period_rejected(self):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            code = trends.main(["--start", "2099-01-01", "--end", "2099-01-02",
                                "--dir", str(self.directory)])
        self.assertEqual(code, 2)
        self.assertIn("FUTURE_DATE_RANGE", output.getvalue())

    def test_39_cli_invalid_archive_does_not_echo_secrets(self):
        self.add("2026-11-04", 1)
        name = self.add("2026-11-05", 0)
        (self.directory / name).write_text('SECRET_IP_192.0.2.10')
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            code = trends.main(["--start", "2026-11-04", "--end", "2026-11-05",
                                "--dir", str(self.directory)])
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET_IP", output.getvalue())
        self.assertNotIn(str(self.directory), output.getvalue())

    def test_40_range_cap(self):
        with self.assertRaises(trends.TrendsError):
            trends.compare([], start="2026-01-01", end="2026-02-03", now=UTC_NOW)


if __name__ == "__main__":
    unittest.main()
