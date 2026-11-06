"""Tests for immutable, whitelisted SOC report snapshots."""
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import soc_snapshot_archive as mod

UTC_NOW = datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc)


def sample(date_str="2026-11-04"):
    return {
        "component": "powerbeam_soc_daily", "report_status": "READY",
        "inspection": "LOCAL_READ_ONLY", "report_date": date_str,
        "timezone": "Europe/Madrid", "emails_sent": 0, "tokens_modified": False,
        "activity": {"alerts_event_date": 1, "acknowledged_on_date": 0,
                     "alerts_by_rule": {"SOC-001": 0, "SOC-002": 1, "other": 0},
                     "alerts_by_severity": {"informational": 0, "low": 0,
                                            "medium": 1, "high": 0, "critical": 0}},
        "pending_now": {"total": 0, "by_severity": {
            "informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
            "oldest_event_age_minutes": None, "status": "HEALTHY"},
        "health": {"detection": "HEALTHY", "alert_queue": "HEALTHY",
                   "backlog": "HEALTHY", "oauth_local": "READY_LOCAL",
                   "oauth_remote": "NOT_CHECKED", "notification_delivery": "NOT_AUTOMATED"},
        "notes": ["source only V1"],
    }


class SnapshotArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="soc-report-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)
        os.chmod(self.parent, 0o700)
        self.folder = self.parent / "reports"

    def clean(self, data=None):
        return mod.minimize_report(sample() if data is None else data)

    def snapshot(self, data=None):
        return mod.build_snapshot(self.clean(data), now=UTC_NOW)

    def test_01_historical_date_explicit(self):
        s = self.snapshot()
        self.assertEqual(s["report_date"], "2026-11-04")
        self.assertEqual(s["snapshot_context"], "RETROSPECTIVE_ACTIVITY_WITH_CURRENT_STATE")

    def test_02_capture_time_is_current(self):
        self.assertEqual(self.snapshot()["captured_at_utc"], "2026-11-06T10:00:00Z")

    def test_03_current_day_marked_partial(self):
        s = self.snapshot(sample("2026-11-06"))
        self.assertEqual(s["snapshot_context"], "SAME_DAY_PARTIAL_ACTIVITY_WITH_CURRENT_STATE")

    def test_04_future_day_rejected(self):
        with self.assertRaises(mod.ArchiveError):
            self.snapshot(sample("2026-11-07"))

    def test_05_retrospective_uses_current_health(self):
        s = self.snapshot()
        self.assertIn("health_at_capture", s)
        self.assertNotIn("historical_health", s)

    def test_06_no_raw_extra_data(self):
        d = sample(); d.update(token="SHOULD_NOT_SAVE", source_ip="192.0.2.41", raw_alerts=[{"secret": "X"}])
        self.assertNotIn("SHOULD_NOT_SAVE", json.dumps(self.snapshot(d)))
        self.assertNotIn("192.0.2.41", json.dumps(self.snapshot(d)))

    def test_07_refuse_invalid_report_status(self):
        d = sample(); d["report_status"] = "UNKNOWN"
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_08_refuse_sent_emails(self):
        d = sample(); d["emails_sent"] = 1
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_09_refuse_changed_token(self):
        d = sample(); d["tokens_modified"] = True
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_10_refuse_wrong_component(self):
        d = sample(); d["component"] = "other"
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_11_refuse_wrong_timezone(self):
        d = sample(); d["timezone"] = "UTC"
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_12_refuse_inconsistent_rule_counts(self):
        d = sample(); d["activity"]["alerts_by_rule"]["SOC-001"] = 1
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_13_refuse_inconsistent_severity_counts(self):
        d = sample(); d["activity"]["alerts_by_severity"]["high"] = 3
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_14_refuse_inconsistent_pending_counts(self):
        d = sample(); d["pending_now"]["total"] = 1
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_15_refuse_bool_counts(self):
        d = sample(); d["activity"]["alerts_event_date"] = True
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_16_refuse_untrusted_health(self):
        d = sample(); d["health"]["oauth_local"] = "SECRET_TOKEN_VALUE"
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_17_refuse_backlog_mismatch(self):
        d = sample(); d["pending_now"]["status"] = "WARNING"
        with self.assertRaises(mod.ArchiveError): self.clean(d)

    def test_18_maximum_stdin_size(self):
        with self.assertRaises(mod.ArchiveError): mod._load_stdin(io.StringIO("X" * (mod.MAX_STDIN + 1)))

    def test_19_corrupt_json(self):
        with self.assertRaises(mod.ArchiveError): mod._load_stdin(io.StringIO("not json"))

    def test_20_valid_stdin(self):
        self.assertEqual(mod._load_stdin(io.StringIO(json.dumps(sample())))["report_date"], "2026-11-04")

    def test_21_save_immutable_json(self):
        name = mod.save_snapshot(self.snapshot(), self.folder, now=UTC_NOW)
        saved = json.loads((self.folder / name).read_text())
        self.assertEqual(saved["activity_by_event_date_v1"]["by_rule"]["SOC-002"], 1)
        self.assertEqual(saved["health_at_capture"]["detection"], "HEALTHY")
        self.assertEqual(saved["captured_at_utc"], "2026-11-06T10:00:00Z")

    def test_22_directory_and_file_permissions(self):
        name = mod.save_snapshot(self.snapshot(), self.folder, now=UTC_NOW)
        self.assertEqual(stat.S_IMODE(self.folder.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.folder / name).stat().st_mode), 0o600)

    def test_23_repeat_save_does_not_overwrite(self):
        a = mod.save_snapshot(self.snapshot(), self.folder, now=UTC_NOW)
        b = mod.save_snapshot(self.snapshot(), self.folder, now=UTC_NOW)
        self.assertNotEqual(a, b)
        self.assertEqual(len(list(self.folder.glob("*.json"))), 2)

    def test_24_no_partial_file(self):
        mod.save_snapshot(self.snapshot(), self.folder, now=UTC_NOW)
        self.assertEqual(len(list(self.folder.glob(".partial*"))), 0)

    def test_25_reject_symlink_archive_dir(self):
        real = self.parent / "real"
        real.mkdir(mode=0o700)
        self.folder.symlink_to(real, target_is_directory=True)
        with self.assertRaises(mod.ArchiveError): mod.save_snapshot(self.snapshot(), self.folder, now=UTC_NOW)

    def test_26_reject_world_traversable_dir(self):
        self.folder.mkdir(mode=0o700)
        self.folder.chmod(0o755)
        with self.assertRaises(mod.ArchiveError): mod.save_snapshot(self.snapshot(), self.folder, now=UTC_NOW)

    def test_27_list_only_sanitized_names(self):
        a = mod.save_snapshot(self.snapshot(), self.folder, now=UTC_NOW)
        (self.folder / "not-a-report.json").write_text("TOKEN")
        result = mod.list_snapshots(self.folder)
        self.assertEqual(result, [{"filename": a, "report_date": "2026-11-04"}])
        self.assertNotIn("TOKEN", json.dumps(result))

    def test_28_dry_run_no_archive_directory(self):
        with patch("sys.stdin", io.StringIO(json.dumps(sample()))), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            code = mod.main(["save", "--dir", str(self.folder), "--dry-run"])
        self.assertEqual(code, 0)
        self.assertFalse(self.folder.exists())
        self.assertFalse(json.loads(out.getvalue())["saved"])

    def test_29_cli_save_and_list(self):
        with patch("sys.stdin", io.StringIO(json.dumps(sample()))), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            code = mod.main(["save", "--dir", str(self.folder)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["action"], "save")
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            code = mod.main(["list", "--dir", str(self.folder)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["count"], 1)

    def test_30_cli_fail_closed_no_raw_echo(self):
        with patch("sys.stdin", io.StringIO('BAD SECRET 192.0.2.14')), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            code = mod.main(["save", "--dir", str(self.folder)])
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET", out.getvalue())
        self.assertFalse(self.folder.exists())

    def test_31_list_missing_directory(self):
        self.assertEqual(mod.list_snapshots(self.folder), [])

    def test_32_daily_report_v1_structure_compatibility(self):
        # Integration against the real aggregate and report builder from phase 6.
        import soc_daily_report
        import soc_daily_metrics
        from zoneinfo import ZoneInfo
        alerts = [{"alert_id": "SOC-002-ONE", "rule_id": "SOC-002",
                   "severity": "medium", "source_ip": "192.0.2.10",
                   "timestamp": "2026-11-04T11:00:00+01:00"}]
        state = {"schema_version": 1, "seen_alert_ids": ["SOC-002-ONE"], "pending": []}
        metrics = soc_daily_metrics.aggregate(
            alerts, state, report_date="2026-11-04",
            tz=ZoneInfo("Europe/Madrid"), now=UTC_NOW)
        validated = soc_daily_report.clean_daily_metrics(metrics)
        self.assertIsNotNone(validated)
        def infra(_token):
            return {"detection_status": "HEALTHY", "alert_queue_status": "HEALTHY",
                    "oauth_local": "READY_LOCAL"}
        report = soc_daily_report.build_report(validated, resilience_reader=infra)
        archived = self.snapshot(report)
        self.assertEqual(archived["activity_by_event_date_v1"]["alerts_total"], 1)
        self.assertEqual(archived["activity_by_event_date_v1"]["by_rule"]["SOC-002"], 1)
        self.assertEqual(archived["pending_at_capture"]["total"], 0)



if __name__ == "__main__":
    unittest.main()
