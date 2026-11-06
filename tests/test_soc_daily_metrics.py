"""Daily SOC metrics: private sources, aggregation, no writes or leakage."""
import io
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import soc_daily_metrics as mod

MADRID = ZoneInfo("Europe/Madrid")
NOW = datetime(2026, 11, 6, 11, 30, tzinfo=timezone.utc)
DAY = date(2026, 11, 6)


def event(aid, stamp="2026-11-06T08:00:00+01:00", severity="medium", rule="SOC-002"):
    return {"alert_id": aid, "rule_id": rule, "severity": severity,
            "source_ip": "192.0.2.10", "timestamp": stamp}


def state(alerts=None, ack=None):
    alerts = alerts or []
    seen = [a["alert_id"] for a in alerts]
    ack = ack or []
    seen.extend([a["alert_id"] for a in ack])
    return {"schema_version": 1, "seen_alert_ids": seen,
            "pending": alerts,
            "acknowledged": ack}


def acknowledge(aid, at="2026-11-06T08:30:00+01:00"):
    return {"alert_id": aid, "reason": "reviewed", "acknowledged_at": at}


class DailyMetricsTests(unittest.TestCase):
    def evaluate(self, alerts=None, st=None, day=DAY):
        return mod.aggregate(alerts or [], st or state(), report_date=day, tz=MADRID, now=NOW)

    def test_01_empty_day(self):
        r = self.evaluate()
        self.assertEqual(r["alerts_on_date"], 0)
        self.assertEqual(r["backlog"]["pending_total"], 0)

    def test_02_count_event_date_not_queue_date(self):
        a = event("A", "2026-11-05T23:30:00Z")  # 06 Nov local
        self.assertEqual(self.evaluate([a])["alerts_on_date"], 1)

    def test_03_exclude_previous_local_day(self):
        a = event("A", "2026-11-05T22:30:00Z")
        self.assertEqual(self.evaluate([a])["alerts_on_date"], 0)

    def test_04_filter_severity(self):
        a = [event("A", severity="high"), event("B", severity="low")]
        r = self.evaluate(a)
        self.assertEqual(r["alerts_by_severity"]["high"], 1)
        self.assertEqual(r["alerts_by_severity"]["low"], 1)
        self.assertEqual(r["alerts_on_date"], 2)

    def test_05_filter_rules(self):
        a = [event("A", rule="SOC-001"), event("B", rule="SOC-002"),
             event("C", rule="SOC-005")]
        r = self.evaluate(a)
        self.assertEqual(r["alerts_by_rule"], {"SOC-001": 1, "SOC-002": 1, "other": 1})

    def test_06_duplicate_same_alert_count_once(self):
        a = event("A")
        self.assertEqual(self.evaluate([a, a])["alerts_on_date"], 1)

    def test_07_conflicting_duplicate_rejected(self):
        with self.assertRaisesRegex(ValueError, "CONFLICTING_ALERT_ID"):
            self.evaluate([event("A"), event("A", severity="high")])

    def test_08_acknowledged_by_ack_date(self):
        ack = acknowledge("OLD", "2026-11-06T01:00:00+01:00")
        r = self.evaluate([], state(ack=[ack]))
        self.assertEqual(r["acknowledged_on_date"], 1)
        self.assertEqual(r["alerts_on_date"], 0)

    def test_09_ack_previous_day_not_counted(self):
        ack = acknowledge("OLD", "2026-11-05T23:00:00+01:00")
        self.assertEqual(self.evaluate([], state(ack=[ack]))["acknowledged_on_date"], 0)

    def test_10_pending_any_date_separate(self):
        old = event("OLD", "2026-11-04T09:00:00+01:00", "high")
        r = self.evaluate([], state(alerts=[old]))
        self.assertEqual(r["alerts_on_date"], 0)
        self.assertEqual(r["backlog"]["pending_total"], 1)

    def test_11_no_sensitive_data_in_report(self):
        a = event("SECRET-ALERT-42")
        r = self.evaluate([a], state(alerts=[a]))
        output = json.dumps(r)
        self.assertNotIn("SECRET-ALERT-42", output)
        self.assertNotIn("192.0.2.10", output)

    def test_12_invalid_date_rejected(self):
        for v in ("2026-11-31", "20261106", "2026-11-06X"):
            with self.subTest(v=v), self.assertRaises(ValueError):
                mod.parse_date(v)

    def test_13_invalid_state_rejected(self):
        with self.assertRaises(ValueError):
            self.evaluate([event("A")], {"schema_version": 9})

    def test_14_timestamp_with_dst_conversion(self):
        a = event("DST", "2026-03-29T22:30:00Z")  # 00:30 on 30 March in Madrid
        r = self.evaluate([a], day=date(2026, 3, 30))
        self.assertEqual(r["alerts_on_date"], 1)

    def test_15_default_today_uses_local_timezone(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, sp = Path(tmp)/"alerts.jsonl", Path(tmp)/"state.json"
            a = event("A")
            src.write_text(json.dumps(a) + "\n")
            sp.write_text(json.dumps(state()))
            # 23:30 UTC is next day in Madrid, so no alert for that day.
            r = mod.inspect(src, sp, now=datetime(2026, 11, 6, 23, 30, tzinfo=timezone.utc))
            self.assertEqual(r["report_date"], "2026-11-07")
            self.assertEqual(r["alerts_on_date"], 0)

    def test_16_files_unmodified_and_partial_tail_deferred(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, sp = Path(tmp)/"alerts.jsonl", Path(tmp)/"state.json"
            a = event("A")
            src.write_text(json.dumps(a) + "\n" + '{"incomplete": ')
            sp.write_text(json.dumps(state()))
            before = (src.read_bytes(), sp.read_bytes())
            r = mod.inspect(src, sp, now=NOW)
            self.assertEqual(r["alerts_on_date"], 1)
            self.assertEqual(before, (src.read_bytes(), sp.read_bytes()))

    def test_17_reject_source_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, link, sp = (Path(tmp)/name for name in ("alerts", "link", "state"))
            src.write_text("")
            link.symlink_to(src)
            sp.write_text(json.dumps(state()))
            with self.assertRaises(ValueError):
                mod.inspect(link, sp, now=NOW)

    def test_18_cli_failure_redacted(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = mod.main(["--alerts", "/does/not/exist/SECRET.log",
                           "--state", "/no/SECRET.json"])
        self.assertEqual(rc, 2)
        self.assertNotIn("SECRET", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
