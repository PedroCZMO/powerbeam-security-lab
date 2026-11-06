"""Read-only backlog health tests with isolated state files, no network/systemd."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import alert_backlog_health as mod

NOW = datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc)


def alert(name, severity="medium", age_min=0, *, now=NOW):
    return {
        "alert_id": name, "rule_id": "SOC-001", "severity": severity,
        "source_ip": "192.0.2.11",
        "timestamp": (now - timedelta(minutes=age_min)).isoformat(),
    }


def state(*pending, ack=(), older_ids=()):
    seen = list(older_ids) + [a["alert_id"] for a in pending] + list(ack)
    out = {"schema_version": 1, "seen_alert_ids": seen, "pending": list(pending)}
    if ack:
        out["acknowledged"] = [{"alert_id": a, "reason": "reviewed",
                                "acknowledged_at": NOW.isoformat()} for a in ack]
    return out


class AlertBacklogHealthTests(unittest.TestCase):
    def check(self, obj, **kw):
        return mod.evaluate(obj, now=NOW, **kw)

    def test_empty_healthy(self):
        r = self.check(state(older_ids=("OLD",)))
        self.assertEqual((r["operational_status"], r["pending_total"]), ("HEALTHY", 0))

    def test_empty_oldest_null(self):
        r = self.check(state())
        self.assertIsNone(r["oldest_event_timestamp"])
        self.assertIsNone(r["oldest_event_age_minutes"])

    def test_recent_medium_healthy(self):
        self.assertEqual(self.check(state(alert("A", age_min=59)))["operational_status"], "HEALTHY")

    def test_medium_warning_exact_60(self):
        self.assertEqual(self.check(state(alert("A", age_min=60)))["status_reason"], "PENDING_EVENT_TOO_OLD")

    def test_recent_high_healthy(self):
        self.assertEqual(self.check(state(alert("A", "high", 29)))["operational_status"], "HEALTHY")

    def test_high_warning_exact_30(self):
        self.assertEqual(self.check(state(alert("A", "high", 30)))["status_reason"], "HIGH_PENDING_TOO_OLD")

    def test_critical_age_exact_four_hours(self):
        self.assertEqual(self.check(state(alert("A", age_min=240)))["status_reason"], "MAX_EVENT_AGE_EXCEEDED")

    def test_not_critical_at_239(self):
        self.assertEqual(self.check(state(alert("A", age_min=239)))["operational_status"], "WARNING")

    def test_critical_severity_immediate(self):
        self.assertEqual(self.check(state(alert("A", "critical", 1)))["status_reason"], "CRITICAL_SEVERITY_PENDING")

    def test_critical_priority_over_age(self):
        self.assertEqual(self.check(state(alert("A", "critical", 300)))["operational_status"], "CRITICAL")

    def test_severity_counts(self):
        alerts = [alert(str(i), s) for i, s in enumerate(mod.SEVERITIES)]
        self.assertEqual(list(self.check(state(*alerts))["pending_by_severity"].values()), [1] * 5)

    def test_oldest_not_first(self):
        r = self.check(state(alert("A", age_min=2), alert("B", age_min=90), alert("C", age_min=30)))
        self.assertEqual(r["oldest_event_age_minutes"], 90)

    def test_seen_counts(self):
        r = self.check(state(alert("A"), older_ids=("HIST",)))
        self.assertEqual(r["seen_total"], 2)

    def test_ack_not_pending(self):
        r = self.check(state(ack=("DONE",)))
        self.assertEqual((r["pending_total"], r["acknowledged_total"]), (0, 1))

    def test_future_timestamp_warning(self):
        r = self.check(state(alert("A", age_min=-3)))
        self.assertEqual((r["status_reason"], r["future_event_timestamp_count"]),
                         ("FUTURE_EVENT_TIMESTAMP", 1))

    def test_clock_skew_under_one_minute(self):
        r = self.check(state(alert("A", age_min=-0.5)))
        self.assertEqual((r["operational_status"], r["oldest_event_age_minutes"]), ("HEALTHY", 0))

    def test_future_plus_old_keeps_age_warning(self):
        r = self.check(state(alert("A", age_min=-3), alert("B", age_min=61)))
        self.assertEqual(r["operational_status"], "WARNING")

    def test_custom_high_policy(self):
        r = self.check(state(alert("A", "high", 12)), high_warning_min=10)
        self.assertEqual(r["operational_status"], "WARNING")

    def test_custom_any_policy(self):
        r = self.check(state(alert("A", age_min=15)), any_warning_min=10)
        self.assertEqual(r["status_reason"], "PENDING_EVENT_TOO_OLD")

    def test_custom_critical_policy(self):
        r = self.check(state(alert("A", age_min=35)), high_warning_min=5, any_warning_min=10, any_critical_min=30)
        self.assertEqual(r["operational_status"], "CRITICAL")

    def test_invalid_policy_zero(self):
        with self.assertRaises(ValueError):
            self.check(state(), high_warning_min=0)

    def test_invalid_policy_order(self):
        with self.assertRaises(ValueError):
            self.check(state(), any_warning_min=300)

    def test_naive_now_rejected(self):
        with self.assertRaises(ValueError):
            mod.evaluate(state(), now=datetime(2026, 11, 6))

    def test_source_evidence_not_present_in_report(self):
        r = self.check(state(alert("SECRET_ALERT_ID")))
        raw = json.dumps(r)
        self.assertNotIn("SECRET_ALERT_ID", raw)
        self.assertNotIn("192.0.2.11", raw)

    def test_timezone_offset(self):
        a = alert("A", age_min=60)
        a["timestamp"] = "2026-11-06T11:00:00+02:00"
        self.assertEqual(self.check(state(a))["oldest_event_age_minutes"], 60)

    def test_does_not_modify_state_object(self):
        data = state(alert("A"))
        before = json.dumps(data, sort_keys=True)
        self.check(data)
        self.assertEqual(json.dumps(data, sort_keys=True), before)

    def test_does_not_modify_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            raw = json.dumps(state(alert("A")), sort_keys=True).encode()
            path.write_bytes(raw)
            mod.inspect(path, now=NOW)
            self.assertEqual(raw, path.read_bytes())
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "real.json"
            p.write_text(json.dumps(state()))
            l = Path(directory) / "sym.json"
            l.symlink_to(p)
            with self.assertRaises(ValueError):
                mod.inspect(l)

    def test_corrupt_schema_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "state.json"
            p.write_text('{"schema_version": 99}')
            with self.assertRaises(ValueError):
                mod.inspect(p)

    def test_cli_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "state.json"
            p.write_text(json.dumps(state()))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = mod.main(["--state", str(p)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["operational_status"], "HEALTHY")

    def test_cli_warning_return_one(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "state.json"
            p.write_text(json.dumps(state(alert("A", "medium", 0, now=datetime.now(timezone.utc) - timedelta(minutes=61)))))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = mod.main(["--state", str(p)])
            self.assertEqual(code, 1)

    def test_cli_missing_state_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "PRIVATE_TOKEN_SHOULD_NOT_PRINT.json"
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = mod.main(["--state", str(p)])
            self.assertEqual(code, 2)
            self.assertNotIn(p.name, out.getvalue())


if __name__ == "__main__":
    unittest.main()
