"""Day 11 phase 1 - no network, no real filesystem interactions."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
import io

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import alert_queue as q


def alert(aid="SOC-002-abcdef123456", rule="SOC-002", **kwargs):
    item = {"alert_id": aid, "rule_id": rule, "severity": "medium",
            "source_ip": "192.0.2.10", "timestamp": "2026-11-04T11:00:25+01:00",
            "description": "will NOT be persisted"}
    item.update(kwargs)
    return item


class AlertQueueTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "alerts.jsonl"
        self.state = self.root / "private" / "notification-state.json"
        self.source.write_text(json.dumps(alert()) + "\n", encoding="utf-8")

    def add(self, obj, complete=True):
        with self.source.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj) + ("\n" if complete else ""))

    def run_bootstrap(self):
        return q.run("bootstrap", self.source, self.state)

    def test_bootstrap_does_not_queue_historical_alert(self):
        out = self.run_bootstrap()
        self.assertEqual(out["historical_ignored"], 1)
        self.assertEqual(q.run("status", self.source, self.state)["pending"], 0)

    def test_new_alert_is_queued(self):
        self.run_bootstrap()
        self.add(alert("SOC-001-new", "SOC-001"))
        r = q.run("scan", self.source, self.state)
        self.assertEqual((r["new_queued"], r["pending"]), (1, 1))
        self.assertEqual(r["new_alerts"][0]["rule_id"], "SOC-001")

    def test_second_scan_is_idempotent(self):
        self.run_bootstrap()
        self.add(alert("SOC-002-new"))
        q.run("scan", self.source, self.state)
        self.assertEqual(q.run("scan", self.source, self.state)["new_queued"], 0)
        self.assertEqual(q.run("status", self.source, self.state)["pending"], 1)

    def test_duplicate_in_input(self):
        self.run_bootstrap()
        self.add(alert("SOC-002-new"))
        self.add(alert("SOC-002-new"))
        self.assertEqual(q.run("scan", self.source, self.state)["new_queued"], 1)

    def test_bootstrap_refuses_reset(self):
        self.run_bootstrap()
        with self.assertRaises(FileExistsError):
            self.run_bootstrap()

    def test_scan_requires_bootstrap(self):
        with self.assertRaises(FileNotFoundError):
            q.run("scan", self.source, self.state)

    def test_corrupt_jsonl_fails_without_state_change(self):
        self.run_bootstrap()
        before = self.state.read_bytes()
        with self.source.open("ab") as f:
            f.write(b"{broken}\n")
        with self.assertRaises(ValueError):
            q.run("scan", self.source, self.state)
        self.assertEqual(self.state.read_bytes(), before)

    def test_partial_tail_is_deferred(self):
        self.run_bootstrap()
        self.add(alert("SOC-002-new"), complete=False)
        self.assertEqual(q.run("scan", self.source, self.state)["new_queued"], 0)
        with self.source.open("a", encoding="utf-8") as f:
            f.write("\n")
        self.assertEqual(q.run("scan", self.source, self.state)["new_queued"], 1)

    def test_invalid_alert_id(self):
        with self.assertRaises(ValueError):
            q.normalize_alert(alert("SOC-002-\nmal"), 1)

    def test_invalid_source_ip(self):
        with self.assertRaises(ValueError):
            q.normalize_alert(alert(source_ip="not-an-ip"), 1)

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            q.normalize_alert(alert(timestamp="2026-11-04T11:00:25"), 1)

    def test_description_not_persisted(self):
        self.run_bootstrap()
        self.add(alert("SOC-002-new", description="PRIVATE DATA"))
        q.run("scan", self.source, self.state)
        self.assertNotIn("PRIVATE DATA", self.state.read_text())

    def test_permissions_state_and_lock(self):
        self.run_bootstrap()
        if os.name == "posix":
            self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.state.parent / (self.state.name + ".lock")).stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.state.parent.stat().st_mode & 0o777, 0o700)

    def test_source_not_modified(self):
        before = self.source.read_bytes()
        self.run_bootstrap()
        q.run("scan", self.source, self.state)
        self.assertEqual(before, self.source.read_bytes())

    def test_bad_state_fails_safely(self):
        self.run_bootstrap()
        self.state.write_text("{garbled", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            q.run("scan", self.source, self.state)

    def test_status_no_source_read(self):
        self.run_bootstrap()
        self.source.unlink()
        self.assertEqual(q.run("status", self.source, self.state)["pending"], 0)

    def test_no_status_or_scan_reinitializes_state(self):
        self.run_bootstrap()
        first = self.state.read_bytes()
        q.run("scan", self.source, self.state)
        q.run("status", self.source, self.state)
        self.assertEqual(first, self.state.read_bytes())

    def test_source_and_state_must_differ(self):
        with self.assertRaises(ValueError):
            q.run("bootstrap", self.source, self.source)

    def test_cli_reports_json_success(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(q.main(["bootstrap", "--source", str(self.source), "--state", str(self.state)]), 0)

    def test_cli_reports_error(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(q.main(["scan", "--source", str(self.source), "--state", str(self.state)]), 1)
