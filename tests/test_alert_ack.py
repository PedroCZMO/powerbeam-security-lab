"""Día 11, fase 5: acuse manual seguro; NO envía correos ni toca V1/V3."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import alert_queue as q


def alert(aid):
    return {"alert_id": aid, "rule_id": "SOC-002", "severity": "medium",
            "source_ip": "192.0.2.10", "timestamp": "2026-11-05T10:01:00+01:00"}


class AcknowledgementTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.source = self.dir / "alerts.jsonl"
        self.state = self.dir / "private" / "state.json"
        self.source.write_text(json.dumps(alert("HIST-001")) + "\n", encoding="utf-8")
        q.run("bootstrap", self.source, self.state)

    def enqueue(self, aid="NEW-001"):
        with self.source.open("a", encoding="utf-8") as f:
            f.write(json.dumps(alert(aid)) + "\n")
        q.run("scan", self.source, self.state)

    def acknowledge(self, aid="NEW-001", reason="reviewed"):
        return q.run("ack", self.source, self.state, alert_id=aid, reason=reason)

    def test_status_existing_state_compatible(self):
        st = q.run("status", self.source, self.state)
        self.assertEqual(st["acknowledged"], 0)
        self.assertEqual(st["pending"], 0)

    def test_ack_removes_one_pending(self):
        self.enqueue("NEW-001")
        self.enqueue("NEW-002")
        r = self.acknowledge()
        self.assertEqual((r["pending"], r["acknowledged"]), (1, 1))
        self.assertEqual(q.run("status", self.source, self.state)["pending_alerts"][0]["alert_id"], "NEW-002")

    def test_ack_persists_reason_time_and_id(self):
        self.enqueue()
        self.acknowledge(reason="delivered")
        content = q.read_state(self.state)
        record = content["acknowledged"][0]
        self.assertEqual(set(record), {"alert_id", "reason", "acknowledged_at"})
        self.assertEqual((record["alert_id"], record["reason"]), ("NEW-001", "delivered"))
        self.assertEqual(q.run("status", self.source, self.state)["pending"], 0)

    def test_second_ack_fails_without_changes(self):
        self.enqueue()
        self.acknowledge()
        before = self.state.read_bytes()
        with self.assertRaisesRegex(ValueError, "no está pendiente"):
            self.acknowledge()
        self.assertEqual(self.state.read_bytes(), before)

    def test_ack_historical_is_refused(self):
        before = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.acknowledge("HIST-001")
        self.assertEqual(self.state.read_bytes(), before)

    def test_ack_unknown_fails(self):
        with self.assertRaises(ValueError):
            self.acknowledge("UNKNOWN-001")

    def test_requires_valid_reason(self):
        self.enqueue()
        with self.assertRaises(ValueError):
            self.acknowledge(reason=None)
        with self.assertRaises(ValueError):
            self.acknowledge(reason="sent-ish")
        self.assertEqual(q.run("status", self.source, self.state)["pending"], 1)

    def test_requires_valid_id(self):
        self.enqueue()
        with self.assertRaises(ValueError):
            q.run("ack", self.source, self.state, alert_id="bad\nID", reason="reviewed")
        with self.assertRaises(ValueError):
            q.run("ack", self.source, self.state, alert_id=None, reason="reviewed")

    def test_source_unchanged(self):
        self.enqueue()
        previous = self.source.read_bytes()
        self.acknowledge()
        self.assertEqual(self.source.read_bytes(), previous)

    def test_repeated_scan_does_not_requeue_ack(self):
        self.enqueue()
        self.acknowledge()
        self.assertEqual(q.run("scan", self.source, self.state)["new_queued"], 0)
        self.assertEqual(q.run("status", self.source, self.state)["pending"], 0)

    def test_corrupt_ack_history_blocks_all_without_overwrite(self):
        self.enqueue()
        state = json.loads(self.state.read_text())
        state["acknowledged"] = [{"alert_id": "NEW-001", "reason": "reviewed", "acknowledged_at": "2026-11-05T10:00:00+00:00"}]
        self.state.write_text(json.dumps(state))
        previous = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.acknowledge()
        self.assertEqual(self.state.read_bytes(), previous)

    def test_cli_requires_ack_flags(self):
        self.enqueue()
        with redirect_stderr(io.StringIO()):
            code = q.main(["ack", "--source", str(self.source), "--state", str(self.state)])
        self.assertEqual(code, 1)

    def test_cli_ack_success(self):
        self.enqueue()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = q.main(["ack", "--source", str(self.source), "--state", str(self.state),
                           "--alert-id", "NEW-001", "--reason", "reviewed"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buf.getvalue())["pending"], 0)

    def test_ack_no_source_access_needed(self):
        self.enqueue()
        self.source.unlink()
        self.assertEqual(self.acknowledge()["pending"], 0)

    def test_ack_schema_errors_detected(self):
        self.enqueue()
        self.acknowledge()
        state = json.loads(self.state.read_text())
        state["acknowledged"][0]["reason"] = "invalid"
        self.state.write_text(json.dumps(state))
        with self.assertRaises(ValueError):
            q.run("status", self.source, self.state)


if __name__ == "__main__":
    unittest.main()
