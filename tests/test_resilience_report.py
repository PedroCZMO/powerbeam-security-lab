import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import resilience_report as mod

NOW = 4_000_000_000


def props(unit, *, active=None, last=3_990_000_000, result="success", status="0"):
    if unit.endswith(".timer"):
        return {"ActiveState": active or "active", "LoadState": "loaded", "Result": "success"}
    return {"ActiveState": active or "inactive", "LoadState": "loaded", "Result": result,
            "ExecMainStatus": status, "ExecMainExitTimestampMonotonic": str(last)}


def local(_):
    return {"local_status": "READY_LOCAL", "refresh_token_present": True,
            "client_secret": "DO_NOT_EXPOSE"}


class ResilienceReportTests(unittest.TestCase):
    def test_unit_count(self):
        self.assertEqual(len(mod.UNITS), 8)

    def test_health_success(self):
        r = mod.collect("/fake/token", now_us=NOW, reader=props, oauth_reader=local)
        self.assertEqual(r["detection_status"], "HEALTHY")
        self.assertEqual(r["alert_queue_status"], "HEALTHY")
        self.assertEqual(r["notification_delivery"], "NOT_AUTOMATED")

    def test_no_remote_default(self):
        def no_remote(*args):
            raise AssertionError("Remote probe must not execute")
        r = mod.collect("/fake/token", now_us=NOW, reader=props,
                        oauth_reader=local, remote_reader=no_remote)
        self.assertEqual(r["oauth_remote"], "NOT_CHECKED")

    def test_remote_accepted(self):
        r = mod.collect("/fake/token", online=True, now_us=NOW, reader=props,
                        oauth_reader=local, remote_reader=lambda _: {"remote_authorization": "ACCEPTED"})
        self.assertEqual(r["oauth_remote"], "ACCEPTED")
        self.assertEqual(r["notification_delivery"], "NOT_AUTOMATED")

    def test_remote_failed_not_detection_failed(self):
        r = mod.collect("/fake/token", online=True, now_us=NOW, reader=props,
                        oauth_reader=local, remote_reader=lambda _: {"remote_authorization": "FAILED"})
        self.assertEqual(r["detection_status"], "HEALTHY")
        self.assertEqual(r["oauth_remote"], "FAILED")

    def test_remote_exception_is_safe(self):
        def fail(_):
            raise RuntimeError("SECRET SHOULD NOT APPEAR")
        r = mod.collect("/fake/token", online=True, now_us=NOW, reader=props,
                        oauth_reader=local, remote_reader=fail)
        self.assertEqual(r["oauth_remote"], "FAILED")
        self.assertNotIn("SECRET", str(r))

    def test_timer_inactive_critical(self):
        self.assertEqual(mod.check_unit({"ActiveState":"inactive"},"timer",NOW,None)["status"],"CRITICAL")

    def test_timer_active_healthy(self):
        self.assertEqual(mod.check_unit({"ActiveState":"active"},"timer",NOW,None)["status"],"HEALTHY")

    def test_service_failed_critical(self):
        self.assertEqual(mod.check_unit(props("a.service",active="failed"),"oneshot",NOW,60)["status"],"CRITICAL")

    def test_service_exit_nonzero(self):
        self.assertEqual(mod.check_unit(props("a.service",status="2"),"oneshot",NOW,60)["status"],"CRITICAL")

    def test_service_stale_warn(self):
        self.assertEqual(mod.check_unit(props("a.service",last=1_000_000),"oneshot",NOW,60)["status"],"WARNING")

    def test_service_future_warn(self):
        self.assertEqual(mod.check_unit(props("a.service",last=NOW+2_000_000),"oneshot",NOW,60)["status"],"WARNING")

    def test_service_never_run_unknown(self):
        self.assertEqual(mod.check_unit(props("a.service",last=0),"oneshot",NOW,60)["status"],"UNKNOWN")

    def test_service_recent_healthy(self):
        self.assertEqual(mod.check_unit(props("a.service"),"oneshot",NOW,60)["status"],"HEALTHY")

    def test_service_incomplete_unknown(self):
        self.assertEqual(mod.check_unit(props("a.service",result=""),"oneshot",NOW,60)["status"],"UNKNOWN")

    def test_service_bad_timestamp_unknown(self):
        p=props("a.service");p["ExecMainExitTimestampMonotonic"]="oops"
        self.assertEqual(mod.check_unit(p,"oneshot",NOW,60)["status"],"UNKNOWN")

    def test_reader_error_is_unknown(self):
        def fail(_):raise RuntimeError("INTERNAL_PRIVATE_PATH")
        r=mod.collect("/fake/token",now_us=NOW,reader=fail,oauth_reader=local)
        self.assertEqual(r["detection_status"],"UNKNOWN")
        self.assertNotIn("PRIVATE_PATH",str(r))

    def test_queue_failed_separate_from_detection(self):
        def reader(unit):
            return props(unit, active="inactive") if unit=="powerbeam-alert-queue.timer" else props(unit)
        r=mod.collect("/fake/token",now_us=NOW,reader=reader,oauth_reader=local)
        self.assertEqual(r["detection_status"],"HEALTHY")
        self.assertEqual(r["alert_queue_status"],"CRITICAL")

    def test_warning_separate_from_oauth(self):
        def reader(unit):
            return props(unit,last=1_000_000) if unit=="powerbeam-health.service" else props(unit)
        r=mod.collect("/fake/token",now_us=NOW,reader=reader,oauth_reader=local)
        self.assertEqual(r["detection_status"],"WARNING")
        self.assertEqual(r["oauth_local"],"READY_LOCAL")

    def test_no_secrets_in_report(self):
        r=mod.collect("/fake/token",now_us=NOW,reader=props,oauth_reader=local)
        self.assertNotIn("DO_NOT_EXPOSE",str(r))
        self.assertNotIn("/fake/token",str(r))

    def test_unit_reader_does_not_use_shell(self):
        from types import SimpleNamespace
        with patch("resilience_report.subprocess.run",return_value=SimpleNamespace(returncode=0,stdout="LoadState=loaded\nActiveState=active\n",stderr="")) as run:
            self.assertEqual(mod.read_unit("powerbeam-health.timer")["ActiveState"],"active")
            self.assertNotIn("shell",run.call_args.kwargs)
            self.assertIsInstance(run.call_args.args[0],list)

    def test_nonzero_read_is_redacted(self):
        from types import SimpleNamespace
        with patch("resilience_report.subprocess.run",return_value=SimpleNamespace(returncode=1,stdout="",stderr="TOKEN")):
            with self.assertRaisesRegex(RuntimeError,"SYSTEMCTL_QUERY_FAILED") as cm:
                mod.read_unit("powerbeam-health.timer")
            self.assertNotIn("TOKEN",str(cm.exception))

    def test_main_exit_for_critial(self):
        with patch("resilience_report.collect",return_value={"detection_status":"CRITICAL","alert_queue_status":"HEALTHY"}) as c,patch("builtins.print"):
            self.assertEqual(mod.main([]),2)

    def test_main_exit_for_healthy(self):
        with patch("resilience_report.collect",return_value={"detection_status":"HEALTHY","alert_queue_status":"HEALTHY"}) as c,patch("builtins.print"):
            self.assertEqual(mod.main([]),0)


if __name__ == "__main__":
    unittest.main()
