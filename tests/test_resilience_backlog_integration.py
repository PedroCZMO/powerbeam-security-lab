"""Phase 5: integration of restricted alert metrics with resilience report.

No systemd changes, network, secrets, actual alert logs or production state.
"""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import alert_backlog_health
import resilience_report as mod

NOW_US = 4_000_000_000


def reader(unit):
    if unit.endswith('.timer'):
        return {'ActiveState': 'active', 'LoadState': 'loaded', 'Result': 'success'}
    return {'ActiveState': 'inactive', 'LoadState': 'loaded', 'Result': 'success',
            'ExecMainStatus': '0', 'ExecMainExitTimestampMonotonic': '3990000000'}


def oauth(_):
    return {'local_status': 'READY_LOCAL', 'private': 'SECRET_NEVER_LOG'}


def sample(*, status='HEALTHY', severity='medium', minutes=5, pending=1):
    from datetime import datetime, timedelta, timezone
    from copy import deepcopy
    now = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
    if not pending:
        state = {'schema_version': 1, 'seen_alert_ids': ['OLD'], 'pending': []}
    else:
        state = {'schema_version': 1, 'seen_alert_ids': ['SOC-EXAMPLE-1'],
                 'pending': [{'alert_id': 'SOC-EXAMPLE-1', 'rule_id': 'SOC-001',
                              'severity': severity, 'source_ip': '192.0.2.11',
                              'timestamp': (now - timedelta(minutes=minutes)).isoformat()}]}
    return alert_backlog_health.evaluate(deepcopy(state), now=now)


def collect(raw=None, *, requested=True, systemd_reader=reader):
    return mod.collect('/path/to/private/token', now_us=NOW_US,
                       reader=systemd_reader, oauth_reader=oauth,
                       backlog_requested=requested, backlog_report=raw)


class BacklogResilienceIntegrationTests(unittest.TestCase):
    def test_01_backwards_compatible_not_requested(self):
        r = collect(requested=False)
        self.assertEqual(r['backlog_status'], 'NOT_CHECKED')
        self.assertEqual(r['alert_management_status'], 'NOT_CHECKED')
        self.assertIsNone(r['alert_backlog'])
        self.assertEqual(r['detection_status'], 'HEALTHY')

    def test_02_empty_backlog_healthy(self):
        r = collect(sample(pending=0))
        self.assertEqual(r['backlog_status'], 'HEALTHY')
        self.assertEqual(r['alert_backlog']['pending_total'], 0)
        self.assertEqual(r['alert_management_status'], 'HEALTHY')

    def test_03_recent_medium_healthy(self):
        r = collect(sample())
        self.assertEqual(r['backlog_status'], 'HEALTHY')
        self.assertEqual(r['alert_backlog']['pending_total'], 1)

    def test_04_old_high_warning(self):
        r = collect(sample(severity='high', minutes=35))
        self.assertEqual(r['backlog_status'], 'WARNING')
        self.assertEqual(r['alert_management_status'], 'WARNING')
        self.assertEqual(r['detection_status'], 'HEALTHY')

    def test_05_old_medium_critical(self):
        r = collect(sample(minutes=250))
        self.assertEqual(r['backlog_status'], 'CRITICAL')
        self.assertEqual(r['alert_management_status'], 'CRITICAL')
        self.assertEqual(r['alert_queue_status'], 'HEALTHY')

    def test_06_critical_severity_immediate(self):
        self.assertEqual(collect(sample(severity='critical'))['backlog_status'], 'CRITICAL')

    def test_07_queue_service_failed_separate(self):
        def failed(unit):
            data = reader(unit)
            if unit == 'powerbeam-alert-queue.timer':
                data['ActiveState'] = 'inactive'
            return data
        r = collect(sample(), systemd_reader=failed)
        self.assertEqual(r['alert_queue_status'], 'CRITICAL')
        self.assertEqual(r['backlog_status'], 'HEALTHY')
        self.assertEqual(r['alert_management_status'], 'CRITICAL')

    def test_08_missing_backlog_is_unknown(self):
        r = collect(None)
        self.assertEqual(r['backlog_status'], 'UNKNOWN')
        self.assertEqual(r['alert_management_status'], 'UNKNOWN')
        self.assertIsNone(r['alert_backlog'])

    def test_09_bad_json_is_unknown(self):
        raw = mod.read_backlog_stdin(io.StringIO('NOT JSON SECRET'))
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_10_bounded_stdin(self):
        raw = mod.read_backlog_stdin(io.StringIO('A' * (mod.MAX_BACKLOG_REPORT_BYTES + 10)))
        self.assertIsNone(raw)

    def test_11_valid_stdin(self):
        raw = mod.read_backlog_stdin(io.StringIO(json.dumps(sample())))
        self.assertEqual(collect(raw)['backlog_status'], 'HEALTHY')

    def test_12_raw_ip_and_ids_never_published(self):
        original = sample()
        original['pending_alerts'] = [{'ip': '192.0.2.11', 'alert_id': 'SENSITIVE-ID'}]
        original['token'] = 'EXAMPLE-VERY-PRIVATE'
        r = collect(original)
        self.assertNotIn('192.0.2.11', json.dumps(r))
        self.assertNotIn('SENSITIVE-ID', json.dumps(r))
        self.assertNotIn('EXAMPLE-VERY-PRIVATE', json.dumps(r))
        self.assertNotIn('SECRET_NEVER_LOG', json.dumps(r))

    def test_13_input_unchanged(self):
        raw = sample()
        before = json.dumps(raw, sort_keys=True)
        collect(raw)
        self.assertEqual(before, json.dumps(raw, sort_keys=True))

    def test_14_invalid_component_unknown(self):
        raw = sample(); raw['component'] = 'unexpected'
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_15_wrong_age_basis_unknown(self):
        raw = sample(); raw['age_basis'] = 'QUEUE_ENTRY_TIME'
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_16_wrong_read_only_flag_unknown(self):
        raw = sample(); raw['state_modified'] = True
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_17_email_sent_flag_unknown(self):
        raw = sample(); raw['emails_sent'] = 1
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_18_bad_severity_sum_unknown(self):
        raw = sample(); raw['pending_by_severity']['high'] = 4
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_19_negative_count_unknown(self):
        raw = sample(); raw['seen_total'] = -1
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_20_boolean_count_unknown(self):
        raw = sample(); raw['pending_total'] = True
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_21_bad_age_unknown(self):
        raw = sample(); raw['oldest_event_age_minutes'] = 'NEVER'
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_22_empty_backlog_inconsistent_unknown(self):
        raw = sample(pending=0); raw['oldest_event_age_minutes'] = 10
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_23_invalid_status_unknown(self):
        raw = sample(); raw['operational_status'] = 'MAGIC'
        self.assertEqual(collect(raw)['backlog_status'], 'UNKNOWN')

    def test_24_no_token_or_raw_data_written(self):
        r = collect(sample())
        self.assertEqual(r['emails_sent'], 0)
        self.assertEqual(r['tokens_modified'], False)
        self.assertNotIn('/path/to/private/token', json.dumps(r))
        self.assertEqual(r['notification_delivery'], 'NOT_AUTOMATED')

    def test_25_cli_warning_exit_code(self):
        backlog = sample(severity='high', minutes=35)
        with patch('sys.stdin', io.StringIO(json.dumps(backlog))), \
             patch('resilience_report.collect', return_value=collect(backlog)), \
             patch('builtins.print'):
            self.assertEqual(mod.main(['--backlog-stdin']), 1)

    def test_26_cli_critical_exit_code(self):
        backlog = sample(minutes=250)
        with patch('sys.stdin', io.StringIO(json.dumps(backlog))), \
             patch('resilience_report.collect', return_value=collect(backlog)), \
             patch('builtins.print'):
            self.assertEqual(mod.main(['--backlog-stdin']), 2)

    def test_27_cli_unknown_exit_code(self):
        with patch('sys.stdin', io.StringIO('bad_json')), \
             patch('resilience_report.collect', return_value=collect(None)), \
             patch('builtins.print'):
            self.assertEqual(mod.main(['--backlog-stdin']), 1)

    def test_28_cli_default_backwards_compatible(self):
        with patch('resilience_report.collect', return_value=collect(requested=False)), \
             patch('builtins.print'):
            self.assertEqual(mod.main([]), 0)

    def test_29_ack_count_aggregated_only(self):
        raw = sample(pending=0)
        raw['seen_total'] = 5
        raw['acknowledged_total'] = 3
        r = collect(raw)
        self.assertEqual(r['alert_backlog']['acknowledged_total'], 3)

    def test_30_no_backlog_stdin_read_without_flag(self):
        with patch('resilience_report.read_backlog_stdin', side_effect=AssertionError('SHOULD NOT READ')), \
             patch('resilience_report.collect', return_value=collect(requested=False)), \
             patch('builtins.print'):
            self.assertEqual(mod.main([]), 0)


if __name__ == '__main__':
    unittest.main()
