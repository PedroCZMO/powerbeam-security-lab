#!/usr/bin/env python3
"""Offline SMTP-acceptance demo; creates and deletes its own temporary queue."""
import json
from pathlib import Path
import tempfile

import alert_queue as queue
import smtp_notifier as notifier


def item(aid):
    return {'alert_id': aid, 'rule_id': 'SOC-002', 'severity': 'medium',
            'source_ip': '192.0.2.10', 'timestamp': '2026-11-05T10:00:00+01:00'}


def main():
    with tempfile.TemporaryDirectory(prefix='powerbeam-smtp-mock-') as base:
        root = Path(base)
        source = root / 'alerts.jsonl'
        state = root / 'queue' / 'state.json'
        source.write_text(json.dumps(item('SOC-HIST-1')) + '\n', encoding='utf-8')
        queue.run('bootstrap', source, state)
        with source.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(item('SOC-NEW-1')) + '\n')
        queue.run('scan', source, state)

        def simulated_failure(_msg):
            raise ConnectionError('sin conexión (simulación)')

        failed = notifier.dispatch(state, simulated_failure, source=source,
                                   sender='soc@example.org', recipient='analyst@example.org')
        assert failed['pending_total'] == 1 and failed['acknowledged'] == 0

        accepted = []
        def mocked_accept(msg):
            accepted.append({'to': msg['To'], 'subject': msg['Subject']})

        result = notifier.dispatch(state, mocked_accept, source=source,
                                   sender='soc@example.org', recipient='analyst@example.org')
        second = notifier.dispatch(state, mocked_accept, source=source,
                                   sender='soc@example.org', recipient='analyst@example.org')
        assert result['acknowledged'] == 1
        assert second['accepted_by_smtp'] == 0 and len(accepted) == 1
        print(json.dumps({
            'mode': 'MOCK - no se abren conexiones ni se envía correo',
            'first_attempt_error': failed['error']['stage'],
            'pending_after_first_failure': failed['pending_total'],
            'mock_accepted': len(accepted),
            'acknowledged_in_temporary_state': result['acknowledged'],
            'repeated_dispatch_accepted': second['accepted_by_smtp'],
            'final_pending': queue.run('status', source, state)['pending'],
        }, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
