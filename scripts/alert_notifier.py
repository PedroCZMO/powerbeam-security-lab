#!/usr/bin/env python3
"""PowerBeam Day 11: notification preview, offline and WITHOUT delivery/acks.

The current alert queue remains the source of truth.  This module ONLY
formats pending alerts for inspection; it does not send mail, contact the
network, or change queue state. SMTP delivery must be a separate phase.
"""
import argparse
import json
from pathlib import Path
import sys

import alert_queue

MAX_PREVIEW = 50
SOURCE_DEFAULT = Path('/var/lib/powerbeam-monitor/alerts.jsonl')


def make_message(alert):
    """Build a minimal text notification from validated queue fields."""
    a = alert_queue.normalize_alert(alert, 'notificación')
    subject = f'[PowerBeam SOC] {a["severity"].upper()} {a["rule_id"]} | {a["alert_id"]}'
    body = (
        'Aviso de PowerBeam Security Lab (entorno de laboratorio).\n'
        'Una alerta necesita revisión; no demuestra por sí sola un compromiso.\n\n'
        f'ID de alerta: {a["alert_id"]}\n'
        f'Regla: {a["rule_id"]}\n'
        f'Severidad de la regla: {a["severity"]}\n'
        f'IP de origen: {a["source_ip"]}\n'
        f'Fecha del evento: {a["timestamp"]}\n\n'
        'Consulta las evidencias locales antes de clasificar el incidente.\n'
    )
    return {'alert_id': a['alert_id'], 'rule_id': a['rule_id'],
            'severity': a['severity'], 'subject': subject, 'body': body}


def preview(state_path, *, source=SOURCE_DEFAULT, max_alerts=10):
    if type(max_alerts) is not int or not (1 <= max_alerts <= MAX_PREVIEW):
        raise ValueError(f'--max-alerts debe estar entre 1 y {MAX_PREVIEW}')
    # The queue's status operation validates state and takes its flock; it
    # does not read the alerts source, acknowledge anything, or save state.
    status = alert_queue.run('status', source, state_path)
    pending = status['pending_alerts']
    selected = pending[:max_alerts]
    return {'action': 'preview', 'dry_run': True, 'sent': 0,
            'acknowledged': 0, 'pending_total': len(pending),
            'previewed': len(selected), 'remaining': len(pending) - len(selected),
            'messages': [make_message(a) for a in selected],
            'note': 'No se ha enviado correo ni reconocido ninguna alerta.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Previsualizar avisos SOC sin enviar correos ni registrar acuses')
    parser.add_argument('command', choices=['preview'])
    parser.add_argument('--source', type=Path, default=SOURCE_DEFAULT,
                        help='Ruta de alertas V1; preview no lee este archivo')
    parser.add_argument('--state', type=Path, required=True,
                        help='Estado ya inicializado de la cola')
    parser.add_argument('--max-alerts', type=int, default=10)
    args = parser.parse_args(argv)
    try:
        result = preview(args.state, source=args.source, max_alerts=args.max_alerts)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
